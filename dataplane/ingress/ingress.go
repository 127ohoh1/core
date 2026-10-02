// Package ingress is the public HTTP(S) handler of the edge. It validates the
// host, resolves the tunnel, asks the Enforcer for a Gate, and streams the
// request and response through one multiplexed tunnel stream.
//
// Metering rule (one layer, deterministic): the metered quantity is HTTP
// message *body* bytes that cross the tunnel, counted once per direction at
// the moment they are handed to the tunnel (request) or received from it
// (response). Headers, tunnel framing, WINDOW_UPDATEs and platform-generated
// error bodies are not metered; client retries are separate requests.
package ingress

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/127ohoh1/core/dataplane/proxy"
	"github.com/127ohoh1/core/dataplane/routing"
	dtunnel "github.com/127ohoh1/core/dataplane/tunnel"
	"github.com/127ohoh1/core/internal/clock"
	"github.com/127ohoh1/core/internal/ids"
	"github.com/127ohoh1/core/internal/observability"
	proto "github.com/127ohoh1/core/protocol/tunnel"
)

// Config configures the handler.
type Config struct {
	BaseDomain     string
	EdgeID         string
	AllowPlainHTTP bool // development: accept requests without TLS/SNI
	// MaxDuration bounds only opening the tunnel stream (Session.Open); it has
	// no activity signal to watch, so a flat deadline is the right tool there.
	// It does not gate the request/response body or an upgraded connection
	// once bytes start flowing — IdleTimeout does, for as long as the
	// exchange keeps making progress (SSE, long-poll, large downloads and
	// WebSocket all rely on this).
	MaxDuration time.Duration
	// IdleTimeout ends an exchange after no progress in either direction
	// (request body, response body, or an upgraded connection's bytes) for
	// this long. It is the sole duration-based limit once the stream is open.
	IdleTimeout time.Duration
	// ResponseHeaderTimeout bounds the wait for the origin's first response
	// byte (zero activity since the stream opened). Independent of
	// MaxDuration: raising it alone is enough to support a slower long-poll.
	ResponseHeaderTimeout time.Duration
	Meta                  proto.MetaLimits
	ChunkSize             int
}

func (c *Config) defaults() {
	if c.MaxDuration <= 0 {
		c.MaxDuration = 10 * time.Minute
	}
	if c.IdleTimeout <= 0 {
		c.IdleTimeout = 60 * time.Second
	}
	if c.ResponseHeaderTimeout <= 0 {
		c.ResponseHeaderTimeout = 60 * time.Second
	}
	if c.ChunkSize <= 0 {
		c.ChunkSize = 16 << 10
	}
}

// Metrics of the ingress.
type Metrics struct {
	Requests  *observability.Counter   // edge_ingress_requests_total{status_class,platform_error}
	Duration  *observability.Histogram // edge_ingress_request_duration_seconds
	Bytes     *observability.Counter   // edge_proxied_bytes_total{direction}
	Streams   *observability.Gauge     // edge_streams_active
	Platform  *observability.Counter   // edge_platform_errors_total{code}
	TunnelRTT *observability.Histogram // edge_stream_open_seconds
}

// NewMetrics registers ingress metrics.
func NewMetrics(r *observability.Registry) Metrics {
	return Metrics{
		Requests:  r.Counter("edge_ingress_requests_total", "Public requests by status class and platform error.", "status_class", "platform_error"),
		Duration:  r.Histogram("edge_ingress_request_duration_seconds", "Public request latency.", nil),
		Bytes:     r.Counter("edge_proxied_bytes_total", "Proxied body bytes by direction.", "direction"),
		Streams:   r.Gauge("edge_streams_active", "In-flight proxied streams."),
		Platform:  r.Counter("edge_platform_errors_total", "Platform-generated error responses by code.", "code"),
		TunnelRTT: r.Histogram("edge_time_to_response_headers_seconds", "Time from request start to origin response headers.", nil),
	}
}

type peerKey struct{}

type forwardedPeer struct{ ip, scheme string }

// WithForwardedPeer records the original client address and scheme for a
// request that reached this edge over the authenticated inter-edge hop.
func WithForwardedPeer(ctx context.Context, ip, scheme string) context.Context {
	return context.WithValue(ctx, peerKey{}, forwardedPeer{ip: ip, scheme: scheme})
}

// Handler is the public ingress.
type Handler struct {
	cfg      Config
	reg      *dtunnel.Registry
	enforcer Enforcer
	log      *slog.Logger
	m        Metrics
	clk      clock.Clock
	ids      *ids.Generator
	bufs     sync.Pool
	// Resolver, if set, is consulted when no local tunnel exists (multi-edge).
	Remote RemoteForwarder
}

// RemoteForwarder forwards a request to the edge that owns the tunnel.
type RemoteForwarder interface {
	// Forward returns true if it handled the request.
	Forward(w http.ResponseWriter, r *http.Request, label string) bool
}

// New builds a Handler.
func New(cfg Config, reg *dtunnel.Registry, enf Enforcer, clk clock.Clock, log *slog.Logger, m Metrics) *Handler {
	cfg.defaults()
	h := &Handler{cfg: cfg, reg: reg, enforcer: enf, log: log, m: m, clk: clk, ids: ids.New(clk)}
	h.bufs.New = func() any { b := make([]byte, cfg.ChunkSize); return &b }
	return h
}

type respWriter struct {
	http.ResponseWriter
	status int
	perr   string
	html   bool // the caller is a browser: platform errors render as a page
}

func (w *respWriter) WriteHeader(c int) {
	if w.status == 0 {
		w.status = c
	}
	w.ResponseWriter.WriteHeader(c)
}

func (w *respWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}
	return w.ResponseWriter.Write(b)
}

func (w *respWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// platformError writes a platform-generated response. It is always
// distinguishable from an origin response by X-127ohoh1-Error.
func (h *Handler) platformError(w *respWriter, reqID string, status int, code, msg string, retry time.Duration) {
	w.perr = code
	h.m.Platform.Inc(code)
	hd := w.Header()
	hd.Set(proxy.ErrorHeader, code)
	hd.Set("Cache-Control", "no-store")
	if retry > 0 {
		hd.Set("Retry-After", strconv.Itoa(int(retry.Round(time.Second).Seconds())+boolToInt(retry < time.Second)))
	}
	if w.html {
		writeErrorPage(w, status, code, msg, reqID)
		return
	}
	hd.Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": code, "message": msg, "request_id": reqID}})
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	start := h.clk.Now()
	reqID := h.ids.New("req")
	w := &respWriter{ResponseWriter: rw, html: wantsHTML(r)}
	w.Header().Set("X-Request-Id", reqID)
	var endpointID string
	// Trace context: the caller's trace id is kept for correlation but its span
	// id is never trusted; this hop starts a fresh, internal span.
	tc := observability.FromExternal(r.Header.Get("Traceparent"))
	var bytesIn, bytesOut atomic.Int64 // bytesIn is written by the request pump goroutine
	defer func() {
		status := w.status
		if status == 0 {
			status = 499 // aborted before any response (client gone / reset)
		}
		dur := h.clk.Now().Sub(start)
		h.m.Requests.Inc(fmt.Sprintf("%dxx", status/100), w.perr)
		h.m.Duration.Observe(dur.Seconds())
		// Only the method and status are logged: paths and queries often carry secrets.
		h.log.Info("ingress.request", observability.FieldEvent, "ingress.request", observability.FieldRequestID, reqID,
			observability.FieldTraceID, tc.TraceID, observability.FieldEndpoint, endpointID, observability.FieldEdge, h.cfg.EdgeID, "method", r.Method, "status", status,
			observability.FieldErrorCode, w.perr, observability.FieldDurationMS, dur.Milliseconds(),
			observability.FieldBytesIn, bytesIn.Load(), observability.FieldBytesOut, bytesOut.Load())
	}()

	if r.Method == http.MethodConnect {
		h.platformError(w, reqID, http.StatusMethodNotAllowed, "method_not_allowed", "CONNECT is not supported.", 0)
		return
	}
	isUpgrade := proxy.IsUpgrade(r.Header)
	label, err := routing.ParseTenantHost(r.Host, h.cfg.BaseDomain)
	if err != nil {
		code, status := "unknown_host", http.StatusNotFound
		if errors.Is(err, routing.ErrBadHost) {
			code, status = "bad_host", http.StatusBadRequest
		}
		h.platformError(w, reqID, status, code, "This host does not route to a tunnel.", 0)
		return
	}
	var sni string
	if r.TLS != nil {
		sni = r.TLS.ServerName
	}
	if err := routing.CheckSNI(sni, label, h.cfg.BaseDomain, h.cfg.AllowPlainHTTP && r.TLS == nil); err != nil {
		h.platformError(w, reqID, http.StatusMisdirectedRequest, "misdirected_request", "The TLS server name does not match the Host header.", 0)
		return
	}

	live, ok := h.reg.ByHostname(label)
	if !ok {
		if h.Remote != nil && h.Remote.Forward(w, r, label) {
			return
		}
		h.platformError(w, reqID, http.StatusNotFound, "endpoint_not_found", "No tunnel is connected for this hostname.", 0)
		return
	}
	endpointID = live.EndpointID

	gate, refusal := h.enforcer.Acquire(r.Context(), live.EndpointID)
	if refusal != nil {
		h.platformError(w, reqID, refusal.Status, refusal.Code, refusal.Message, refusal.RetryAfter)
		return
	}
	defer gate.Release()
	lim := gate.Limits()

	if lim.MaxRequestHeaderBytes > 0 && proxy.HeaderBytes(r.Header) > lim.MaxRequestHeaderBytes {
		h.platformError(w, reqID, http.StatusRequestHeaderFieldsTooLarge, "request_headers_too_large", "Request headers exceed the allowed size.", 0)
		return
	}
	if lim.MaxRequestBodyBytes > 0 && r.ContentLength > lim.MaxRequestBodyBytes {
		h.platformError(w, reqID, http.StatusRequestEntityTooLarge, "request_body_too_large", "Request body exceeds the allowed size.", 0)
		return
	}

	target := r.URL.RequestURI()
	if !strings.HasPrefix(target, "/") {
		h.platformError(w, reqID, http.StatusBadRequest, "bad_request_target", "Only origin-form request targets are supported.", 0)
		return
	}
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	peerIP := proxy.PeerIP(r.RemoteAddr)
	if fp, ok := r.Context().Value(peerKey{}).(forwardedPeer); ok { // request came over the authenticated inter-edge hop
		peerIP, scheme = fp.ip, fp.scheme
	}
	hdrs := proxy.RequestHeaders(r.Header)
	if isUpgrade {
		hdrs = proxy.UpgradeRequestHeaders(r.Header)
	}
	meta := proto.RequestMeta{
		Method: r.Method, Target: target, Host: r.Host, Header: hdrs,
		RemoteAddr: peerIP, Proto: scheme, ContentLength: r.ContentLength, Traceparent: tc.String(),
	}
	if r.ContentLength == 0 || r.Body == http.NoBody {
		meta.ContentLength = 0
	}
	mb, err := proto.EncodeRequestMeta(meta, h.cfg.Meta)
	if err != nil {
		h.platformError(w, reqID, http.StatusRequestHeaderFieldsTooLarge, "request_headers_too_large", "Request headers cannot be forwarded.", 0)
		return
	}

	// MaxDuration bounds only this call: opening the stream has no activity
	// signal to watch, so a flat deadline is the right tool here. Everything
	// after the stream opens is governed by IdleTimeout (watchdog, below)
	// instead, so a request/response/upgrade that is still making progress is
	// never cut off by wall-clock alone.
	openCtx, cancel := context.WithTimeout(r.Context(), h.cfg.MaxDuration)
	defer cancel()

	openStart := h.clk.Now()
	st, err := live.Session.Open(openCtx, mb)
	if err != nil {
		switch {
		case errors.Is(err, proto.ErrTooManyStreams):
			h.platformError(w, reqID, http.StatusServiceUnavailable, "tunnel_busy", "The tunnel has too many concurrent requests.", time.Second)
		case openCtx.Err() != nil:
		default:
			h.platformError(w, reqID, http.StatusBadGateway, "tunnel_offline", "The tunnel is not accepting requests.", 0)
		}
		return
	}
	h.m.Streams.Add(1)
	defer h.m.Streams.Add(-1)
	// Whatever happens, end the stream when the handler returns; Close is a
	// no-op on a stream that already ended cleanly.
	defer st.Close()

	// One shared "no progress in either direction" watchdog for the whole
	// exchange: every direction (request body, response body, or an upgraded
	// connection's bytes in either direction) touches it on each chunk, and
	// only true, simultaneous silence across all of them ends the stream.
	watchdog := newIdleWatchdog(h.cfg.IdleTimeout, func() { st.Reset(proto.CodeTimeout) })
	defer watchdog.stop()

	rc := http.NewResponseController(w)
	_ = rc.EnableFullDuplex() // allow reading the request body while writing the response (HTTP/1)

	// Request body -> tunnel, concurrently with awaiting the response. A real
	// protocol-upgrade handshake never carries a body (RFC 6455 et al.); once
	// accepted, the stream's write side belongs entirely to the duplex pump
	// in serveUpgrade, so pumpRequest must not run (or half-close it) here.
	pumpErr := make(chan error, 1)
	if !isUpgrade {
		go func() {
			n, err := h.pumpRequest(r.Context(), r, st, gate, lim, meta.ContentLength != 0, watchdog)
			bytesIn.Store(n)
			pumpErr <- err
		}()
	}

	wctx, wcancel := context.WithTimeout(r.Context(), h.cfg.ResponseHeaderTimeout)
	rm, err := st.WaitResponse(wctx)
	timedOut := errors.Is(wctx.Err(), context.DeadlineExceeded) // evaluate before cancelling wctx
	wcancel()
	if err != nil {
		st.Reset(proto.CodeCancel)
		select { // a request-side refusal (quota, size) explains the failure better than the stream error
		case perr := <-pumpErr:
			if h.reportPumpErr(w, reqID, perr) {
				return
			}
		case <-time.After(50 * time.Millisecond):
		}
		if r.Context().Err() != nil {
			return // caller went away
		}
		h.originFailure(w, reqID, err, timedOut)
		return
	}
	h.m.TunnelRTT.Observe(h.clk.Now().Sub(openStart).Seconds())
	resp, err := proto.DecodeResponseMeta(rm, h.cfg.Meta)
	if err != nil {
		st.Reset(proto.CodeProtocolError)
		h.platformError(w, reqID, http.StatusBadGateway, "bad_origin_response", "The origin returned an invalid response.", 0)
		return
	}

	if isUpgrade && resp.Status == http.StatusSwitchingProtocols {
		w.status = http.StatusSwitchingProtocols // bypasses respWriter.WriteHeader below
		hijacked, n1, n2 := h.serveUpgrade(w, rc, st, resp, gate, watchdog)
		bytesIn.Store(n1)
		bytesOut.Store(n2)
		if !hijacked {
			st.Reset(proto.CodeInternalError)
			h.platformError(w, reqID, http.StatusBadGateway, "bad_origin_response", "The origin accepted a protocol upgrade this connection cannot relay.", 0)
		}
		return
	}

	hd := w.Header()
	for k, vs := range proxy.ResponseHeaders(resp.Header) {
		for _, v := range vs {
			hd.Add(k, v)
		}
	}
	if resp.ContentLength >= 0 && hd.Get("Content-Length") == "" {
		hd.Set("Content-Length", strconv.FormatInt(resp.ContentLength, 10))
	}
	w.WriteHeader(resp.Status)
	n, err := h.pumpResponse(r.Context(), w, rc, st, gate, watchdog)
	bytesOut.Store(n)
	if err != nil {
		// Truncated or over-quota response: abort the connection so the caller
		// cannot mistake a short body for a complete one.
		st.Reset(proto.CodeCancel)
		panic(http.ErrAbortHandler)
	}
	select { // surface a request-side failure that did not stop the response
	case <-pumpErr:
	default:
	}
}

func (h *Handler) originFailure(w *respWriter, reqID string, err error, timedOut bool) {
	h.log.Debug("ingress.origin_failure", observability.FieldEvent, "ingress.origin_failure", observability.FieldRequestID, reqID, "cause", err.Error())
	var se *proto.StreamError
	switch {
	case errors.As(err, &se) && se.Code == proto.CodeTimeout, timedOut:
		h.platformError(w, reqID, http.StatusGatewayTimeout, "origin_timeout", "The origin did not respond in time.", 0)
	case errors.As(err, &se) && se.Code == proto.CodeRefusedStream:
		h.platformError(w, reqID, http.StatusServiceUnavailable, "tunnel_busy", "The tunnel refused the request.", time.Second)
	case errors.As(err, &se) && se.Remote && se.Code == proto.CodeInternalError:
		h.platformError(w, reqID, http.StatusBadGateway, "origin_unreachable", "The origin could not be reached.", 0)
	case errors.Is(err, proto.ErrSessionClosed):
		h.platformError(w, reqID, http.StatusBadGateway, "tunnel_lost", "The tunnel connection was lost.", 0)
	default:
		h.platformError(w, reqID, http.StatusBadGateway, "origin_error", "The origin request failed.", 0)
	}
}

// reportPumpErr writes a platform response for request-side refusals and
// reports whether it did.
func (h *Handler) reportPumpErr(w *respWriter, reqID string, err error) bool {
	var ref *Refusal
	var mbe *http.MaxBytesError
	switch {
	case errors.As(err, &ref):
		h.platformError(w, reqID, ref.Status, ref.Code, ref.Message, ref.RetryAfter)
		return true
	case errors.As(err, &mbe):
		h.platformError(w, reqID, http.StatusRequestEntityTooLarge, "request_body_too_large", "Request body exceeds the allowed size.", 0)
		return true
	}
	return false
}

// pumpRequest copies the public request body into the tunnel stream. ctx
// cancels only on real client disconnect (r.Context()) — not on MaxDuration —
// so a slow-but-active upload runs for as long as watchdog keeps seeing
// progress.
func (h *Handler) pumpRequest(ctx context.Context, r *http.Request, st *proto.Stream, gate Gate, lim Limits, hasBody bool, watchdog *idleWatchdog) (int64, error) {
	var total int64
	if hasBody {
		body := r.Body
		if lim.MaxRequestBodyBytes > 0 {
			body = http.MaxBytesReader(nil, r.Body, lim.MaxRequestBodyBytes)
		}
		bp := h.bufs.Get().(*[]byte)
		defer h.bufs.Put(bp)
		buf := *bp
		for {
			n, rerr := body.Read(buf)
			if n > 0 {
				watchdog.touch(h.cfg.IdleTimeout)
				if err := gate.Wait(ctx, n); err != nil {
					return total, err
				}
				if err := gate.Account(n, ToTunnel); err != nil {
					st.Reset(proto.CodeQuotaExhausted)
					return total, err
				}
				if _, err := st.WriteContext(ctx, buf[:n]); err != nil {
					return total, err
				}
				total += int64(n)
				h.m.Bytes.Add(float64(n), "in")
			}
			if rerr == io.EOF {
				break
			}
			if rerr != nil {
				st.Reset(proto.CodeCancel)
				return total, rerr
			}
		}
	}
	return total, st.CloseWrite()
}

// pumpResponse copies the tunnel response body to the public caller. ctx
// cancels only on real client disconnect (r.Context()) — not on MaxDuration —
// so an actively-streaming response (SSE, long-poll, a large download) runs
// for as long as watchdog keeps seeing progress.
func (h *Handler) pumpResponse(ctx context.Context, w http.ResponseWriter, rc *http.ResponseController, st *proto.Stream, gate Gate, watchdog *idleWatchdog) (int64, error) {
	bp := h.bufs.Get().(*[]byte)
	defer h.bufs.Put(bp)
	buf := *bp
	var total int64
	for {
		n, rerr := st.Read(buf)
		if n > 0 {
			watchdog.touch(h.cfg.IdleTimeout)
			if err := gate.Wait(ctx, n); err != nil {
				return total, err
			}
			if err := gate.Account(n, FromTunnel); err != nil {
				return total, err
			}
			if _, err := w.Write(buf[:n]); err != nil {
				return total, err
			}
			total += int64(n)
			h.m.Bytes.Add(float64(n), "out")
			_ = rc.Flush()
		}
		if rerr == io.EOF {
			return total, nil
		}
		if rerr != nil {
			return total, rerr
		}
	}
}

// TLSConfig returns a server TLS config for the public listener. certFn
// supplies certificates (allows atomic rotation).
func TLSConfig(certFn func(*tls.ClientHelloInfo) (*tls.Certificate, error)) *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: certFn, NextProtos: []string{"h2", "http/1.1"}}
}
