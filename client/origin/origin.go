// Package origin forwards tunnel streams to the local HTTP origin.
//
// Safety properties:
//   - the origin is fixed at startup (scheme http, one host:port); the request
//     path/query from the tunnel can never change where the request goes, so a
//     public caller cannot turn the client into an open proxy (SSRF);
//   - by default only loopback addresses may be dialled, checked on the
//     *resolved* IP at connect time (defeats DNS rebinding);
//   - redirects are not followed, proxies are not used, no other schemes.
package origin

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"

	proto "github.com/127ohoh1/core/protocol/tunnel"
)

// Options configures the forwarder.
type Options struct {
	// AllowNonLoopback permits non-loopback targets (explicit unsafe opt-in).
	AllowNonLoopback bool
	// RewriteHost sends the origin's own host as Host instead of the public one.
	RewriteHost bool
	// ResponseHeaderTimeout bounds time to the origin's response headers.
	ResponseHeaderTimeout time.Duration
	Meta                  proto.MetaLimits
	Log                   *slog.Logger
}

// Handler serves streams by calling the local origin.
type Handler struct {
	target *url.URL
	opts   Options
	client *http.Client
	dial   func(ctx context.Context, network, addr string) (net.Conn, error)
	log    *slog.Logger
}

// ParseTarget validates an origin URL: http only, a host, no userinfo, and
// (unless allowed) a loopback host.
func ParseTarget(raw string, allowNonLoopback bool) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid origin URL: %w", err)
	}
	if u.Scheme != "http" {
		return nil, fmt.Errorf("unsupported origin scheme %q: only http:// origins are supported", u.Scheme)
	}
	if u.Host == "" || u.Hostname() == "" {
		return nil, errors.New("origin URL has no host")
	}
	if u.User != nil {
		return nil, errors.New("origin URL must not contain credentials")
	}
	if u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("origin URL must be scheme://host[:port] without a path")
	}
	if !allowNonLoopback && !isLoopbackHost(u.Hostname()) {
		return nil, fmt.Errorf("origin host %q is not a loopback address; pass --unsafe-allow-non-loopback-origin to proxy to it", u.Hostname())
	}
	if u.Port() == "" {
		u.Host = net.JoinHostPort(u.Hostname(), "80")
	}
	u.Path = ""
	return u, nil
}

func isLoopbackHost(h string) bool {
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// New builds a Handler.
func New(target *url.URL, o Options) *Handler {
	if o.ResponseHeaderTimeout <= 0 {
		o.ResponseHeaderTimeout = 60 * time.Second
	}
	if o.Log == nil {
		o.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	d := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	if !o.AllowNonLoopback {
		// Control runs after DNS resolution, with the concrete address about
		// to be dialled, so a hostname that re-resolves to a public IP is refused.
		d.Control = func(network, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
				return fmt.Errorf("refusing to connect to non-loopback address %s", host)
			}
			return nil
		}
	}
	tr := &http.Transport{
		Proxy: nil, DialContext: d.DialContext, ForceAttemptHTTP2: false,
		MaxIdleConns: 32, MaxIdleConnsPerHost: 32, IdleConnTimeout: 60 * time.Second,
		ResponseHeaderTimeout: o.ResponseHeaderTimeout, DisableCompression: true, // pass Accept-Encoding through untouched
	}
	return &Handler{target: target, opts: o, log: o.Log, dial: d.DialContext, client: &http.Client{
		Transport:     tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

// hopByHop headers must not be forwarded between connections.
var hopByHop = map[string]bool{
	"Connection": true, "Proxy-Connection": true, "Keep-Alive": true, "Proxy-Authenticate": true,
	"Proxy-Authorization": true, "Te": true, "Trailer": true, "Transfer-Encoding": true, "Upgrade": true,
}

// upgradeHopByHop is hopByHop minus Connection/Upgrade, which a genuine
// protocol upgrade needs preserved verbatim.
var upgradeHopByHop = map[string]bool{
	"Proxy-Connection": true, "Keep-Alive": true, "Proxy-Authenticate": true,
	"Proxy-Authorization": true, "Te": true, "Trailer": true, "Transfer-Encoding": true,
}

func stripHopByHop(h http.Header) {
	for _, v := range h.Values("Connection") {
		for _, f := range strings.Split(v, ",") {
			if f = strings.TrimSpace(f); f != "" {
				h.Del(f)
			}
		}
	}
	for k := range hopByHop {
		h.Del(k)
	}
}

func stripHopByHopKeepUpgrade(h http.Header) {
	for _, v := range h.Values("Connection") {
		for _, f := range strings.Split(v, ",") {
			if f = strings.TrimSpace(f); f != "" && !strings.EqualFold(f, "upgrade") {
				h.Del(f)
			}
		}
	}
	for k := range upgradeHopByHop {
		h.Del(k)
	}
}

// isUpgrade reports whether the request asks for a protocol upgrade.
func isUpgrade(h http.Header) bool {
	if h.Get("Upgrade") != "" {
		return true
	}
	for _, v := range h.Values("Connection") {
		for _, f := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(f), "upgrade") {
				return true
			}
		}
	}
	return false
}

// Serve handles one stream. It returns when the exchange is complete or failed.
func (h *Handler) Serve(st *proto.Stream) {
	ctx := st.Context() // cancelled on reset / session loss: cancels the origin request
	meta, err := proto.DecodeRequestMeta(st.OpenMeta, h.opts.Meta)
	if err != nil {
		st.Reset(proto.CodeProtocolError)
		return
	}
	u, err := url.ParseRequestURI(meta.Target)
	if err != nil {
		st.Reset(proto.CodeProtocolError)
		return
	}
	// The destination is fixed; only path and query come from the tunnel.
	out := &url.URL{Scheme: h.target.Scheme, Host: h.target.Host, Path: u.Path, RawPath: u.RawPath, RawQuery: u.RawQuery}

	var body io.Reader
	if meta.ContentLength != 0 {
		// NopCloser is essential: *Stream has a Close method, and the HTTP
		// transport would otherwise close the tunnel stream (killing the
		// response path) as soon as the request body was written.
		body = io.NopCloser(st)
	}
	req, err := http.NewRequestWithContext(ctx, meta.Method, out.String(), body)
	if err != nil {
		st.Reset(proto.CodeProtocolError)
		return
	}
	if meta.ContentLength > 0 {
		req.ContentLength = meta.ContentLength
	} else if meta.ContentLength < 0 && body != nil {
		req.ContentLength = -1
	}
	for k, vs := range meta.Header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	upgrade := isUpgrade(req.Header)
	if upgrade {
		stripHopByHopKeepUpgrade(req.Header)
	} else {
		stripHopByHop(req.Header)
	}
	if h.opts.RewriteHost {
		req.Host = h.target.Host
	} else if meta.Host != "" {
		req.Host = meta.Host
	}
	if meta.RemoteAddr != "" {
		req.Header.Set("X-Forwarded-For", meta.RemoteAddr)
	}
	if meta.Proto != "" {
		req.Header.Set("X-Forwarded-Proto", meta.Proto)
	}
	if meta.Host != "" {
		req.Header.Set("X-Forwarded-Host", meta.Host)
	}
	if meta.Traceparent != "" {
		req.Header.Set("Traceparent", meta.Traceparent)
	}

	if upgrade {
		h.serveUpgrade(ctx, req, st)
		return
	}

	resp, err := h.client.Do(req)
	if err != nil {
		code := proto.CodeInternalError // edge renders 502 origin_unreachable
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			code = proto.CodeTimeout // edge renders 504 origin_timeout
		}
		if ctx.Err() == nil {
			h.log.Warn("origin.error", "event", "origin.error", "error_code", code.String())
		}
		st.Reset(code)
		return
	}
	defer resp.Body.Close()
	stripHopByHop(resp.Header)
	rm, err := proto.EncodeResponseMeta(proto.ResponseMeta{Status: resp.StatusCode, Header: resp.Header, ContentLength: resp.ContentLength}, h.opts.Meta)
	if err != nil {
		st.Reset(proto.CodeInternalError)
		return
	}
	if err := st.SendResponse(rm); err != nil {
		h.log.Debug("origin.send_response_failed", "event", "origin.send_response_failed", "err", err.Error())
		return
	}
	if _, err := io.Copy(st, resp.Body); err != nil {
		st.Reset(proto.CodeInternalError) // origin died mid-response: signal truncation, do not fake a clean end
		return
	}
	_ = st.CloseWrite()
	// Drain the request side so the stream can complete even if the origin
	// answered before reading the whole body.
	go io.Copy(io.Discard, st)
}

// serveUpgrade handles a protocol-upgrade request (WebSocket and friends).
// http.Client has no supported way to hand back the raw backend connection
// after a 101, so this dials and speaks HTTP/1.1 manually, mirroring
// net/http/httputil.ReverseProxy's handleUpgradeRequest/handleUpgradeResponse.
func (h *Handler) serveUpgrade(ctx context.Context, req *http.Request, st *proto.Stream) {
	conn, err := h.dial(ctx, "tcp", h.target.Host)
	if err != nil {
		if ctx.Err() == nil {
			h.log.Warn("origin.error", "event", "origin.error", "error_code", proto.CodeInternalError.String())
		}
		st.Reset(proto.CodeInternalError)
		return
	}
	var closeOnce sync.Once
	closeConn := func() { closeOnce.Do(func() { conn.Close() }) }
	defer closeConn()
	// Ties the lifetime of the manual connection to the stream's: a reset
	// (idle timeout, session loss, peer disconnect) must unblock this
	// goroutine the same way context cancellation would for h.client.Do.
	defer context.AfterFunc(ctx, closeConn)()

	if err := req.Write(conn); err != nil {
		st.Reset(proto.CodeInternalError)
		return
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		code := proto.CodeInternalError
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			code = proto.CodeTimeout
		}
		if ctx.Err() == nil {
			h.log.Warn("origin.error", "event", "origin.error", "error_code", code.String())
		}
		st.Reset(code)
		return
	}

	if resp.StatusCode != http.StatusSwitchingProtocols {
		// The origin declined the upgrade: proxy its answer like any other response.
		defer resp.Body.Close()
		stripHopByHop(resp.Header)
		rm, err := proto.EncodeResponseMeta(proto.ResponseMeta{Status: resp.StatusCode, Header: resp.Header, ContentLength: resp.ContentLength}, h.opts.Meta)
		if err != nil {
			st.Reset(proto.CodeInternalError)
			return
		}
		if err := st.SendResponse(rm); err != nil {
			h.log.Debug("origin.send_response_failed", "event", "origin.send_response_failed", "err", err.Error())
			return
		}
		if _, err := io.Copy(st, resp.Body); err != nil {
			st.Reset(proto.CodeInternalError)
			return
		}
		_ = st.CloseWrite()
		go io.Copy(io.Discard, st)
		return
	}

	stripHopByHopKeepUpgrade(resp.Header)
	rm, err := proto.EncodeResponseMeta(proto.ResponseMeta{Status: resp.StatusCode, Header: resp.Header, ContentLength: -1}, h.opts.Meta)
	if err != nil {
		st.Reset(proto.CodeInternalError)
		return
	}
	if err := st.SendResponse(rm); err != nil {
		h.log.Debug("origin.send_response_failed", "event", "origin.send_response_failed", "err", err.Error())
		return
	}
	// Any bytes the origin already sent past the response headers (a frame
	// racing the handshake) are sitting in br's buffer; forward them before
	// switching to raw conn reads.
	if n := br.Buffered(); n > 0 {
		buf := make([]byte, n)
		if _, err := io.ReadFull(br, buf); err != nil {
			st.Reset(proto.CodeInternalError)
			return
		}
		if _, err := st.Write(buf); err != nil {
			return
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); io.Copy(st, conn); _ = st.CloseWrite() }()
	go func() { defer wg.Done(); io.Copy(conn, st); closeWriteOrClose(conn) }()
	wg.Wait()
}

// closeWriteOrClose half-closes c's send side if possible, otherwise closes
// it outright.
func closeWriteOrClose(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
}
