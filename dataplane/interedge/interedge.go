// Package interedge routes a public request to the edge that owns the tunnel
// (multi-edge DEVELOPMENT profile, ADR 0005).
//
// Design rules:
//   - the tenant payload never touches the control plane;
//   - the hop is authenticated (shared service secret in this reference; use
//     mutual TLS between edges in a real deployment);
//   - usage is metered ONCE, at the owning edge: the forwarding edge is a
//     dumb streaming proxy with bounded buffers and propagated cancellation;
//   - the extra hop is visible: metrics and the X-127ohoh1-Hop response header;
//   - a request that arrived over the hop is never forwarded again (no loops).
package interedge

import (
	"context"
	"crypto/subtle"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/127ohoh1/core/dataplane/ingress"
	"github.com/127ohoh1/core/dataplane/proxy"
	"github.com/127ohoh1/core/dataplane/routing"
	"github.com/127ohoh1/core/internal/observability"
)

// Header names used on the hop.
const (
	AuthHeader     = "X-127ohoh1-Internal-Auth"
	ClientIPHeader = "X-127ohoh1-Client-Ip"
	ProtoHeader    = "X-127ohoh1-Client-Proto"
	// HopHeader is set on responses that crossed an extra edge.
	HopHeader = "X-127ohoh1-Hop"
)

// Metrics of the hop.
type Metrics struct {
	Requests *observability.Counter   // edge_interedge_requests_total{result}
	Duration *observability.Histogram // edge_interedge_forward_seconds (time to response headers)
	DirErrs  *observability.Counter   // edge_directory_errors_total{op}
}

// NewMetrics registers hop metrics.
func NewMetrics(r *observability.Registry) Metrics {
	return Metrics{
		Requests: r.Counter("edge_interedge_requests_total", "Requests forwarded to another edge by result.", "result"),
		Duration: r.Histogram("edge_interedge_forward_seconds", "Extra-hop time to the owning edge's response headers.", nil),
		DirErrs:  r.Counter("edge_directory_errors_total", "Tunnel directory failures by operation.", "op"),
	}
}

// Forwarder implements ingress.RemoteForwarder.
type Forwarder struct {
	Dir    routing.TunnelDirectory
	SelfID string
	Token  string
	Client *http.Client
	M      Metrics
	// Now/Since hooks are not needed: latency uses the wall clock.
}

// NewForwarder builds a Forwarder with a streaming-friendly HTTP client.
func NewForwarder(dir routing.TunnelDirectory, selfID, token string, m Metrics) *Forwarder {
	return &Forwarder{Dir: dir, SelfID: selfID, Token: token, M: m, Client: &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			Proxy: nil, MaxIdleConnsPerHost: 64, IdleConnTimeout: 60 * time.Second,
			ResponseHeaderTimeout: 60 * time.Second, DisableCompression: true,
		},
	}}
}

func platform(w http.ResponseWriter, status int, code, msg string) {
	h := w.Header()
	h.Set(proxy.ErrorHeader, code)
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, `{"error":{"code":"`+code+`","message":"`+msg+`"}}`+"\n")
}

// Forward returns true if it produced a response. false means "not mine":
// the ingress then answers endpoint_not_found itself.
func (f *Forwarder) Forward(w http.ResponseWriter, r *http.Request, label string) bool {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	owner, err := f.Dir.Lookup(ctx, label)
	cancel()
	switch {
	case errors.Is(err, routing.ErrNotFound):
		return false
	case err != nil:
		// Directory partition: local tunnels are unaffected, remote ones cannot be reached.
		f.M.DirErrs.Inc("lookup")
		f.M.Requests.Inc("directory_unavailable")
		platform(w, http.StatusServiceUnavailable, "directory_unavailable", "The tunnel directory is temporarily unavailable.")
		return true
	}
	if owner.EdgeID == f.SelfID || owner.InternalAddr == "" {
		return false // stale record pointing at ourselves, or an owner we cannot reach
	}

	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	out, err := http.NewRequestWithContext(r.Context(), r.Method, "http://"+owner.InternalAddr+r.URL.RequestURI(), r.Body)
	if err != nil {
		f.M.Requests.Inc("error")
		platform(w, http.StatusBadGateway, "edge_hop_failed", "The request could not be forwarded.")
		return true
	}
	out.Header = r.Header.Clone()
	proxy.StripHopByHop(out.Header)
	out.Host = r.Host
	out.ContentLength = r.ContentLength
	out.Header.Set(AuthHeader, f.Token)
	out.Header.Set(ClientIPHeader, proxy.PeerIP(r.RemoteAddr))
	out.Header.Set(ProtoHeader, scheme)

	start := time.Now()
	resp, err := f.Client.Do(out)
	if err != nil {
		if r.Context().Err() == nil {
			f.M.Requests.Inc("error")
			platform(w, http.StatusBadGateway, "edge_hop_failed", "The owning edge could not be reached.")
		}
		return true
	}
	defer resp.Body.Close()
	f.M.Duration.Observe(time.Since(start).Seconds())
	f.M.Requests.Inc("ok")
	proxy.StripHopByHop(resp.Header)
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.Header().Set(HopHeader, "1")
	w.WriteHeader(resp.StatusCode)
	rc := http.NewResponseController(w)
	buf := make([]byte, 16<<10)
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return true
			}
			_ = rc.Flush()
		}
		if rerr == io.EOF {
			return true
		}
		if rerr != nil {
			panic(http.ErrAbortHandler) // owner died mid-response: do not fake a clean end
		}
	}
}

// Internal wraps the owner-side ingress handler for the internal listener. It
// authenticates the hop and restores the original client's address and scheme
// so forwarded headers stay truthful.
func Internal(token string, next *ingress.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get(AuthHeader)), []byte(token)) != 1 || token == "" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		ip := r.Header.Get(ClientIPHeader)
		scheme := r.Header.Get(ProtoHeader)
		if scheme != "https" {
			scheme = "http"
		}
		r.Header.Del(AuthHeader)
		r.Header.Del(ClientIPHeader)
		r.Header.Del(ProtoHeader)
		r = r.WithContext(ingress.WithForwardedPeer(r.Context(), ip, scheme))
		next.ServeHTTP(w, r)
	})
}

var _ = strconv.Itoa
