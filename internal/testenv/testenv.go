// Package testenv assembles a complete in-process system (control plane, edge,
// clients, local origins) for integration and failure tests.
package testenv

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/127ohoh1/core/client/api"
	cid "github.com/127ohoh1/core/client/identity"
	"github.com/127ohoh1/core/client/origin"
	"github.com/127ohoh1/core/client/session"
	cpapp "github.com/127ohoh1/core/controlplane/app"
	"github.com/127ohoh1/core/controlplane/policy"
	edgeapp "github.com/127ohoh1/core/dataplane/app"
	"github.com/127ohoh1/core/dataplane/routing"
	"github.com/127ohoh1/core/internal/clock"
	"github.com/127ohoh1/core/internal/config"
	"github.com/127ohoh1/core/internal/observability"
)

// Service token shared between the control plane and the edge in tests.
const ServiceToken = "test-edge-service-token-0123456789"

// BaseDomain used by tests.
const BaseDomain = "127ohoh1.test"

// FastCatalog is the default test fixture: the canonical plans with bandwidth
// and monthly transfer scaled up 1000x so functional tests are not throttled.
// The canonical constants themselves are never modified; tests that verify
// real limits pass policy.DefaultCatalog() (or their own fixture) explicitly.
func FastCatalog() *policy.Catalog {
	ps := policy.Canonical()
	for i := range ps {
		ps[i].BandwidthBytesPerSecond *= 1000
		ps[i].MonthlyTransferBytes *= 1000
	}
	return policy.NewCatalog(ps...)
}

// Canonical returns the unmodified canonical catalog (for tests of exact limits).
func Canonical() *policy.Catalog { return policy.DefaultCatalog() }

// Options tweaks the environment.
type Options struct {
	Clock     clock.Clock
	CP        func(*config.ControlPlane)
	Edge      func(*config.Edge)
	EdgeOpts  func(*edgeapp.Options)
	NoEdge    bool
	Catalog   *policy.Catalog // reduced-scale plan fixture
	LogWriter io.Writer
}

// Env is a running system.
type Env struct {
	T        testing.TB
	CP       *cpapp.App
	CPServer *httptest.Server
	Edge     *edgeapp.App
	Clock    clock.Clock
	http     *http.Client
	logw     io.Writer
	ecfg     config.Edge
	eopts    edgeapp.Options
	cpDown   atomic.Bool
}

// SetControlPlaneDown simulates a control-plane outage (or its recovery). The
// control plane keeps its state; only the network path is cut.
func (e *Env) SetControlPlaneDown(down bool) { e.cpDown.Store(down) }

// New starts a control plane and (unless NoEdge) an edge.
func New(t testing.TB, o Options) *Env {
	t.Helper()
	if o.Clock == nil {
		o.Clock = clock.Real{}
	}
	if o.LogWriter == nil {
		o.LogWriter = io.Discard
	}
	if o.Catalog == nil {
		o.Catalog = FastCatalog()
	}
	log := observability.NewLogger(o.LogWriter, "debug", "test")

	ccfg := config.DefaultControlPlane()
	ccfg.AppEnv, ccfg.BaseDomain, ccfg.EdgeServiceToken = config.EnvTest, BaseDomain, ServiceToken
	ccfg.EdgeTunnelAddr = "127.0.0.1:0"
	ccfg.PublicPort = 0
	if o.CP != nil {
		o.CP(&ccfg)
	}
	cp, err := cpapp.New(ccfg, cpapp.Options{Log: log, Clock: o.Clock, Catalog: o.Catalog})
	if err != nil {
		t.Fatal(err)
	}
	e := &Env{T: t, CP: cp, Clock: o.Clock, logw: o.LogWriter, http: &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}}
	e.CPServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if e.cpDown.Load() { // simulate an outage: drop the connection without answering
			if hj, ok := w.(http.Hijacker); ok {
				if c, _, err := hj.Hijack(); err == nil {
					c.Close()
					return
				}
			}
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		cp.Handler().ServeHTTP(w, r)
	}))
	t.Cleanup(e.CPServer.Close)
	ctx, cancel := context.WithCancel(context.Background())
	go cp.Run(ctx)
	t.Cleanup(cancel)
	if o.NoEdge {
		return e
	}

	ecfg := config.DefaultEdge()
	ecfg.AppEnv, ecfg.BaseDomain, ecfg.EdgeServiceToken = config.EnvTest, BaseDomain, ServiceToken
	ecfg.ControlPlaneURL = e.CPServer.URL
	ecfg.IngressAddr, ecfg.TunnelAddr, ecfg.AdminAddr = "127.0.0.1:0", "127.0.0.1:0", "127.0.0.1:0"
	ecfg.DevTLSDir = filepath.Join(t.TempDir(), "tls")
	ecfg.IngressPlainHTTP = true
	if o.Edge != nil {
		o.Edge(&ecfg)
	}
	eo := edgeapp.Options{Log: log, Clock: o.Clock, StaticKeys: cp.Keys}
	if o.EdgeOpts != nil {
		o.EdgeOpts(&eo)
	}
	edge, err := edgeapp.New(ecfg, eo)
	if err != nil {
		t.Fatal(err)
	}
	if err := edge.Start(); err != nil {
		t.Fatal(err)
	}
	e.Edge, e.ecfg, e.eopts = edge, ecfg, eo
	t.Cleanup(func() {
		sctx, c := context.WithTimeout(context.Background(), 5*time.Second)
		defer c()
		e.Edge.Shutdown(sctx)
	})
	return e
}

// StartSecondEdge starts another edge on ephemeral ports, connected to the same
// control plane and sharing dir (a stand-in for Redis) so it can route to
// tunnels owned by the first edge. The first edge must have been started with
// the same directory; use Options.EdgeOpts to pass it.
func (e *Env) StartSecondEdge(dir routing.TunnelDirectory, mut func(*config.Edge)) *edgeapp.App {
	e.T.Helper()
	cfg := e.ecfg
	cfg.EdgeID = "edge-2"
	cfg.IngressAddr, cfg.TunnelAddr, cfg.AdminAddr = "127.0.0.1:0", "127.0.0.1:0", "127.0.0.1:0"
	cfg.InternalAddr = "127.0.0.1:0"
	cfg.AdvertiseInternal = ""
	if mut != nil {
		mut(&cfg)
	}
	opts := e.eopts
	opts.Directory = dir
	edge, err := edgeapp.New(cfg, opts)
	if err != nil {
		e.T.Fatal(err)
	}
	if err := edge.Start(); err != nil {
		e.T.Fatal(err)
	}
	e.T.Cleanup(func() {
		ctx, c := context.WithTimeout(context.Background(), 5*time.Second)
		defer c()
		edge.Shutdown(ctx)
	})
	return edge
}

// StopEdge shuts the edge down (graceful, bounded by grace).
func (e *Env) StopEdge(grace time.Duration) {
	e.T.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), grace)
	defer cancel()
	e.Edge.Shutdown(ctx)
}

// StartEdge starts a fresh edge process on the same addresses and TLS
// material (a restart: all in-memory tunnel state is gone).
func (e *Env) StartEdge() {
	e.T.Helper()
	cfg := e.ecfg
	cfg.IngressAddr, cfg.TunnelAddr, cfg.AdminAddr = e.Edge.Addrs().Ingress, e.Edge.Addrs().Tunnel, e.Edge.Addrs().Admin
	opts := e.eopts
	opts.Directory = nil
	edge, err := edgeapp.New(cfg, opts)
	if err != nil {
		e.T.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if err = edge.Start(); err == nil {
			break
		}
		if time.Now().After(deadline) {
			e.T.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond) // ports may linger briefly
	}
	e.Edge = edge
}

// Runner is a reconnecting client (what `expose` runs).
type Runner struct {
	Endpoint api.Endpoint
	Cancel   context.CancelFunc
	Done     chan error
	mu       sync.Mutex
	states   []string
	connects int
}

// States returns the recorded state transitions.
func (r *Runner) States() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.states...)
}

// Connects returns how many times the tunnel was (re)established.
func (r *Runner) Connects() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.connects
}

// RunClient starts the reconnecting client for an existing or new endpoint.
func (e *Env) RunClient(id cid.Identity, originURL, endpointID string, bo session.Backoff) *Runner {
	e.T.Helper()
	c := e.API(id)
	var ep api.Endpoint
	var err error
	if endpointID == "" {
		ep, err = c.CreateEndpoint(context.Background(), "")
	} else {
		ep, err = c.GetEndpoint(context.Background(), endpointID)
	}
	if err != nil {
		e.T.Fatal(err)
	}
	target, err := origin.ParseTarget(originURL, false)
	if err != nil {
		e.T.Fatal(err)
	}
	h := origin.New(target, origin.Options{})
	tunnelAddr, tlsCfg := e.Edge.Addrs().Tunnel, e.TLSConfig() // an edge restart reuses both
	ctx, cancel := context.WithCancel(context.Background())
	r := &Runner{Endpoint: ep, Cancel: cancel, Done: make(chan error, 1)}
	go func() {
		r.Done <- session.Run(ctx, session.RunOptions{
			Credential: func(ctx context.Context) (api.TunnelCredential, error) {
				cr, err := c.TunnelCredentials(ctx, ep.ID)
				cr.Edge.Addr = tunnelAddr
				return cr, err
			},
			TLS: tlsCfg, Identity: id, Handler: h, Backoff: bo, DrainGrace: 2 * time.Second,
			OnState:     func(s session.State, info string) { r.mu.Lock(); r.states = append(r.states, string(s)); r.mu.Unlock() },
			OnConnected: func(*session.Connection) { r.mu.Lock(); r.connects++; r.mu.Unlock() },
		})
	}()
	e.T.Cleanup(cancel)
	return r
}

// NewIdentity creates a fresh client identity in a temp dir.
func (e *Env) NewIdentity() cid.Identity {
	id, err := cid.Generate(filepath.Join(e.T.TempDir(), "id"))
	if err != nil {
		e.T.Fatal(err)
	}
	return id
}

// CPURL returns the control-plane base URL.
func (e *Env) CPURL() string { return e.CPServer.URL }

// API returns a control-plane client for id.
func (e *Env) API(id cid.Identity) *api.Client { return api.New(e.CPServer.URL, id, nil) }

// TLSConfig trusts the edge's development CA.
func (e *Env) TLSConfig() *tls.Config {
	return &tls.Config{RootCAs: e.Edge.TLS.CAPool(), ServerName: "127.0.0.1", MinVersion: tls.VersionTLS13}
}

// Origin starts a local HTTP origin bound to loopback.
func (e *Env) Origin(h http.Handler) *httptest.Server {
	srv := httptest.NewServer(h)
	e.T.Cleanup(srv.Close)
	return srv
}

// Exposure is a client that has connected a tunnel for one endpoint.
type Exposure struct {
	Endpoint api.Endpoint
	Identity cid.Identity
	Conn     *session.Connection
	Done     chan error // receives the Serve result when the session ends
}

// Expose creates an endpoint (or reuses endpointID if non-empty), connects a
// tunnel and serves the given origin over it.
func (e *Env) Expose(id cid.Identity, originURL string, endpointID string) *Exposure {
	e.T.Helper()
	ctx := context.Background()
	c := e.API(id)
	var ep api.Endpoint
	var err error
	if endpointID == "" {
		if ep, err = c.CreateEndpoint(ctx, ""); err != nil {
			e.T.Fatal(err)
		}
	} else if ep, err = c.GetEndpoint(ctx, endpointID); err != nil {
		e.T.Fatal(err)
	}
	cred, err := c.TunnelCredentials(ctx, ep.ID)
	if err != nil {
		e.T.Fatal(err)
	}
	conn, err := session.Connect(ctx, e.Edge.Addrs().Tunnel, e.TLSConfig(), cred, id, 5*time.Second)
	if err != nil {
		e.T.Fatal(err)
	}
	target, err := origin.ParseTarget(originURL, false)
	if err != nil {
		e.T.Fatal(err)
	}
	h := origin.New(target, origin.Options{Log: observability.NewLogger(e.logw, "debug", "client")})
	x := &Exposure{Endpoint: ep, Identity: id, Conn: conn, Done: make(chan error, 1)}
	go func() { x.Done <- session.Serve(ctx, conn.Session, h) }()
	e.T.Cleanup(func() { conn.Session.Close() })
	e.WaitRegistered(ep.Hostname)
	return x
}

// WaitRegistered blocks until the edge routes the hostname.
func (e *Env) WaitRegistered(host string) {
	e.T.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := e.Edge.Registry.ByHostname(host); ok {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	e.T.Fatalf("edge never registered %s", host)
}

// Request sends an HTTP request to the edge ingress with the tenant Host.
func (e *Env) Request(host, method, path string, body io.Reader, hdr map[string]string) (*http.Response, error) {
	req, err := http.NewRequest(method, "http://"+e.Edge.Addrs().Ingress+path, body)
	if err != nil {
		return nil, err
	}
	if host != "" {
		req.Host = host + "." + BaseDomain
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	return e.http.Do(req)
}

// Get is Request with GET and no body; it reads and returns the body.
func (e *Env) Get(host, path string) (*http.Response, string) {
	e.T.Helper()
	resp, err := e.Request(host, "GET", path, nil, nil)
	if err != nil {
		e.T.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

// LogBuffer is a goroutine-safe buffer for capturing logs in tests.
type LogBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *LogBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *LogBuffer) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

// HTTPSClient returns a client that dials the edge ingress directly, verifying
// its certificate against the development CA with the given SNI/verification
// name (empty = derive from the URL host).
func (e *Env) HTTPSClient(serverName string) *http.Client {
	addr := e.Edge.Addrs().Ingress
	return &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
		ForceAttemptHTTP2: true, DisableKeepAlives: true,
		TLSClientConfig: &tls.Config{RootCAs: e.Edge.TLS.CAPool(), ServerName: serverName, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}}
}

// LoopbackAddr returns a free loopback TCP address that nothing listens on.
func LoopbackAddr(t testing.TB) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a := l.Addr().String()
	l.Close()
	return a
}

// HasPrefixFold is a small helper for header assertions.
func HasPrefixFold(s, p string) bool { return len(s) >= len(p) && strings.EqualFold(s[:len(p)], p) }
