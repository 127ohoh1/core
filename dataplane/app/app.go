// Package app assembles the edge (data plane) from configuration. It is shared
// by cmd/edge and integration tests.
package app

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/127ohoh1/core/dataplane/cert"
	"github.com/127ohoh1/core/dataplane/controlclient"
	"github.com/127ohoh1/core/dataplane/enforce"
	"github.com/127ohoh1/core/dataplane/ingress"
	"github.com/127ohoh1/core/dataplane/interedge"
	"github.com/127ohoh1/core/dataplane/metering"
	"github.com/127ohoh1/core/dataplane/policycache"
	"github.com/127ohoh1/core/dataplane/presence"
	"github.com/127ohoh1/core/dataplane/routing"
	dtunnel "github.com/127ohoh1/core/dataplane/tunnel"
	"github.com/127ohoh1/core/internal/clock"
	"github.com/127ohoh1/core/internal/config"
	"github.com/127ohoh1/core/internal/devtls"
	"github.com/127ohoh1/core/internal/health"
	"github.com/127ohoh1/core/internal/observability"
	"github.com/127ohoh1/core/protocol/auth"
	pp "github.com/127ohoh1/core/protocol/policy"
	proto "github.com/127ohoh1/core/protocol/tunnel"
)

// Options carries injectable dependencies.
type Options struct {
	Log       *slog.Logger
	Clock     clock.Clock
	Directory routing.TunnelDirectory
	Enforcer  ingress.Enforcer
	// StaticKeys, if set, seeds the key cache (skips waiting for the control plane).
	StaticKeys auth.KeySet
	// Admission overrides the default (allow all).
	Admission dtunnel.Admission
}

// Addrs are the bound listener addresses.
type Addrs struct{ Ingress, Tunnel, Admin, Internal string }

// App is an assembled edge.
type App struct {
	Cfg         config.Edge
	Log         *slog.Logger
	Clock       clock.Clock
	Metrics     *observability.Registry
	Registry    *dtunnel.Registry
	Tunnel      *dtunnel.Server
	Ingress     *ingress.Handler
	Enforcer    *enforce.Enforcer
	Usage       *metering.Collector
	Presence    *presence.Reporter
	Cert        cert.CertificateProvider
	Watchdog    *health.Watchdog
	PolicyCache *policycache.Cache
	Keys        *controlclient.KeyCache
	CP          *controlclient.Client
	Dir         routing.TunnelDirectory
	TLS         devtls.Bundle // development TLS bundle (zero when certificates come from files)

	ready     atomic.Bool
	draining  atomic.Bool
	ingressS  *http.Server
	adminS    *http.Server
	tunnelLn  net.Listener
	internalS *http.Server
	internalH http.Handler
	addrs     Addrs
	wg        sync.WaitGroup
	cancel    context.CancelFunc

	// acmeHandler, when set by setupCertificates (Autocert), serves ACME
	// HTTP-01 challenges and redirects; acmeS/acmeLn are its listener.
	acmeHandler http.Handler
	acmeS       *http.Server
	acmeLn      net.Listener
}

// New validates cfg and assembles the edge.
func New(cfg config.Edge, o Options) (*App, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if o.Clock == nil {
		o.Clock = clock.Real{}
	}
	if o.Log == nil {
		o.Log = observability.NewLogger(os.Stderr, cfg.LogLevel, "edge")
	}
	if cfg.IngressPlainHTTP {
		o.Log.Warn("DEVELOPMENT: public ingress is serving plain HTTP", observability.FieldEvent, "dev.ingress_plain_http")
	}
	a := &App{Cfg: cfg, Log: o.Log, Clock: o.Clock, Metrics: observability.NewRegistry(), Registry: dtunnel.NewRegistry()}
	a.Metrics.RegisterRuntime()
	a.Watchdog = health.NewWatchdog()
	a.Watchdog.Register("keys", cfg.PolicyRefresh.D())
	a.Watchdog.Register("janitor", time.Minute)
	a.Watchdog.Register("usage_flush", cfg.UsageFlush.D())
	a.Watchdog.Register("presence", time.Second)

	a.CP = controlclient.New(cfg.ControlPlaneURL, cfg.EdgeServiceToken, nil)
	a.Keys = controlclient.NewKeyCache(a.CP.Keys)
	if o.StaticKeys != nil {
		a.Keys.Set(o.StaticKeys)
	}
	a.Dir = o.Directory
	if a.Dir == nil && cfg.RedisURL != "" {
		// Multi-edge DEVELOPMENT profile: leases in Redis (ADR 0005).
		rd, err := routing.NewRedis(cfg.RedisURL)
		if err != nil {
			return nil, fmt.Errorf("redis_url: %w", err)
		}
		a.Dir = rd
		o.Log.Warn("DEVELOPMENT: multi-edge routing through Redis enabled", observability.FieldEvent, "dev.multi_edge")
	}
	if a.Dir == nil {
		a.Dir = routing.NewInMemory(o.Clock)
	}
	a.PolicyCache = policycache.New(policycache.Config{StaleGrace: cfg.PolicyStaleGrace.D(), Refresh: cfg.PolicyRefresh.D()},
		a.CP, o.Clock, policycache.NewMetrics(a.Metrics),
		func(msg string, kv ...any) { o.Log.Warn(msg, append([]any{observability.FieldEvent, msg}, kv...)...) })
	a.Usage = metering.NewCollector(cfg.EdgeID, a.CP, metering.NewMetrics(a.Metrics))
	a.Usage.Tick = func() { a.Watchdog.Beat("usage_flush") }
	a.Presence = presence.New(cfg.EdgeID, a.CP, o.Clock, func() []string {
		var ids []string
		for _, l := range a.Registry.Snapshot() {
			ids = append(ids, l.EndpointID)
		}
		return ids
	})
	a.Presence.Tick = func() { a.Watchdog.Beat("presence") }
	a.Enforcer = enforce.New(a.PolicyCache, a.Usage, o.Clock, enforce.NewMetrics(a.Metrics))
	var enf ingress.Enforcer = a.Enforcer
	if o.Enforcer != nil {
		enf = o.Enforcer
	}
	admission := o.Admission
	if admission == nil {
		admission = a.Enforcer
	}

	scfg := proto.Defaults()
	scfg.MaxFramePayload, scfg.StreamWindow, scfg.ConnWindow = cfg.MaxFramePayload, cfg.StreamWindow, cfg.ConnWindow
	scfg.MaxStreams = cfg.MaxStreamsPerSession
	scfg.PingInterval, scfg.PingTimeout = cfg.PingInterval.D(), cfg.PingTimeout.D()

	a.Tunnel = dtunnel.NewServer(dtunnel.ServerConfig{
		EdgeID: cfg.EdgeID, Audience: cfg.EdgeAudience, Session: scfg, MaxSessions: cfg.MaxSessions,
		SupersedeDrain: cfg.DrainTimeout.D(), InternalAddr: cfg.AdvertiseInternal, LeaseTTL: cfg.LeaseTTL.D(),
	}, a.Keys, admission, a.Dir, a.Registry, o.Clock, o.Log, dtunnel.NewMetrics(a.Metrics), dtunnel.Hooks{
		OnConnect: func(l *dtunnel.Live) { a.Presence.Connected(l.EndpointID) },
		OnDisconnect: func(l *dtunnel.Live) {
			a.Presence.Disconnected(l.EndpointID)
			// Report what this tunnel carried right away: a session that ends is
			// often a handoff, and the next owner must see current usage.
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = a.Usage.Flush(ctx)
			}()
		},
	})

	a.Ingress = ingress.New(ingress.Config{
		BaseDomain: cfg.BaseDomain, EdgeID: cfg.EdgeID, AllowPlainHTTP: cfg.IngressPlainHTTP,
		MaxDuration: cfg.RequestMaxDuration.D(), IdleTimeout: cfg.RequestIdleTimeout.D(), ResponseHeaderTimeout: cfg.ResponseHeaderTimeout.D(),
		Meta: proto.MetaLimits{MaxBytes: min(cfg.MaxFramePayload, 64<<10)},
	}, a.Registry, enf, o.Clock, o.Log, ingress.NewMetrics(a.Metrics))
	if cfg.InternalAddr != "" {
		// Requests for tunnels owned by another edge are forwarded over an
		// authenticated hop and metered once, at the owner.
		hopMetrics := interedge.NewMetrics(a.Metrics)
		a.Ingress.Remote = interedge.NewForwarder(a.Dir, cfg.EdgeID, cfg.EdgeServiceToken, hopMetrics)
		a.internalH = interedge.Internal(cfg.EdgeServiceToken, ingress.New(ingress.Config{
			BaseDomain: cfg.BaseDomain, EdgeID: cfg.EdgeID, AllowPlainHTTP: true, // TLS was terminated by the forwarding edge
			MaxDuration: cfg.RequestMaxDuration.D(), IdleTimeout: cfg.RequestIdleTimeout.D(), ResponseHeaderTimeout: cfg.ResponseHeaderTimeout.D(),
			Meta: proto.MetaLimits{MaxBytes: min(cfg.MaxFramePayload, 64<<10)},
		}, a.Registry, enf, o.Clock, o.Log, ingress.NewMetrics(a.Metrics))) // no Remote: a hop is never forwarded again
	}
	// A tunnel must not outlive its endpoint's permission to exist: when policy
	// says suspended/expired/released, drop the session immediately (the
	// client's reconnect is then refused at admission).
	a.PolicyCache.OnChange(func(_, cur pp.EndpointPolicy, _ bool) {
		if cur.State == pp.StateActive {
			return
		}
		if l, ok := a.Registry.ByEndpoint(cur.EndpointID); ok {
			o.Log.Info("tunnel.revoked", observability.FieldEvent, "tunnel.revoked", observability.FieldEndpoint, cur.EndpointID, "state", string(cur.State))
			l.Session.GoAway(proto.CodeShutdown)
			l.Session.Close()
		}
	})
	return a, nil
}

// setupCertificates prepares the CertificateProvider. With explicit files
// (production, or any external ACME client writing them) they are used as is;
// otherwise, outside production, a development CA and certificate are
// generated into DevTLSDir.
func (a *App) setupCertificates() error {
	if a.Cfg.AutocertCacheDir != "" {
		var extra []string
		if a.Cfg.AutocertHosts != "" {
			extra = strings.Split(a.Cfg.AutocertHosts, ",")
		}
		// Issue only for a name with a live tunnel, or one the control plane
		// confirms is an active reserved (paid) name, so a certificate can be
		// warmed right after payment (ADR 0011). Names nobody has reserved
		// and connected are refused, keeping the unauthenticated-issuance DoS
		// found in the 2026-10-01 review closed.
		gate := &cert.IssuanceGate{
			Live: func(ctx context.Context, label string) bool {
				_, err := a.Dir.Lookup(ctx, label)
				return err == nil
			},
			Lookup: a.CP.HostnameStatus,
			Now:    a.Clock.Now,
		}
		prov, handler := cert.NewAutocert(a.Cfg.AutocertCacheDir, a.Cfg.BaseDomain, a.Cfg.AutocertEmail, extra, gate.Allow)
		a.Cert = prov
		a.acmeHandler = handler
		return nil
	}
	certFile, keyFile := a.Cfg.CertFile, a.Cfg.KeyFile
	if certFile == "" {
		if a.Cfg.AppEnv == config.EnvProduction {
			return errors.New("certificates are required in production")
		}
		var err error
		a.TLS, err = devtls.LoadOrGenerate(a.Cfg.DevTLSDir, []string{a.Cfg.BaseDomain, "*." + a.Cfg.BaseDomain, "localhost", "127.0.0.1", "::1", "edge", "edge-1", "edge-2"}, a.Clock.Now())
		if err != nil {
			return err
		}
		a.Log.Warn("DEVELOPMENT: using a generated local CA and certificate", observability.FieldEvent, "dev.tls", "ca", a.Cfg.DevTLSDir+"/ca.pem")
		certFile, keyFile = a.Cfg.DevTLSDir+"/cert.pem", a.Cfg.DevTLSDir+"/key.pem"
	}
	prov, err := cert.NewFile(certFile, keyFile, a.Cfg.BaseDomain, a.Clock, a.Log, cert.NewMetrics(a.Metrics))
	if err != nil {
		return fmt.Errorf("load certificate: %w", err)
	}
	a.Cert = prov
	return nil
}

// ReloadCertificates re-reads the certificate files (SIGHUP handler). A no-op
// when certificates come from Autocert, which renews on its own.
func (a *App) ReloadCertificates() error {
	if a.Cert == nil {
		return errors.New("certificates not initialised")
	}
	if r, ok := a.Cert.(interface{ Reload() error }); ok {
		return r.Reload()
	}
	return nil
}

// Start binds the listeners and begins serving.
func (a *App) Start() error {
	if err := a.setupCertificates(); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.cancel = cancel

	var err error
	// The tunnel needs TLS 1.3 (channel binding through the exporter).
	a.tunnelLn, err = tls.Listen("tcp", a.Cfg.TunnelAddr, &tls.Config{MinVersion: tls.VersionTLS13, GetCertificate: a.Cert.GetCertificate})
	if err != nil {
		cancel()
		return fmt.Errorf("tunnel listener: %w", err)
	}
	iln, err := net.Listen("tcp", a.Cfg.IngressAddr)
	if err != nil {
		cancel()
		a.tunnelLn.Close()
		return fmt.Errorf("ingress listener: %w", err)
	}
	aln, err := net.Listen("tcp", a.Cfg.AdminAddr)
	if err != nil {
		cancel()
		a.tunnelLn.Close()
		iln.Close()
		return fmt.Errorf("admin listener: %w", err)
	}
	a.addrs = Addrs{Ingress: iln.Addr().String(), Tunnel: a.tunnelLn.Addr().String(), Admin: aln.Addr().String()}
	if a.acmeHandler != nil {
		if a.acmeLn, err = net.Listen("tcp", a.Cfg.AutocertHTTPAddr); err != nil {
			cancel()
			a.tunnelLn.Close()
			iln.Close()
			aln.Close()
			return fmt.Errorf("acme http listener: %w", err)
		}
		a.acmeS = &http.Server{Handler: a.acmeHandler, ReadHeaderTimeout: 5 * time.Second}
	}
	var xln net.Listener
	if a.internalH != nil {
		if xln, err = net.Listen("tcp", a.Cfg.InternalAddr); err != nil {
			cancel()
			a.tunnelLn.Close()
			iln.Close()
			aln.Close()
			return fmt.Errorf("internal listener: %w", err)
		}
		a.addrs.Internal = xln.Addr().String()
		if a.Cfg.AdvertiseInternal == "" { // dev: advertise what we bound
			a.Tunnel.SetInternalAddr(a.addrs.Internal)
		}
		a.internalS = &http.Server{Handler: a.internalH, ReadHeaderTimeout: a.Cfg.RequestHeaderTimeout.D(), MaxHeaderBytes: 32 << 10}
	}

	a.ingressS = &http.Server{Handler: a.Ingress, TLSConfig: ingress.TLSConfig(a.Cert.GetCertificate), ReadHeaderTimeout: a.Cfg.RequestHeaderTimeout.D(), IdleTimeout: 120 * time.Second,
		MaxHeaderBytes: 32 << 10, ErrorLog: slog.NewLogLogger(a.Log.Handler(), slog.LevelWarn)}
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", a.Metrics.Handler())
	// Liveness: only a wedged process fails it. A control-plane outage must not.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		if s := a.Watchdog.Stalled(); len(s) > 0 {
			http.Error(w, "stalled: "+strings.Join(s, ","), http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !a.ready.Load() || a.draining.Load() {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte("ready\n"))
	})
	a.adminS = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}

	serve := func(f func() error, name string) {
		a.wg.Add(1)
		go func() {
			defer a.wg.Done()
			if err := f(); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
				a.Log.Error("listener.failed", observability.FieldEvent, "listener.failed", "listener", name, "err", err.Error())
			}
		}()
	}
	serve(func() error { return a.Tunnel.Serve(a.tunnelLn) }, "tunnel")
	if a.Cfg.IngressPlainHTTP {
		serve(func() error { return a.ingressS.Serve(iln) }, "ingress")
	} else {
		// ServeTLS (not tls.NewListener) so HTTP/2 is negotiated via ALPN.
		serve(func() error { return a.ingressS.ServeTLS(iln, "", "") }, "ingress")
	}
	serve(func() error { return a.adminS.Serve(aln) }, "admin")
	if xln != nil {
		serve(func() error { return a.internalS.Serve(xln) }, "internal")
	}
	if a.acmeS != nil {
		serve(func() error { return a.acmeS.Serve(a.acmeLn) }, "acme-http")
	}

	a.wg.Add(6)
	go func() {
		defer a.wg.Done()
		if w, ok := a.Cert.(interface {
			Watch(<-chan struct{}, time.Duration)
		}); ok {
			w.Watch(ctx.Done(), a.Cfg.CertReloadInterval.D())
		} else {
			<-ctx.Done()
		}
	}()
	go func() { defer a.wg.Done(); a.keyLoop(ctx) }()
	go func() { defer a.wg.Done(); a.PolicyCache.Run(ctx) }()
	go func() { defer a.wg.Done(); a.Usage.Run(ctx, a.Cfg.UsageFlush.D()) }()
	go func() { defer a.wg.Done(); a.Presence.Run(ctx, time.Second, 20*time.Second) }()
	go func() {
		defer a.wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case <-a.Clock.After(time.Minute):
				a.Watchdog.Beat("janitor")
				a.Enforcer.Janitor()
			}
		}
	}()
	a.Log.Info("edge.listening", observability.FieldEvent, "edge.listening", observability.FieldEdge, a.Cfg.EdgeID,
		"ingress", a.addrs.Ingress, "tunnel", a.addrs.Tunnel, "admin", a.addrs.Admin)
	return nil
}

// keyLoop obtains the verification keys (retrying until the control plane is
// reachable) and then refreshes them periodically. The edge becomes ready once
// it holds a key set.
func (a *App) keyLoop(ctx context.Context) {
	if len(a.Keys.Keys()) > 0 {
		a.ready.Store(true)
	}
	for {
		a.Watchdog.Beat("keys")
		rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := a.Keys.Refresh(rctx)
		cancel()
		wait := a.Cfg.PolicyRefresh.D()
		if err != nil {
			a.Log.Warn("keys.refresh_failed", observability.FieldEvent, "keys.refresh_failed", "err", err.Error())
			if len(a.Keys.Keys()) == 0 {
				wait = time.Second
			}
		} else {
			a.ready.Store(true)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// Addrs returns the bound addresses (valid after Start).
func (a *App) Addrs() Addrs { return a.addrs }

// Ready reports readiness.
func (a *App) Ready() bool { return a.ready.Load() && !a.draining.Load() }

// Shutdown drains the edge: fail readiness, stop accepting public requests,
// GOAWAY tunnels and let streams finish (bounded by ctx), then stop workers.
func (a *App) Shutdown(ctx context.Context) error {
	a.draining.Store(true) // readiness goes false first so load balancers stop sending traffic
	a.Log.Info("edge.draining", observability.FieldEvent, "edge.draining")
	var err error
	if a.ingressS != nil {
		err = a.ingressS.Shutdown(ctx) // waits for in-flight public requests
	}
	if a.tunnelLn != nil {
		a.tunnelLn.Close()
	}
	a.Tunnel.Shutdown(ctx)
	if a.internalS != nil {
		_ = a.internalS.Shutdown(ctx)
	}
	// Report everything that was metered: usage first (bounded loss otherwise),
	// then the final presence updates (the tunnel disconnects just happened).
	fctx, fcancel := context.WithTimeout(context.Background(), 5*time.Second)
	if uerr := a.Usage.Shutdown(fctx); uerr != nil {
		a.Log.Error("usage.shutdown_flush_failed", observability.FieldEvent, "usage.shutdown_flush_failed", "err", uerr.Error())
	}
	_ = a.Presence.Flush(fctx)
	fcancel()
	if a.cancel != nil {
		a.cancel()
	}
	if a.adminS != nil {
		_ = a.adminS.Shutdown(ctx)
	}
	if a.acmeS != nil {
		_ = a.acmeS.Shutdown(ctx)
	}
	a.wg.Wait()
	return err
}
