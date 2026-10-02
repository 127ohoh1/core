package tunnel

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/127ohoh1/core/dataplane/routing"
	"github.com/127ohoh1/core/internal/clock"
	"github.com/127ohoh1/core/internal/ids"
	"github.com/127ohoh1/core/internal/observability"
	"github.com/127ohoh1/core/protocol/auth"
	proto "github.com/127ohoh1/core/protocol/tunnel"
)

var b64 = base64.RawURLEncoding

// TokenVerifier verifies tunnel credentials locally (no control-plane call).
type TokenVerifier interface {
	Verify(ctx context.Context, token, typ, aud string, now time.Time) (auth.Claims, error)
}

// Admission decides whether an authenticated endpoint may hold a tunnel
// (endpoint state, suspension). It is the edge's view of resolved policy.
type Admission interface {
	Admit(ctx context.Context, endpointID string) error
}

// Errors from Admission.
var (
	ErrEndpointUnavailable = errors.New("endpoint unavailable")           // suspended, released, expired
	ErrPolicyUnavailable   = errors.New("policy temporarily unavailable") // retryable
)

// AllowAll is the admission used until policy is wired (and in tests).
type AllowAll struct{}

func (AllowAll) Admit(context.Context, string) error { return nil }

// Hooks let the edge react to session lifecycle (presence reporting, metrics).
type Hooks struct {
	OnConnect    func(l *Live)
	OnDisconnect func(l *Live)
}

// Metrics observed by the server.
type Metrics struct {
	Active     *observability.Gauge   // edge_tunnel_sessions_active
	AuthOK     *observability.Counter // edge_tunnel_auth_total{result}
	AuthFail   *observability.Counter // edge_tunnel_auth_failures_total{reason}
	Superseded *observability.Counter
	Handshakes *observability.Gauge
	DirErrors  *observability.Counter // edge_directory_errors_total{op}
}

// NewMetrics registers the tunnel metrics.
func NewMetrics(r *observability.Registry) Metrics {
	return Metrics{
		Active:     r.Gauge("edge_tunnel_sessions_active", "Authenticated tunnel sessions."),
		AuthOK:     r.Counter("edge_tunnel_auth_successes_total", "Successful tunnel authentications."),
		AuthFail:   r.Counter("edge_tunnel_auth_failures_total", "Failed tunnel authentications by reason.", "reason"),
		Superseded: r.Counter("edge_tunnel_sessions_superseded_total", "Sessions superseded by a newer one for the same endpoint."),
		Handshakes: r.Gauge("edge_tunnel_handshakes_inflight", "Tunnel handshakes in progress."),
		DirErrors:  r.Counter("edge_directory_errors_total", "Tunnel directory failures by operation.", "op"),
	}
}

// ServerConfig configures the tunnel server.
type ServerConfig struct {
	EdgeID           string
	Audience         string
	Session          proto.Config
	HandshakeTimeout time.Duration
	MaxSessions      int
	MaxHandshakes    int           // concurrent unauthenticated handshakes (CPU/FD guard)
	LeaseTTL         time.Duration // directory lease
	SupersedeDrain   time.Duration // how long a superseded session may drain
	InternalAddr     string
}

// Server accepts tunnel connections.
type Server struct {
	cfg      ServerConfig
	verifier TokenVerifier
	admit    Admission
	dir      routing.TunnelDirectory
	reg      *Registry
	clk      clock.Clock
	ids      *ids.Generator
	log      *slog.Logger
	m        Metrics
	hooks    Hooks
	hsSem    chan struct{}

	mu       sync.Mutex
	draining bool
	wg       sync.WaitGroup
}

// NewServer builds a Server.
func NewServer(cfg ServerConfig, v TokenVerifier, a Admission, dir routing.TunnelDirectory, reg *Registry, clk clock.Clock, log *slog.Logger, m Metrics, h Hooks) *Server {
	if cfg.HandshakeTimeout <= 0 {
		cfg.HandshakeTimeout = 10 * time.Second
	}
	if cfg.MaxSessions <= 0 {
		cfg.MaxSessions = 10000
	}
	if cfg.MaxHandshakes <= 0 {
		cfg.MaxHandshakes = 256
	}
	if cfg.LeaseTTL <= 0 {
		cfg.LeaseTTL = 30 * time.Second
	}
	if cfg.SupersedeDrain <= 0 {
		cfg.SupersedeDrain = 10 * time.Second
	}
	if a == nil {
		a = AllowAll{}
	}
	return &Server{cfg: cfg, verifier: v, admit: a, dir: dir, reg: reg, clk: clk, ids: ids.New(clk), log: log, m: m, hooks: h,
		hsSem: make(chan struct{}, cfg.MaxHandshakes)}
}

// SetInternalAddr sets the address other edges use to reach this edge.
func (s *Server) SetInternalAddr(a string) {
	s.mu.Lock()
	s.cfg.InternalAddr = a
	s.mu.Unlock()
}

// InternalAddr returns the advertised inter-edge address.
func (s *Server) InternalAddr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg.InternalAddr
}

// Registry exposes live sessions to the ingress.
func (s *Server) Registry() *Registry { return s.reg }

// Serve accepts connections on ln (which must already be a TLS listener
// producing *tls.Conn) until ln is closed.
func (s *Server) Serve(ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			s.mu.Lock()
			d := s.draining
			s.mu.Unlock()
			if d || errors.Is(err, net.ErrClosed) {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		s.wg.Add(1)
		go func() { defer s.wg.Done(); s.ServeConn(c) }()
	}
}

// Shutdown sends GOAWAY to every session, waits up to ctx for streams to
// drain, then closes the rest.
func (s *Server) Shutdown(ctx context.Context) {
	s.mu.Lock()
	s.draining = true
	s.mu.Unlock()
	var wg sync.WaitGroup
	for _, l := range s.reg.Snapshot() {
		wg.Add(1)
		go func(l *Live) { defer wg.Done(); l.Session.Drain(ctx, proto.CodeShutdown) }(l)
	}
	wg.Wait()
	s.wg.Wait()
}

func (s *Server) isDraining() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.draining
}

func (s *Server) reject(conn net.Conn, reason, code, msg string, retryable bool) {
	s.m.AuthFail.Inc(reason)
	_ = proto.WriteHandshake(conn, proto.TypeAuthError, proto.AuthError{Code: code, Message: msg, Retryable: retryable}, 3*time.Second)
	conn.Close()
}

// ServeConn runs the handshake on conn and, on success, the session until it ends.
func (s *Server) ServeConn(conn net.Conn) {
	defer conn.Close()
	select {
	case s.hsSem <- struct{}{}:
	default:
		s.m.AuthFail.Inc("handshake_capacity")
		_ = proto.WriteHandshake(conn, proto.TypeAuthError, proto.AuthError{Code: "capacity", Message: "too many concurrent handshakes", Retryable: true}, time.Second)
		return
	}
	s.m.Handshakes.Add(1)
	live, ok := s.handshake(conn)
	s.m.Handshakes.Add(-1)
	<-s.hsSem
	if !ok {
		return
	}
	s.m.Active.Add(1)
	defer s.m.Active.Add(-1)
	log := s.log.With(observability.FieldEndpoint, live.EndpointID, observability.FieldSession, live.SessionID, observability.FieldEdge, s.cfg.EdgeID)
	log.Info("tunnel.connected", observability.FieldEvent, "tunnel.connected", "remote", live.RemoteAddr)
	if s.hooks.OnConnect != nil {
		s.hooks.OnConnect(live)
	}

	hbCtx, stopHB := context.WithCancel(context.Background())
	var hbWG sync.WaitGroup
	hbWG.Add(1)
	go func() { defer hbWG.Done(); s.heartbeat(hbCtx, live) }()

	<-live.Session.Done()
	stopHB()
	hbWG.Wait()
	if s.reg.Remove(live) {
		_ = s.dir.Release(context.Background(), live.EndpointID, live.SessionID)
	}
	if s.hooks.OnDisconnect != nil {
		s.hooks.OnDisconnect(live)
	}
	log.Info("tunnel.disconnected", observability.FieldEvent, "tunnel.disconnected", "cause", errString(live.Session.Err()))
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// heartbeat keeps the directory lease alive; losing it means another owner
// took over, so this session stops taking new work.
func (s *Server) heartbeat(ctx context.Context, l *Live) {
	t := time.NewTicker(s.cfg.LeaseTTL / 3)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			err := s.dir.Heartbeat(ctx, l.EndpointID, l.SessionID, s.cfg.LeaseTTL)
			switch {
			case err == nil:
			case errors.Is(err, routing.ErrSuperseded):
				// Another session owns the endpoint now (or our lease lapsed during a
				// partition and someone else claimed it): stop taking new work.
				if cur, ok := s.reg.ByEndpoint(l.EndpointID); ok && cur == l {
					// We are still the local owner: re-assert the lease unless a live
					// different owner exists.
					if o, lerr := s.dir.Lookup(ctx, l.Hostname); lerr == nil && o.SessionID != l.SessionID {
						s.reg.Remove(l) // stop routing new requests here; they follow the directory to the new owner
						s.supersede(l)  // GOAWAY + bounded drain + close, exactly as for a same-edge takeover
						return
					} else if lerr != nil {
						_, _ = s.dir.Claim(ctx, routing.Owner{EndpointID: l.EndpointID, Hostname: l.Hostname, EdgeID: s.cfg.EdgeID, SessionID: l.SessionID, InternalAddr: s.InternalAddr()}, s.cfg.LeaseTTL)
					}
				} else {
					s.supersede(l)
					return
				}
			default:
				s.m.DirErrors.Inc("heartbeat")
			}
		}
	}
}

func (s *Server) handshake(conn net.Conn) (*Live, bool) {
	hto := s.cfg.HandshakeTimeout
	tc, isTLS := conn.(*tls.Conn)
	if !isTLS {
		s.reject(conn, "not_tls", "protocol", "TLS required", false)
		return nil, false
	}
	if s.isDraining() {
		s.reject(conn, "draining", "shutting_down", "edge is shutting down", true)
		return nil, false
	}
	if err := tc.HandshakeContext(ctxTimeout(hto)); err != nil {
		s.m.AuthFail.Inc("tls")
		return nil, false
	}

	// 1. HELLO exchange / version negotiation.
	var hello proto.Hello
	if err := proto.ReadHandshake(conn, proto.TypeHello, &hello, hto); err != nil {
		s.m.AuthFail.Inc("bad_hello")
		return nil, false
	}
	okVer := false
	for _, v := range hello.Versions {
		if v == proto.Version {
			okVer = true
		}
	}
	if !okVer {
		s.m.AuthFail.Inc("version")
		b, _ := proto.AppendFrame(nil, proto.ErrorFrame(proto.CodeProtocolError, "unsupported protocol version; server supports 1"), proto.MaxHandshakePayload)
		_, _ = conn.Write(b)
		return nil, false
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, false
	}
	params := proto.ParamsFromConfig(s.cfg.Session)
	if err := proto.WriteHandshake(conn, proto.TypeHello, proto.Hello{Version: proto.Version, EdgeID: s.cfg.EdgeID, Nonce: b64.EncodeToString(nonce), Params: &params}, hto); err != nil {
		return nil, false
	}

	// 2. AUTH: verify the credential locally, then proof of possession.
	var am proto.Auth
	if err := proto.ReadHandshake(conn, proto.TypeAuth, &am, hto); err != nil {
		s.m.AuthFail.Inc("bad_auth_frame")
		return nil, false
	}
	now := s.clk.Now()
	claims, err := s.verifier.Verify(context.Background(), am.Token, auth.TypeTunnel, s.cfg.Audience, now)
	if err != nil {
		reason, code := "invalid_credential", "invalid_credential"
		if errors.Is(err, auth.ErrTokenExpired) {
			reason, code = "expired_credential", "credential_expired"
		}
		s.reject(conn, reason, code, "The tunnel credential was rejected.", errors.Is(err, auth.ErrTokenExpired))
		return nil, false
	}
	if claims.Endpoint == "" || claims.Hostname == "" || claims.PublicKey == "" || am.JTI != claims.ID {
		s.reject(conn, "invalid_credential", "invalid_credential", "The tunnel credential was rejected.", false)
		return nil, false
	}
	pub, err := auth.ParsePublicKey(claims.PublicKey)
	if err != nil {
		s.reject(conn, "invalid_credential", "invalid_credential", "The tunnel credential was rejected.", false)
		return nil, false
	}
	cs := tc.ConnectionState()
	exporter, err := cs.ExportKeyingMaterial(proto.ExporterLabel, nil, 32)
	if err != nil {
		s.reject(conn, "tls_exporter", "protocol", "TLS 1.3 exporter unavailable", false)
		return nil, false
	}
	sig, err := b64.Strict().DecodeString(am.Proof)
	if err != nil || len(sig) != ed25519.SignatureSize ||
		!ed25519.Verify(pub, auth.TunnelProofBytes(exporter, nonce, claims.ID, claims.Endpoint), sig) {
		s.reject(conn, "bad_proof", "invalid_credential", "The tunnel credential was rejected.", false)
		return nil, false
	}

	// 3. Admission: endpoint must be allowed to hold a tunnel right now.
	if err := s.admit.Admit(context.Background(), claims.Endpoint); err != nil {
		if errors.Is(err, ErrPolicyUnavailable) {
			s.reject(conn, "policy_unavailable", "policy_unavailable", "Policy is temporarily unavailable; retry.", true)
		} else {
			s.reject(conn, "endpoint_unavailable", "endpoint_unavailable", "The endpoint is not available.", false)
		}
		return nil, false
	}
	if s.reg.Count() >= s.cfg.MaxSessions {
		s.reject(conn, "capacity", "capacity", "The edge is at capacity.", true)
		return nil, false
	}
	sessionID := s.ids.New("ts")
	if err := proto.WriteHandshake(conn, proto.TypeAuthOK, proto.AuthOK{SessionID: sessionID, EndpointID: claims.Endpoint, Hostname: claims.Hostname}, hto); err != nil {
		return nil, false
	}

	// 4. REGISTER_ENDPOINT must match the credential exactly.
	var reg proto.Register
	if err := proto.ReadHandshake(conn, proto.TypeRegisterEndpoint, &reg, hto); err != nil {
		s.m.AuthFail.Inc("bad_register")
		return nil, false
	}
	if reg.EndpointID != claims.Endpoint || reg.Hostname != claims.Hostname {
		s.m.AuthFail.Inc("endpoint_mismatch")
		b, _ := proto.AppendFrame(nil, proto.ErrorFrame(proto.CodeUnauthenticated, "endpoint does not match credential"), proto.MaxHandshakePayload)
		_, _ = conn.Write(b)
		return nil, false
	}
	prev, err := s.dir.Claim(context.Background(), routing.Owner{EndpointID: claims.Endpoint, Hostname: claims.Hostname, EdgeID: s.cfg.EdgeID, SessionID: sessionID, InternalAddr: s.InternalAddr()}, s.cfg.LeaseTTL)
	if err != nil {
		// Degraded mode (registry partition): the local registry stays
		// authoritative for local routing, so this tunnel serves. What degrades is
		// cross-edge routing and cross-edge duplicate detection, which recover
		// when the heartbeat re-claims the lease.
		s.m.DirErrors.Inc("claim")
		s.log.Warn("directory.claim_failed", observability.FieldEvent, "directory.claim_failed", observability.FieldEndpoint, claims.Endpoint, "err", err.Error())
		prev = nil
	}
	if err := proto.WriteHandshake(conn, proto.TypeRegisterOK, nil, hto); err != nil {
		_ = s.dir.Release(context.Background(), claims.Endpoint, sessionID)
		return nil, false
	}
	proto.ClearDeadlines(conn)

	scfg := s.cfg.Session
	scfg.Logger = s.log
	sess := proto.NewSession(conn, proto.RoleServer, scfg)
	live := &Live{EndpointID: claims.Endpoint, Hostname: claims.Hostname, PrincipalID: claims.Subject, SessionID: sessionID,
		TokenID: claims.ID, Session: sess, ConnectedAt: now, RemoteAddr: conn.RemoteAddr().String()}
	old := s.reg.Add(live)
	s.m.AuthOK.Inc()
	if old != nil {
		s.supersede(old)
	} else if prev != nil && prev.EdgeID != s.cfg.EdgeID {
		s.log.Info("tunnel.superseded_remote", observability.FieldEvent, "tunnel.superseded_remote", observability.FieldEndpoint, claims.Endpoint, "previous_edge", prev.EdgeID)
	}
	return live, true
}

// supersede tells the previous session to stop taking streams, lets existing
// streams drain for a bounded time, then closes it.
func (s *Server) supersede(old *Live) {
	s.m.Superseded.Inc()
	s.log.Info("tunnel.superseded", observability.FieldEvent, "tunnel.superseded", observability.FieldEndpoint, old.EndpointID, observability.FieldSession, old.SessionID)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), s.cfg.SupersedeDrain)
		defer cancel()
		old.Session.Drain(ctx, proto.CodeSuperseded)
	}()
}

func ctxTimeout(d time.Duration) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	time.AfterFunc(d, cancel)
	return ctx
}
