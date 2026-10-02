// Package api is the control-plane HTTP surface (/v1). Handlers are thin: they
// authenticate, decode, call domain services and encode. No business rules
// live here.
package api

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/127ohoh1/core/controlplane/abuse"
	"github.com/127ohoh1/core/controlplane/audit"
	"github.com/127ohoh1/core/controlplane/endpoint"
	"github.com/127ohoh1/core/controlplane/entitlement"
	"github.com/127ohoh1/core/controlplane/identity"
	"github.com/127ohoh1/core/controlplane/offer"
	"github.com/127ohoh1/core/controlplane/payment"
	"github.com/127ohoh1/core/controlplane/policy"
	"github.com/127ohoh1/core/controlplane/usage"
	"github.com/127ohoh1/core/internal/apperr"
	"github.com/127ohoh1/core/internal/clock"
	"github.com/127ohoh1/core/internal/config"
	"github.com/127ohoh1/core/internal/ids"
	"github.com/127ohoh1/core/internal/observability"
	"github.com/127ohoh1/core/protocol/auth"
)

const maxBodyBytes = 64 << 10

// Deps are the collaborators of the API server.
type Deps struct {
	Cfg          config.ControlPlane
	Clock        clock.Clock
	IDs          *ids.Generator
	Log          *slog.Logger
	Metrics      *observability.Registry
	Identity     *identity.Service
	Endpoints    *endpoint.Service
	Signer       *auth.Signer
	Keys         auth.KeySet
	Audit        audit.Recorder
	Catalog      *policy.Catalog
	Resolver     *policy.Resolver
	Publisher    *policy.Publisher
	Usage        *usage.Service
	Offers       *offer.Service
	Payments     *payment.Service
	Verifier     payment.PaymentVerifier // nil unless development payments are enabled
	Entitlements *entitlement.Service
	Abuse        *abuse.Service
	// Ready lists readiness checks; any error makes /readyz return 503.
	Ready []func(context.Context) error
}

// Server is the control-plane API.
type Server struct {
	d        Deps
	mux      *http.ServeMux
	idem     *Idempotency
	authLim  *ipLimiter
	abuseLim *ipLimiter
	mReq     *observability.Counter
	mDur     *observability.Histogram
	mAuth    *observability.Counter
}

// New builds the server and its routes.
func New(d Deps) *Server {
	if d.Audit == nil {
		d.Audit = audit.Nop{}
	}
	if d.Metrics == nil {
		d.Metrics = observability.NewRegistry()
	}
	s := &Server{
		d:        d,
		mux:      http.NewServeMux(),
		idem:     NewIdempotency(d.Clock, 24*time.Hour, 100000),
		authLim:  newIPLimiter(d.Clock, d.Cfg.AuthRatePerMinute, max(20, d.Cfg.AuthRatePerMinute/3), 10000),
		abuseLim: newIPLimiter(d.Clock, d.Cfg.AbuseReportsPerMinute, max(5, d.Cfg.AbuseReportsPerMinute/6), 10000),
		mReq:     d.Metrics.Counter("cp_http_requests_total", "Control-plane requests.", "route", "status_class"),
		mDur:     d.Metrics.Histogram("cp_http_request_duration_seconds", "Control-plane request latency.", nil, "route"),
		mAuth:    d.Metrics.Counter("cp_auth_failures_total", "Authentication failures by reason.", "reason"),
	}
	s.routes()
	return s
}

// AuthFailure is the hook wired into identity.Config.OnFailure.
func (s *Server) AuthFailure(reason string) { s.mAuth.Inc(reason) }

// Handler returns the root handler with all middleware applied.
func (s *Server) Handler() http.Handler { return s.wrap(s.mux) }

func (s *Server) routes() {
	m := s.mux
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, map[string]string{"status": "ok"}) })
	m.HandleFunc("GET /readyz", s.readyz)
	m.HandleFunc("GET /v1/keys", s.handleKeys)
	m.HandleFunc("POST /v1/auth/challenges", s.handleChallenge)
	m.HandleFunc("POST /v1/auth/sessions", s.handleSession)
	m.HandleFunc("POST /v1/endpoints", s.principal(s.handleCreateEndpoint))
	m.HandleFunc("GET /v1/endpoints", s.principal(s.handleListEndpoints))
	m.HandleFunc("GET /v1/endpoints/{endpoint_id}", s.principal(s.handleGetEndpoint))
	m.HandleFunc("DELETE /v1/endpoints/{endpoint_id}", s.principal(s.handleDeleteEndpoint))
	m.HandleFunc("POST /v1/endpoints/{endpoint_id}/tunnel-credentials", s.principal(s.handleTunnelCredentials))
	s.policyRoutes()
	s.usageRoutes()
	s.paymentRoutes()
	s.abuseRoutes()
}

// ---- request plumbing ------------------------------------------------------

type reqInfo struct {
	id        string
	principal string
}

type ctxKey int

const infoKey ctxKey = 1

func info(r *http.Request) *reqInfo { v, _ := r.Context().Value(infoKey).(*reqInfo); return v }

func requestID(r *http.Request) string {
	if i := info(r); i != nil {
		return i.id
	}
	return ""
}

type statusWriter struct {
	http.ResponseWriter
	status int
	n      int64
}

func (w *statusWriter) WriteHeader(c int) {
	if w.status == 0 {
		w.status = c
	}
	w.ResponseWriter.WriteHeader(c)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}
	n, err := w.ResponseWriter.Write(b)
	w.n += int64(n)
	return n, err
}

func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *Server) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		start := s.d.Clock.Now()
		ri := &reqInfo{id: s.d.IDs.New("req")}
		r = r.WithContext(context.WithValue(r.Context(), infoKey, ri))
		w := &statusWriter{ResponseWriter: rw}
		w.Header().Set("X-Request-Id", ri.id)
		defer func() {
			if rec := recover(); rec != nil {
				s.d.Log.Error("http.panic", observability.FieldEvent, "http.panic", observability.FieldRequestID, ri.id, "panic", fmt.Sprint(rec))
				if w.status == 0 {
					apperr.Write(w, apperr.ErrInternal, ri.id)
				}
			}
			route := r.Pattern
			if route == "" {
				route = "unmatched"
			}
			dur := s.d.Clock.Now().Sub(start)
			class := fmt.Sprintf("%dxx", w.status/100)
			s.mReq.Inc(route, class)
			s.mDur.Observe(dur.Seconds(), route)
			s.d.Log.Info("http.request", observability.FieldEvent, "http.request",
				observability.FieldRequestID, ri.id, observability.FieldTraceID, observability.FromExternal(r.Header.Get("Traceparent")).TraceID, "method", r.Method, "route", route, "status", w.status,
				observability.FieldPrincipal, ri.principal, observability.FieldDurationMS, dur.Milliseconds())
		}()
		limit := int64(maxBodyBytes)
		if r.URL.Path == "/v1/usage/batches" {
			limit = maxBatchBody
		}
		r.Body = http.MaxBytesReader(w, r.Body, limit)
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		apperr.Write(w, apperr.ErrInternal.Wrap(err), "")
		return
	}
	writeRaw(w, status, b)
}

func writeRaw(w http.ResponseWriter, status int, b []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

// readBody reads the (size-limited) body once.
func readBody(r *http.Request) ([]byte, error) {
	b, err := io.ReadAll(r.Body)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return nil, apperr.New(http.StatusRequestEntityTooLarge, "request_too_large", "The request body is too large.")
		}
		return nil, apperr.ErrInvalidRequest.Wrap(err)
	}
	return b, nil
}

// decode strictly parses JSON (unknown fields and trailing data rejected).
func decode(b []byte, dst any) error {
	if len(bytes.TrimSpace(b)) == 0 {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return apperr.ErrInvalidRequest.WithDetails(map[string]any{"reason": "malformed_json"}).Wrap(err)
	}
	if dec.More() {
		return apperr.ErrInvalidRequest.WithDetails(map[string]any{"reason": "trailing_data"})
	}
	return nil
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	e := apperr.As(err)
	if e.Status >= 500 {
		s.d.Log.Error("http.error", observability.FieldEvent, "http.error", observability.FieldRequestID, requestID(r), observability.FieldErrorCode, e.Code, "cause", err.Error())
	}
	apperr.Write(w, err, requestID(r))
}

// principal authenticates the bearer session token.
func (s *Server) principal(h func(http.ResponseWriter, *http.Request, identity.Principal)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok, ok := bearer(r)
		if !ok {
			s.mAuth.Inc("missing_bearer")
			w.Header().Set("WWW-Authenticate", `Bearer realm="127ohoh1"`)
			s.fail(w, r, apperr.ErrUnauthorized)
			return
		}
		p, err := s.d.Identity.Authenticate(r.Context(), tok)
		if err != nil {
			s.mAuth.Inc("bad_session")
			w.Header().Set("WWW-Authenticate", `Bearer realm="127ohoh1"`)
			s.fail(w, r, err)
			return
		}
		if i := info(r); i != nil {
			i.principal = p.ID
		}
		h(w, r, p)
	}
}

func bearer(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	const pfx = "Bearer "
	if len(h) <= len(pfx) || !strings.EqualFold(h[:len(pfx)], pfx) {
		return "", false
	}
	return strings.TrimSpace(h[len(pfx):]), true
}

// serviceAuth checks a static service credential in constant time.
func serviceAuth(r *http.Request, want string) bool {
	tok, ok := bearer(r)
	if !ok || want == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(tok), []byte(want)) == 1
}

func (s *Server) readyz(w http.ResponseWriter, r *http.Request) {
	for _, c := range s.d.Ready {
		if err := c(r.Context()); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "not_ready"})
			return
		}
	}
	writeJSON(w, 200, map[string]string{"status": "ready"})
}

// ---- auth ------------------------------------------------------------------

func (s *Server) handleKeys(w http.ResponseWriter, _ *http.Request) {
	type key struct {
		KID       string `json:"kid"`
		PublicKey string `json:"public_key"`
	}
	var ks []key
	for kid, pub := range s.d.Keys {
		ks = append(ks, key{kid, auth.EncodeKey(pub)})
	}
	writeJSON(w, 200, map[string]any{"algorithm": "Ed25519", "keys": ks})
}

var b64 = base64.RawURLEncoding

func (s *Server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	if !s.authLim.allow(r) {
		s.mAuth.Inc("rate_limited")
		w.Header().Set("Retry-After", "5")
		s.fail(w, r, apperr.ErrRateLimited)
		return
	}
	body, err := readBody(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var in struct {
		PublicKey string `json:"public_key"`
	}
	if err := decode(body, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	c, err := s.d.Identity.IssueChallenge(r.Context(), in.PublicKey)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"challenge_id": c.ID, "nonce": b64.EncodeToString(c.Nonce), "audience": c.Audience,
		"protocol_version": auth.Version, "issued_at": c.IssuedAt.UTC().Format(time.RFC3339),
		"expires_at": c.ExpiresAt.UTC().Format(time.RFC3339),
	})
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	if !s.authLim.allow(r) {
		s.mAuth.Inc("rate_limited")
		w.Header().Set("Retry-After", "5")
		s.fail(w, r, apperr.ErrRateLimited)
		return
	}
	body, err := readBody(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var in struct {
		ChallengeID string `json:"challenge_id"`
		Nonce       string `json:"nonce"`
		Signature   string `json:"signature"`
	}
	if err := decode(body, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	nonce, err1 := b64.Strict().DecodeString(in.Nonce)
	sig, err2 := b64.Strict().DecodeString(in.Signature)
	if err1 != nil || err2 != nil || in.ChallengeID == "" {
		s.fail(w, r, apperr.ErrInvalidRequest)
		return
	}
	sess, err := s.d.Identity.CreateSession(r.Context(), in.ChallengeID, nonce, sig)
	if err != nil {
		s.d.Audit.Record(r.Context(), audit.Event{ID: s.d.IDs.New("aud"), Actor: "anonymous", Action: "session.create", Target: in.ChallengeID, Result: "denied", RequestID: requestID(r), At: s.d.Clock.Now()})
		s.fail(w, r, err)
		return
	}
	if sess.Created {
		s.d.Audit.Record(r.Context(), audit.Event{ID: s.d.IDs.New("aud"), Actor: sess.PrincipalID, Action: "principal.create", Target: sess.PrincipalID, Result: "ok", RequestID: requestID(r), At: s.d.Clock.Now()})
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"session_token": sess.Token, "expires_at": sess.ExpiresAt.UTC().Format(time.RFC3339),
		"principal_id": sess.PrincipalID, "fingerprint": sess.Fingerprint,
	})
}

// ---- endpoints -------------------------------------------------------------

// EndpointView is the JSON representation of an endpoint.
type EndpointView struct {
	ID           string `json:"id"`
	Hostname     string `json:"hostname"`
	URL          string `json:"url"`
	Kind         string `json:"kind"`
	State        string `json:"state"`
	Plan         string `json:"plan"`
	CreatedAt    string `json:"created_at"`
	LastActiveAt string `json:"last_active_at"`
}

func (s *Server) publicURL(host string) string {
	u := "https://" + host + "." + s.d.Cfg.BaseDomain
	if p := s.d.Cfg.PublicPort; p != 0 && p != 443 {
		u += fmt.Sprintf(":%d", p)
	}
	return u
}

// view renders an endpoint. Random endpoints are on the free plan; a reserved
// endpoint reports the plan of its active entitlement ("none" once lapsed).
func (s *Server) view(r *http.Request, e endpoint.Endpoint) EndpointView {
	plan := "free"
	if e.Kind == endpoint.KindReserved {
		plan = "none"
		if s.d.Entitlements != nil {
			if id, ok, _ := s.d.Entitlements.ActivePlan(r.Context(), e.PrincipalID, e.Hostname, s.d.Clock.Now()); ok {
				plan = id
			}
		}
	}
	return EndpointView{
		ID: e.ID, Hostname: e.Hostname, URL: s.publicURL(e.Hostname), Kind: string(e.Kind), State: string(e.State), Plan: plan,
		CreatedAt: e.CreatedAt.UTC().Format(time.RFC3339), LastActiveAt: e.LastActiveAt.UTC().Format(time.RFC3339),
	}
}

// idempotent wraps a mutating operation when an Idempotency-Key is supplied.
func (s *Server) idempotent(w http.ResponseWriter, r *http.Request, p identity.Principal, op string, body []byte, fn func() (int, any, error)) {
	run := func() (int, []byte, error) {
		status, v, err := fn()
		if err != nil {
			return 0, nil, err
		}
		b, merr := json.Marshal(v)
		if merr != nil {
			return 0, nil, apperr.ErrInternal.Wrap(merr)
		}
		return status, b, nil
	}
	key := r.Header.Get("Idempotency-Key")
	if key == "" {
		status, b, err := run()
		if err != nil {
			s.fail(w, r, err)
			return
		}
		writeRaw(w, status, b)
		return
	}
	if err := ValidKey(key); err != nil {
		s.fail(w, r, apperr.ErrInvalidRequest.WithDetails(map[string]any{"header": "Idempotency-Key", "reason": err.Error()}))
		return
	}
	res, err := s.idem.Do(p.ID, op, key, Digest([]byte(op), body), func(st int) bool { return st >= 200 && st < 300 }, run)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if res.Replayed {
		w.Header().Set("Idempotent-Replayed", "true")
	}
	writeRaw(w, res.Status, res.Body)
}

func (s *Server) handleCreateEndpoint(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	body, err := readBody(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var in struct {
		Kind string `json:"kind"`
	}
	if err := decode(body, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	if in.Kind != "" && in.Kind != string(endpoint.KindRandom) {
		s.fail(w, r, apperr.ErrInvalidRequest.WithDetails(map[string]any{"field": "kind", "reason": "use POST /v1/endpoints/reserve for reserved names"}))
		return
	}
	s.idempotent(w, r, p, "endpoint.create", body, func() (int, any, error) {
		e, err := s.d.Endpoints.CreateRandom(r.Context(), p.ID)
		if err != nil {
			return 0, nil, err
		}
		s.d.Audit.Record(r.Context(), audit.Event{ID: s.d.IDs.New("aud"), Actor: p.ID, Action: "endpoint.create", Target: e.ID, Result: "ok", RequestID: requestID(r), At: s.d.Clock.Now()})
		return http.StatusCreated, s.view(r, e), nil
	})
}

func (s *Server) handleListEndpoints(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	es, err := s.d.Endpoints.List(r.Context(), p.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := make([]EndpointView, 0, len(es))
	for _, e := range es {
		out = append(out, s.view(r, e))
	}
	writeJSON(w, 200, map[string]any{"endpoints": out})
}

func (s *Server) handleGetEndpoint(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	e, err := s.d.Endpoints.Get(r.Context(), p.ID, r.PathValue("endpoint_id"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, s.view(r, e))
}

func (s *Server) handleDeleteEndpoint(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	e, err := s.d.Endpoints.Release(r.Context(), p.ID, r.PathValue("endpoint_id"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.d.Audit.Record(r.Context(), audit.Event{ID: s.d.IDs.New("aud"), Actor: p.ID, Action: "endpoint.release", Target: e.ID, Result: "ok", RequestID: requestID(r), At: s.d.Clock.Now()})
	writeJSON(w, 200, s.view(r, e))
}

func (s *Server) handleTunnelCredentials(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	e, err := s.d.Endpoints.Get(r.Context(), p.ID, r.PathValue("endpoint_id"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	switch e.State {
	case endpoint.StateActive:
	case endpoint.StateReleased:
		s.fail(w, r, apperr.ErrGone.WithDetails(map[string]any{"state": string(e.State)}))
		return
	default:
		s.fail(w, r, apperr.ErrConflict.WithDetails(map[string]any{"reason": "endpoint_not_active", "state": string(e.State)}))
		return
	}
	now := s.d.Clock.Now()
	exp := now.Add(s.d.Cfg.TunnelCredentialTTL.D())
	jti := s.d.IDs.New("tok")
	tok, err := s.d.Signer.Sign(auth.Claims{Type: auth.TypeTunnel, Subject: p.ID, Audience: s.d.Cfg.EdgeAudience,
		Endpoint: e.ID, Hostname: e.Hostname, PublicKey: auth.EncodeKey(p.PublicKey), ID: jti, IssuedAt: now.Unix(), ExpiresAt: exp.Unix()})
	if err != nil {
		s.fail(w, r, apperr.ErrInternal.Wrap(err))
		return
	}
	s.d.Audit.Record(r.Context(), audit.Event{ID: s.d.IDs.New("aud"), Actor: p.ID, Action: "tunnel_credential.issue", Target: e.ID, Result: "ok", RequestID: requestID(r), At: now, Metadata: map[string]string{"jti": jti}})
	writeJSON(w, http.StatusCreated, map[string]any{
		"token": tok, "expires_at": exp.UTC().Format(time.RFC3339), "endpoint_id": e.ID, "hostname": e.Hostname,
		"url":  s.publicURL(e.Hostname),
		"edge": map[string]any{"addr": s.d.Cfg.EdgeTunnelAddr, "audience": s.d.Cfg.EdgeAudience},
	})
}

type ctxEnabled struct{}

func withEnabled(ctx context.Context, v *bool) context.Context {
	return context.WithValue(ctx, ctxEnabled{}, v)
}

func enabledFrom(ctx context.Context) *bool {
	v, _ := ctx.Value(ctxEnabled{}).(*bool)
	return v
}
