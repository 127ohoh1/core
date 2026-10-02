package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/127ohoh1/core/controlplane/audit"
	"github.com/127ohoh1/core/controlplane/identity"
	"github.com/127ohoh1/core/internal/apperr"
	"github.com/127ohoh1/core/internal/observability"
	pp "github.com/127ohoh1/core/protocol/policy"
)

func (s *Server) policyRoutes() {
	m := s.mux
	m.HandleFunc("GET /v1/plans", s.handlePlans)
	m.HandleFunc("GET /v1/endpoints/{endpoint_id}/policy", s.handlePolicy)
	m.HandleFunc("GET /v1/policies/changes", s.handlePolicyChanges)
	m.HandleFunc("GET /v1/hostnames/{label}", s.handleHostnameStatus)

	// Administrative suspension / revocation hooks. Disabled (404) unless an
	// admin token is configured; every call is audited.
	m.HandleFunc("POST /v1/admin/endpoints/{endpoint_id}/suspend", s.admin("endpoint.suspend", s.adminEndpoint(true)))
	m.HandleFunc("POST /v1/admin/endpoints/{endpoint_id}/unsuspend", s.admin("endpoint.unsuspend", s.adminEndpoint(false)))
	m.HandleFunc("POST /v1/admin/principals/{principal_id}/suspend", s.admin("principal.suspend", s.adminPrincipal(true)))
	m.HandleFunc("POST /v1/admin/principals/{principal_id}/unsuspend", s.admin("principal.unsuspend", s.adminPrincipal(false)))
	m.HandleFunc("POST /v1/admin/emergency", s.admin("emergency.set", s.adminEmergency))
}

func (s *Server) handlePlans(w http.ResponseWriter, _ *http.Request) {
	type view struct {
		ID                      string `json:"id"`
		Name                    string `json:"name"`
		Price                   any    `json:"price"`
		BandwidthBytesPerSecond int64  `json:"bandwidth_bytes_per_second"`
		BurstBytes              int64  `json:"burst_bytes"`
		MonthlyTransferBytes    int64  `json:"monthly_transfer_bytes"`
		Hostname                string `json:"hostname"`
		Version                 int    `json:"version"`
	}
	var out []view
	for _, p := range s.d.Catalog.List() {
		out = append(out, view{
			ID: p.ID, Name: p.Name, Version: p.Version, Hostname: p.HostnameKind,
			Price:                   map[string]string{"amount": p.PriceAmount, "asset": p.PriceAsset, "interval": p.Interval, "unit": p.Unit},
			BandwidthBytesPerSecond: p.BandwidthBytesPerSecond, BurstBytes: 2 * p.BandwidthBytesPerSecond, MonthlyTransferBytes: p.MonthlyTransferBytes,
		})
	}
	writeJSON(w, 200, map[string]any{"plans": out, "units": "decimal SI: 1 kB = 1,000 bytes; 1 MB = 1,000,000; 1 GB = 1,000,000,000"})
}

// edgeOrOwner authorises either the edge service credential or the owning
// principal. It reports which one matched.
func (s *Server) edgeOrOwner(w http.ResponseWriter, r *http.Request, endpointID string) (allowed bool) {
	if serviceAuth(r, s.d.Cfg.EdgeServiceToken) {
		return true
	}
	tok, ok := bearer(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Bearer realm="127ohoh1"`)
		s.fail(w, r, apperr.ErrUnauthorized)
		return false
	}
	p, err := s.d.Identity.Authenticate(r.Context(), tok)
	if err != nil {
		s.fail(w, r, err)
		return false
	}
	if i := info(r); i != nil {
		i.principal = p.ID
	}
	if _, err := s.d.Endpoints.Get(r.Context(), p.ID, endpointID); err != nil {
		s.fail(w, r, err)
		return false
	}
	return true
}

func (s *Server) handlePolicy(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("endpoint_id")
	if !s.edgeOrOwner(w, r, id) {
		return
	}
	p, err := s.d.Publisher.Current(r.Context(), id)
	if err != nil {
		s.fail(w, r, apperr.ErrNotFound)
		return
	}
	writeJSON(w, 200, p)
}

// handleHostnameStatus tells an edge what one tenant label is, so it can
// issue a certificate for an active reserved name before any tunnel connects
// (ADR 0011). The state is the endpoint's resolved policy state: exactly what
// the edge would enforce, suspension included.
func (s *Server) handleHostnameStatus(w http.ResponseWriter, r *http.Request) {
	if !serviceAuth(r, s.d.Cfg.EdgeServiceToken) {
		s.mAuth.Inc("bad_service_token")
		s.fail(w, r, apperr.ErrUnauthorized)
		return
	}
	e, err := s.d.Endpoints.ByHostname(r.Context(), r.PathValue("label"))
	if err != nil {
		s.fail(w, r, apperr.ErrNotFound)
		return
	}
	p, err := s.d.Publisher.Current(r.Context(), e.ID)
	if err != nil {
		s.fail(w, r, apperr.ErrNotFound)
		return
	}
	writeJSON(w, 200, pp.HostnameStatus{EndpointID: e.ID, Kind: string(e.Kind), State: p.State})
}

func (s *Server) handlePolicyChanges(w http.ResponseWriter, r *http.Request) {
	if !serviceAuth(r, s.d.Cfg.EdgeServiceToken) {
		s.mAuth.Inc("bad_service_token")
		s.fail(w, r, apperr.ErrUnauthorized)
		return
	}
	since, err := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
	if err != nil || since < 0 {
		s.fail(w, r, apperr.ErrInvalidRequest.WithDetails(map[string]any{"field": "since"}))
		return
	}
	wait := 20 * time.Second
	if v := r.URL.Query().Get("wait"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > 30 {
			s.fail(w, r, apperr.ErrInvalidRequest.WithDetails(map[string]any{"field": "wait", "reason": "0..30 seconds"}))
			return
		}
		wait = time.Duration(n) * time.Second
	}
	writeJSON(w, 200, s.d.Publisher.Changes(r.Context(), since, wait))
}

// ---- administrative hooks --------------------------------------------------

func (s *Server) admin(action string, h func(w http.ResponseWriter, r *http.Request, reason string) (target string, err error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.d.Cfg.AdminToken == "" {
			s.fail(w, r, apperr.ErrNotFound) // feature disabled: indistinguishable from a missing route
			return
		}
		if !serviceAuth(r, s.d.Cfg.AdminToken) {
			s.mAuth.Inc("bad_admin_token")
			s.d.Audit.Record(r.Context(), audit.Event{ID: s.d.IDs.New("aud"), Actor: "unknown", Action: action, Result: "denied", RequestID: requestID(r), At: s.d.Clock.Now()})
			s.fail(w, r, apperr.ErrUnauthorized)
			return
		}
		body, err := readBody(r)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		var in struct {
			Reason  string `json:"reason"`
			Enabled *bool  `json:"enabled"`
		}
		if err := decode(body, &in); err != nil {
			s.fail(w, r, err)
			return
		}
		if len(in.Reason) > 256 {
			s.fail(w, r, apperr.ErrInvalidRequest.WithDetails(map[string]any{"field": "reason"}))
			return
		}
		r = r.WithContext(withEnabled(r.Context(), in.Enabled))
		target, err := h(w, r, in.Reason)
		res := "ok"
		if err != nil {
			res = "error"
		}
		s.d.Audit.Record(r.Context(), audit.Event{ID: s.d.IDs.New("aud"), Actor: "admin", Action: action, Target: target, Result: res,
			RequestID: requestID(r), At: s.d.Clock.Now(), Metadata: map[string]string{"reason": in.Reason}})
		if err != nil {
			s.fail(w, r, err)
			return
		}
	}
}

func (s *Server) adminEndpoint(suspend bool) func(http.ResponseWriter, *http.Request, string) (string, error) {
	return func(w http.ResponseWriter, r *http.Request, _ string) (string, error) {
		id := r.PathValue("endpoint_id")
		var err error
		if suspend {
			_, err = s.d.Endpoints.Suspend(r.Context(), id)
		} else {
			_, err = s.d.Endpoints.Unsuspend(r.Context(), id)
		}
		if err != nil {
			return id, err
		}
		p, err := s.d.Publisher.Current(r.Context(), id)
		if err != nil {
			return id, err
		}
		writeJSON(w, 200, map[string]any{"endpoint_id": id, "policy_state": p.State, "policy_version": p.PolicyVersion})
		return id, nil
	}
}

func (s *Server) adminPrincipal(suspend bool) func(http.ResponseWriter, *http.Request, string) (string, error) {
	return func(w http.ResponseWriter, r *http.Request, _ string) (string, error) {
		id := r.PathValue("principal_id")
		var err error
		if suspend {
			err = s.d.Identity.Suspend(r.Context(), id)
		} else {
			err = s.d.Identity.Unsuspend(r.Context(), id)
		}
		if err != nil {
			return id, err
		}
		s.d.Publisher.RecomputePrincipal(r.Context(), s.d.Endpoints, id) // suspension must reach every edge quickly
		state := identity.PrincipalActive
		if suspend {
			state = identity.PrincipalSuspended
		}
		writeJSON(w, 200, map[string]any{"principal_id": id, "state": state})
		return id, nil
	}
}

func (s *Server) adminEmergency(w http.ResponseWriter, r *http.Request, _ string) (string, error) {
	en := enabledFrom(r.Context())
	if en == nil {
		return "emergency", apperr.ErrInvalidRequest.WithDetails(map[string]any{"field": "enabled"})
	}
	s.d.Resolver.SetEmergencyDeny(*en)
	s.d.Log.Warn("admin.emergency_override", observability.FieldEvent, "admin.emergency_override", "enabled", *en)
	// Republishing every endpoint is the publisher's job; the change feed carries it.
	s.d.Publisher.RecomputeAll(r.Context(), s.d.Endpoints)
	b, _ := json.Marshal(map[string]any{"emergency_deny": *en})
	writeRaw(w, 200, b)
	return "emergency", nil
}
