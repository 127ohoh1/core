package api

import (
	"net/http"
	"time"

	"github.com/127ohoh1/core/controlplane/usage"
	"github.com/127ohoh1/core/internal/apperr"
)

func (s *Server) usageRoutes() {
	s.mux.HandleFunc("POST /v1/usage/batches", s.handleUsageBatch)
	s.mux.HandleFunc("GET /v1/endpoints/{endpoint_id}/usage", s.handleUsage)
	s.mux.HandleFunc("POST /v1/presence", s.handlePresence)
}

// maxBatchBody bounds a usage batch (1000 items of ~150 bytes, with headroom).
const maxBatchBody = 512 << 10

func (s *Server) handleUsageBatch(w http.ResponseWriter, r *http.Request) {
	if !serviceAuth(r, s.d.Cfg.EdgeServiceToken) {
		s.mAuth.Inc("bad_service_token")
		s.fail(w, r, apperr.ErrUnauthorized)
		return
	}
	body, err := readBody(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var b usage.Batch
	if err := decode(body, &b); err != nil {
		s.fail(w, r, err)
		return
	}
	res, err := s.d.Usage.Apply(r.Context(), b)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if res.Duplicate {
		w.Header().Set("Idempotent-Replayed", "true")
	}
	writeJSON(w, 200, res)
}

func (s *Server) handleUsage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("endpoint_id")
	if !s.edgeOrOwner(w, r, id) {
		return
	}
	p, err := s.d.Publisher.Current(r.Context(), id)
	if err != nil {
		s.fail(w, r, apperr.ErrNotFound)
		return
	}
	remaining := p.Limits.MonthlyTransferBytes - p.Usage.UsedBytes
	if remaining < 0 {
		remaining = 0
	}
	writeJSON(w, 200, map[string]any{
		"endpoint_id": id, "period_start": p.Usage.PeriodStart, "period_end": p.Usage.PeriodEnd,
		"used_bytes": p.Usage.UsedBytes, "limit_bytes": p.Limits.MonthlyTransferBytes, "remaining_bytes": remaining,
		"policy_version": p.PolicyVersion,
	})
}

// handlePresence records which endpoints have an authenticated tunnel right
// now. last_active_at drives the 24h free-name inactivity clock.
func (s *Server) handlePresence(w http.ResponseWriter, r *http.Request) {
	if !serviceAuth(r, s.d.Cfg.EdgeServiceToken) {
		s.mAuth.Inc("bad_service_token")
		s.fail(w, r, apperr.ErrUnauthorized)
		return
	}
	body, err := readBody(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var in struct {
		EdgeID  string `json:"edge_id"`
		Updates []struct {
			EndpointID string    `json:"endpoint_id"`
			Connected  bool      `json:"connected"`
			At         time.Time `json:"at"`
		} `json:"updates"`
	}
	if err := decode(body, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	if in.EdgeID == "" || len(in.Updates) == 0 || len(in.Updates) > 1000 {
		s.fail(w, r, apperr.ErrInvalidRequest.WithDetails(map[string]any{"reason": "edge_id and 1..1000 updates required"}))
		return
	}
	now := s.d.Clock.Now()
	applied := 0
	for _, u := range in.Updates {
		at := u.At
		if at.IsZero() || at.After(now) {
			at = now // never trust a timestamp from the future
		}
		if err := s.d.Endpoints.SetPresence(r.Context(), u.EndpointID, u.Connected, at); err == nil {
			applied++
		}
	}
	writeJSON(w, 200, map[string]int{"applied": applied})
}
