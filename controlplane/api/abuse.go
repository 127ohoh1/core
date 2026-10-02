package api

import (
	"net/http"
	"time"

	"github.com/127ohoh1/core/controlplane/abuse"
	"github.com/127ohoh1/core/controlplane/audit"
	"github.com/127ohoh1/core/internal/apperr"
)

func (s *Server) abuseRoutes() {
	s.mux.HandleFunc("POST /v1/abuse-reports", s.handleAbuseReport)
	s.mux.HandleFunc("GET /v1/admin/abuse-reports", s.handleAbuseList)
}

// handleAbuseReport is the public intake. It needs no account (a victim must
// be able to report), so it is IP rate limited and strictly bounded.
func (s *Server) handleAbuseReport(w http.ResponseWriter, r *http.Request) {
	if !s.abuseLim.allow(r) {
		w.Header().Set("Retry-After", "60")
		s.fail(w, r, apperr.ErrRateLimited)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	body, err := readBody(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var in struct {
		Hostname    string `json:"hostname"`
		Category    string `json:"category"`
		Description string `json:"description"`
		URL         string `json:"url"`
		Contact     string `json:"contact"`
	}
	if err := decode(body, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	rep, err := s.d.Abuse.Submit(r.Context(), abuse.Input{Hostname: in.Hostname, Category: in.Category, Description: in.Description, URL: in.URL, Contact: in.Contact})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.d.Audit.Record(r.Context(), audit.Event{ID: s.d.IDs.New("aud"), Actor: "reporter", Action: "abuse.report", Target: rep.ID, Result: "ok", RequestID: requestID(r), At: s.d.Clock.Now(),
		Metadata: map[string]string{"category": rep.Category}})
	// 202: accepted for review. Nothing is enforced automatically.
	writeJSON(w, http.StatusAccepted, map[string]any{"report_id": rep.ID, "status": rep.Status,
		"message": "Thank you. Reports are reviewed by people; no automatic action is taken."})
}

// handleAbuseList lets an operator review reports; it links to the manual
// suspension hooks through endpoint_id.
func (s *Server) handleAbuseList(w http.ResponseWriter, r *http.Request) {
	if s.d.Cfg.AdminToken == "" {
		s.fail(w, r, apperr.ErrNotFound)
		return
	}
	if !serviceAuth(r, s.d.Cfg.AdminToken) {
		s.mAuth.Inc("bad_admin_token")
		s.fail(w, r, apperr.ErrUnauthorized)
		return
	}
	type view struct {
		ID          string `json:"id"`
		Hostname    string `json:"hostname"`
		EndpointID  string `json:"endpoint_id,omitempty"`
		Category    string `json:"category"`
		Description string `json:"description"`
		URL         string `json:"url,omitempty"`
		Contact     string `json:"contact,omitempty"`
		Status      string `json:"status"`
		CreatedAt   string `json:"created_at"`
		ExpiresAt   string `json:"expires_at"`
	}
	var out []view
	for _, rep := range s.d.Abuse.List(r.URL.Query().Get("hostname")) {
		out = append(out, view{ID: rep.ID, Hostname: rep.Hostname, EndpointID: rep.EndpointID, Category: rep.Category, Description: rep.Description,
			URL: rep.URL, Contact: rep.Contact, Status: string(rep.Status), CreatedAt: rep.CreatedAt.UTC().Format(time.RFC3339), ExpiresAt: rep.ExpiresAt.UTC().Format(time.RFC3339)})
	}
	s.d.Audit.Record(r.Context(), audit.Event{ID: s.d.IDs.New("aud"), Actor: "admin", Action: "abuse.list", Result: "ok", RequestID: requestID(r), At: s.d.Clock.Now()})
	writeJSON(w, 200, map[string]any{"reports": out})
}
