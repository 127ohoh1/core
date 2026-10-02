// Package abuse is the public abuse-report *intake contract* plus a manual
// enforcement hook (admin listing + the existing suspension endpoints).
//
// PUBLIC REFERENCE SCOPE: intake only. Detection heuristics, triage tooling,
// case management, appeals and evidence handling are private-product concerns.
// Intake is treated as hostile input: bounded, sanitised, rate limited, and it
// never fetches or renders reported URLs.
package abuse

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/127ohoh1/core/internal/apperr"
	"github.com/127ohoh1/core/internal/clock"
	"github.com/127ohoh1/core/internal/ids"
)

// Categories a reporter can choose.
var Categories = map[string]bool{"malware": true, "phishing": true, "illegal_content": true, "spam": true, "harassment": true, "copyright": true, "other": true}

// Size limits.
const (
	MaxDescription = 2000
	MaxContact     = 200
	MaxURL         = 500
	MaxHostname    = 253
	// Retention is the default time a report is kept (configurable policy in a product).
	Retention = 180 * 24 * time.Hour
)

// Status of a report (the full workflow is a product concern).
type Status string

const StatusReported Status = "REPORTED"

// Report is one stored intake record.
type Report struct {
	ID          string
	Hostname    string // label of the reported tunnel host, lowercased
	EndpointID  string // resolved at intake if the hostname is live, else ""
	Category    string
	Description string
	URL         string // informational only; never fetched
	Contact     string // optional, voluntarily supplied
	Status      Status
	CreatedAt   time.Time
	ExpiresAt   time.Time
}

// Input is an untrusted submission.
type Input struct {
	Hostname    string
	Category    string
	Description string
	URL         string
	Contact     string
}

// Resolver maps a hostname label to a live endpoint id.
type Resolver func(ctx context.Context, hostname string) (endpointID string, ok bool)

// Service accepts reports.
type Service struct {
	clk     clock.Clock
	ids     *ids.Generator
	resolve Resolver
	max     int

	mu      sync.Mutex
	reports []Report
}

// NewService builds a service holding at most max reports (oldest dropped).
func NewService(clk clock.Clock, g *ids.Generator, r Resolver, max int) *Service {
	if max <= 0 {
		max = 10000
	}
	return &Service{clk: clk, ids: g, resolve: r, max: max}
}

// clean strips control characters (log/terminal injection) and trims.
func clean(s string) string {
	return strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && r != '\n' {
			return -1
		}
		return r
	}, s))
}

// ErrInvalid is returned for malformed submissions (mapped to 400).
var ErrInvalid = errors.New("abuse: invalid report")

// Submit validates and stores a report.
func (s *Service) Submit(ctx context.Context, in Input) (Report, error) {
	host := strings.ToLower(clean(in.Hostname))
	// Accept a bare label or a full host; keep only the leftmost label if a domain was pasted.
	if i := strings.IndexByte(host, '.'); i > 0 {
		host = host[:i]
	}
	desc, url, contact := clean(in.Description), clean(in.URL), clean(in.Contact)
	switch {
	case host == "" || len(host) > MaxHostname || len(host) > 63:
		return Report{}, apperr.ErrInvalidRequest.WithDetails(map[string]any{"field": "hostname"})
	case !Categories[in.Category]:
		return Report{}, apperr.ErrInvalidRequest.WithDetails(map[string]any{"field": "category"})
	case len(desc) > MaxDescription:
		return Report{}, apperr.ErrInvalidRequest.WithDetails(map[string]any{"field": "description", "max": MaxDescription})
	case len(url) > MaxURL:
		return Report{}, apperr.ErrInvalidRequest.WithDetails(map[string]any{"field": "url", "max": MaxURL})
	case len(contact) > MaxContact:
		return Report{}, apperr.ErrInvalidRequest.WithDetails(map[string]any{"field": "contact", "max": MaxContact})
	}
	now := s.clk.Now()
	r := Report{ID: s.ids.New("abr"), Hostname: host, Category: in.Category, Description: desc, URL: url, Contact: contact,
		Status: StatusReported, CreatedAt: now, ExpiresAt: now.Add(Retention)}
	if s.resolve != nil {
		if id, ok := s.resolve(ctx, host); ok {
			r.EndpointID = id
		}
	}
	s.mu.Lock()
	if len(s.reports) >= s.max {
		s.reports = append(s.reports[:0], s.reports[1:]...)
	}
	s.reports = append(s.reports, r)
	s.mu.Unlock()
	return r, nil
}

// List returns stored reports, newest first, optionally filtered by hostname.
func (s *Service) List(hostname string) []Report {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Report
	for i := len(s.reports) - 1; i >= 0; i-- {
		if r := s.reports[i]; hostname == "" || r.Hostname == hostname {
			out = append(out, r)
		}
	}
	return out
}

// PurgeExpired deletes reports past their retention (returns how many).
func (s *Service) PurgeExpired() int {
	now := s.clk.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.reports[:0]
	n := 0
	for _, r := range s.reports {
		if now.Before(r.ExpiresAt) {
			kept = append(kept, r)
		} else {
			n++
		}
	}
	s.reports = kept
	return n
}
