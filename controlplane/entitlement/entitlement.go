// Package entitlement converts settled economic events into capabilities: a
// time-bounded right for one principal to use one hostname under one plan's
// limits. It never touches money; payment.Service reports a settlement and
// this service decides what that buys.
//
// PUBLIC REFERENCE SCOPE: demo grant and expiry only. Renewal, upgrade,
// downgrade, grace periods, revocation policy and repair jobs are product
// concerns implemented in the private repository.
package entitlement

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/127ohoh1/core/controlplane/offer"
	"github.com/127ohoh1/core/controlplane/payment"
	"github.com/127ohoh1/core/internal/apperr"
	"github.com/127ohoh1/core/internal/clock"
	"github.com/127ohoh1/core/internal/ids"
)

// State of an entitlement.
type State string

const (
	StateActive  State = "active"
	StateExpired State = "expired"
	StateRevoked State = "revoked"
)

// Entitlement is proof that consideration was received for one name.
type Entitlement struct {
	ID           string
	PrincipalID  string
	ScopeName    string
	PlanID       string
	Terms        offer.Terms // snapshot from the offer, never re-read from the catalog
	SettlementID string      // payment id; unique: one entitlement per settlement
	ValidFrom    time.Time
	ValidUntil   time.Time
	State        State
	CreatedAt    time.Time
}

// ActiveAt reports whether the entitlement grants capabilities at t.
func (e Entitlement) ActiveAt(t time.Time) bool {
	return e.State == StateActive && !t.Before(e.ValidFrom) && t.Before(e.ValidUntil)
}

// EntitlementService is the boundary named in the specification.
type EntitlementService interface {
	GrantFromSettlement(ctx context.Context, g payment.Grant) (Entitlement, error)
	ListActive(ctx context.Context, principalID string, at time.Time) ([]Entitlement, error)
}

// Store errors.
var ErrNotFound = errors.New("entitlement: not found")

// Service is the development EntitlementService.
type Service struct {
	clk clock.Clock
	ids *ids.Generator

	mu     sync.Mutex
	byID   map[string]Entitlement
	bySett map[string]string // settlement id -> entitlement id (uniqueness)
	// OnChange is called (outside locks) after a grant, expiry or revoke for a name.
	OnChange func(ctx context.Context, name string)
}

// NewService builds the service.
func NewService(clk clock.Clock, g *ids.Generator) *Service {
	return &Service{clk: clk, ids: g, byID: map[string]Entitlement{}, bySett: map[string]string{}}
}

// GrantFromSettlement grants at most one entitlement per settlement. Calling
// it again for the same settlement returns the existing entitlement, which is
// what makes duplicate settlement delivery harmless.
func (s *Service) GrantFromSettlement(ctx context.Context, g payment.Grant) (Entitlement, error) {
	if g.SettlementID == "" || g.ScopeName == "" || g.PrincipalID == "" {
		return Entitlement{}, apperr.ErrInvalidRequest
	}
	now := s.clk.Now()
	s.mu.Lock()
	if id, ok := s.bySett[g.SettlementID]; ok {
		e := s.byID[id]
		s.mu.Unlock()
		return e, nil
	}
	// One live entitlement per name: a second, different holder is an
	// exception that needs a human (the payment stays SETTLED; see docs).
	for _, e := range s.byID {
		if e.ScopeName == g.ScopeName && e.ActiveAt(now) {
			s.mu.Unlock()
			return Entitlement{}, apperr.ErrConflict.WithDetails(map[string]any{"reason": "name_already_entitled"})
		}
	}
	from := g.SettledAt
	if from.IsZero() {
		from = now
	}
	e := Entitlement{ID: s.ids.New("ent"), PrincipalID: g.PrincipalID, ScopeName: g.ScopeName, PlanID: g.Terms.PlanID, Terms: g.Terms,
		SettlementID: g.SettlementID, ValidFrom: from, ValidUntil: from.AddDate(0, 1, 0), State: StateActive, CreatedAt: now}
	s.byID[e.ID], s.bySett[g.SettlementID] = e, e.ID
	cb := s.OnChange
	s.mu.Unlock()
	if cb != nil {
		cb(ctx, e.ScopeName)
	}
	return e, nil
}

// ListActive lists the principal's entitlements active at `at`.
func (s *Service) ListActive(_ context.Context, principalID string, at time.Time) ([]Entitlement, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Entitlement
	for _, e := range s.byID {
		if e.PrincipalID == principalID && e.ActiveAt(at) {
			out = append(out, e)
		}
	}
	return out, nil
}

// ActivePlan implements policy.EntitlementLookup: the plan id of the
// principal's active entitlement for name, if any.
func (s *Service) ActivePlan(_ context.Context, principalID, name string, at time.Time) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.byID {
		if e.PrincipalID == principalID && e.ScopeName == name && e.ActiveAt(at) {
			return e.PlanID, true, nil
		}
	}
	return "", false, nil
}

// HeldByOther reports whether someone other than principalID holds an active
// entitlement for name (used to keep a paid name from being sold twice).
func (s *Service) HeldByOther(principalID, name string, at time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.byID {
		if e.ScopeName == name && e.PrincipalID != principalID && e.ActiveAt(at) {
			return true
		}
	}
	return false
}

// Active returns the entitlement of principalID for name at `at`.
func (s *Service) Active(principalID, name string, at time.Time) (Entitlement, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.byID {
		if e.PrincipalID == principalID && e.ScopeName == name && e.ActiveAt(at) {
			return e, true
		}
	}
	return Entitlement{}, false
}

// Sweep marks entitlements whose term ended as expired and returns their names
// so dependent state (policy, endpoint lifecycle) can be updated. Idempotent.
func (s *Service) Sweep(ctx context.Context, at time.Time) []string {
	s.mu.Lock()
	var names []string
	for id, e := range s.byID {
		if e.State == StateActive && !at.Before(e.ValidUntil) {
			e.State = StateExpired
			s.byID[id] = e
			names = append(names, e.ScopeName)
		}
	}
	cb := s.OnChange
	s.mu.Unlock()
	if cb != nil {
		for _, n := range names {
			cb(ctx, n)
		}
	}
	return names
}

// Revoke ends an entitlement immediately (administrative hook). Idempotent.
func (s *Service) Revoke(ctx context.Context, id string) error {
	s.mu.Lock()
	e, ok := s.byID[id]
	if !ok {
		s.mu.Unlock()
		return apperr.ErrNotFound
	}
	changed := e.State == StateActive
	if changed {
		e.State = StateRevoked
		s.byID[id] = e
	}
	cb := s.OnChange
	s.mu.Unlock()
	if changed && cb != nil {
		cb(ctx, e.ScopeName)
	}
	return nil
}

// Granter adapts the service to payment.EntitlementGranter.
type Granter struct{ S *Service }

func (g Granter) GrantFromSettlement(ctx context.Context, gr payment.Grant) error {
	_, err := g.S.GrantFromSettlement(ctx, gr)
	return err
}
