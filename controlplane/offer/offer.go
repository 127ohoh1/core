// Package offer owns purchase offers: an expiring, immutable snapshot of the
// terms under which a principal may buy one plan for one hostname.
package offer

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/127ohoh1/core/controlplane/endpoint"
	"github.com/127ohoh1/core/controlplane/policy"
	"github.com/127ohoh1/core/internal/apperr"
	"github.com/127ohoh1/core/internal/clock"
	"github.com/127ohoh1/core/internal/ids"
)

// State of an offer.
type State string

const (
	StateOpen      State = "open"
	StatePaid      State = "paid"
	StateExpired   State = "expired"
	StateCancelled State = "cancelled"
)

// Terms is the immutable snapshot of what is being sold. It is copied into
// the entitlement on purchase; changing the catalog later never alters it.
type Terms struct {
	PlanID                  string `json:"plan"`
	PlanVersion             int    `json:"plan_version"`
	Amount                  string `json:"amount"` // decimal string
	Asset                   string `json:"asset"`
	Interval                string `json:"interval"`
	Unit                    string `json:"unit"`
	BandwidthBytesPerSecond int64  `json:"bandwidth_bytes_per_second"`
	MonthlyTransferBytes    int64  `json:"monthly_transfer_bytes"`
}

// Offer is a priced, expiring proposal.
type Offer struct {
	ID          string
	PrincipalID string
	ScopeName   string // hostname label the offer is scoped to
	PlanID      string
	Terms       Terms
	State       State
	CreatedAt   time.Time
	ExpiresAt   time.Time
}

// Errors.
var ErrNotFound = errors.New("offer: not found")

// Store persists offers.
type Store interface {
	Put(ctx context.Context, o Offer) error
	Get(ctx context.Context, id string) (Offer, error)
	// FindOpen returns an unexpired open offer for (principal, name, plan).
	FindOpen(ctx context.Context, principalID, name, planID string, at time.Time) (Offer, bool)
	List(ctx context.Context) []Offer
}

// InMemory is the development store.
type InMemory struct {
	mu sync.Mutex
	m  map[string]Offer
}

// NewInMemory returns an empty store.
func NewInMemory() *InMemory { return &InMemory{m: map[string]Offer{}} }

func (s *InMemory) Put(_ context.Context, o Offer) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[o.ID] = o
	return nil
}

func (s *InMemory) Get(_ context.Context, id string) (Offer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.m[id]
	if !ok {
		return Offer{}, ErrNotFound
	}
	return o, nil
}

func (s *InMemory) FindOpen(_ context.Context, pr, name, plan string, at time.Time) (Offer, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var best Offer
	found := false
	for _, o := range s.m {
		if o.PrincipalID == pr && o.ScopeName == name && o.PlanID == plan && o.State == StateOpen && at.Before(o.ExpiresAt) {
			if !found || o.CreatedAt.After(best.CreatedAt) {
				best, found = o, true
			}
		}
	}
	return best, found
}

func (s *InMemory) List(_ context.Context) []Offer {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Offer, 0, len(s.m))
	for _, o := range s.m {
		out = append(out, o)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Service creates and manages offers.
type Service struct {
	store     Store
	catalog   *policy.Catalog
	endpoints *endpoint.Service
	clk       clock.Clock
	ids       *ids.Generator
	ttl       time.Duration
	mu        sync.Mutex
	// Available, if set, adds availability rules beyond endpoint uniqueness
	// (for example: another principal already holds an entitlement for name).
	Available func(ctx context.Context, principalID, name string) error
}

// NewService builds an offer service.
func NewService(store Store, cat *policy.Catalog, eps *endpoint.Service, clk clock.Clock, g *ids.Generator, ttl time.Duration) *Service {
	return &Service{store: store, catalog: cat, endpoints: eps, clk: clk, ids: g, ttl: ttl}
}

// PaidPlan validates that planID names a purchasable (paid) plan.
func (s *Service) PaidPlan(planID string) (policy.Plan, error) {
	p, err := s.catalog.Get(planID)
	if err != nil || !p.Paid() || p.HostnameKind != "reserved" {
		return policy.Plan{}, apperr.ErrInvalidRequest.WithDetails(map[string]any{"field": "plan", "reason": "must be one of the paid tiers"})
	}
	return p, nil
}

// CreateOrReuse returns an open offer for (principal, name, plan), creating a
// new one with a fresh terms snapshot if none is open. Availability of the
// name is checked (non-binding: there is no hold).
func (s *Service) CreateOrReuse(ctx context.Context, principalID, name, planID string) (Offer, error) {
	plan, err := s.PaidPlan(planID)
	if err != nil {
		return Offer{}, err
	}
	n, err := s.endpoints.CheckName(ctx, principalID, name)
	if err != nil {
		return Offer{}, err
	}
	if s.Available != nil {
		if err := s.Available(ctx, principalID, n); err != nil {
			return Offer{}, err
		}
	}
	now := s.clk.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if o, ok := s.store.FindOpen(ctx, principalID, n, planID, now); ok {
		return o, nil
	}
	o := Offer{ID: s.ids.New("offer"), PrincipalID: principalID, ScopeName: n, PlanID: planID, State: StateOpen, CreatedAt: now, ExpiresAt: now.Add(s.ttl),
		Terms: Terms{PlanID: plan.ID, PlanVersion: plan.Version, Amount: plan.PriceAmount, Asset: plan.PriceAsset, Interval: plan.Interval, Unit: plan.Unit,
			BandwidthBytesPerSecond: plan.BandwidthBytesPerSecond, MonthlyTransferBytes: plan.MonthlyTransferBytes}}
	if err := s.store.Put(ctx, o); err != nil {
		return Offer{}, apperr.ErrInternal.Wrap(err)
	}
	return o, nil
}

// GetByID returns an offer regardless of owner (internal use).
func (s *Service) GetByID(ctx context.Context, id string) (Offer, error) {
	o, err := s.store.Get(ctx, id)
	if err != nil {
		return Offer{}, apperr.ErrNotFound
	}
	return s.refresh(o), nil
}

// Get returns an offer owned by principalID.
func (s *Service) Get(ctx context.Context, principalID, id string) (Offer, error) {
	o, err := s.GetByID(ctx, id)
	if err != nil || o.PrincipalID != principalID {
		return Offer{}, apperr.ErrNotFound
	}
	return o, nil
}

// refresh derives "expired" lazily so readers never see a stale open offer.
func (s *Service) refresh(o Offer) Offer {
	if o.State == StateOpen && !s.clk.Now().Before(o.ExpiresAt) {
		o.State = StateExpired
	}
	return o
}

func (s *Service) transition(ctx context.Context, id string, to State) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, err := s.store.Get(ctx, id)
	if err != nil {
		return apperr.ErrNotFound
	}
	if o.State == to || o.State == StatePaid {
		return nil // paid is final; idempotent otherwise
	}
	o.State = to
	return s.store.Put(ctx, o)
}

// MarkPaid records that the offer's payment settled.
func (s *Service) MarkPaid(ctx context.Context, id string) error {
	return s.transition(ctx, id, StatePaid)
}

// MarkExpired records expiry.
func (s *Service) MarkExpired(ctx context.Context, id string) error {
	return s.transition(ctx, id, StateExpired)
}

// ExpireDue persists expiry for offers past their deadline and returns them.
func (s *Service) ExpireDue(ctx context.Context) []Offer {
	var out []Offer
	now := s.clk.Now()
	for _, o := range s.store.List(ctx) {
		if o.State == StateOpen && !now.Before(o.ExpiresAt) {
			if s.MarkExpired(ctx, o.ID) == nil {
				o.State = StateExpired
				out = append(out, o)
			}
		}
	}
	return out
}
