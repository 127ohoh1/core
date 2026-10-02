// Package endpoint owns endpoint identity, hostname allocation and the
// lifecycle state machine.
package endpoint

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/127ohoh1/core/internal/apperr"
	"github.com/127ohoh1/core/internal/clock"
	"github.com/127ohoh1/core/internal/ids"
)

// Kind distinguishes randomly assigned free names from reserved paid names.
type Kind string

const (
	KindRandom   Kind = "random"
	KindReserved Kind = "reserved"
)

// State is the endpoint lifecycle state.
type State string

const (
	StatePending   State = "PENDING"
	StateActive    State = "ACTIVE"
	StateSuspended State = "SUSPENDED"
	StateExpired   State = "EXPIRED"
	StateReleased  State = "RELEASED"
)

// transitions is the complete, explicit state machine.
//
//	PENDING   -> ACTIVE | RELEASED
//	ACTIVE    -> SUSPENDED | EXPIRED | RELEASED
//	SUSPENDED -> ACTIVE | EXPIRED | RELEASED
//	EXPIRED   -> ACTIVE (renewed) | RELEASED
//	RELEASED  -> (terminal)
var transitions = map[State][]State{
	StatePending:   {StateActive, StateReleased},
	StateActive:    {StateSuspended, StateExpired, StateReleased},
	StateSuspended: {StateActive, StateExpired, StateReleased},
	StateExpired:   {StateActive, StateReleased},
	StateReleased:  nil,
}

// CanTransition reports whether from -> to is a valid transition. A
// self-transition is *not* valid here; idempotence is handled by callers
// treating "already in target state" as a no-op.
func CanTransition(from, to State) bool {
	for _, s := range transitions[from] {
		if s == to {
			return true
		}
	}
	return false
}

// Endpoint is a routable hostname bound to an owner.
type Endpoint struct {
	ID           string
	PrincipalID  string
	Hostname     string // label only, e.g. "quiet-river-7f2c"
	Kind         Kind
	State        State
	Connected    bool
	LastActiveAt time.Time
	CreatedAt    time.Time
	UpdatedAt    time.Time
	ReleasedAt   time.Time
}

// Registry errors.
var (
	ErrNotFound      = errors.New("endpoint: not found")
	ErrHostnameTaken = errors.New("endpoint: hostname unavailable")
	ErrLimit         = errors.New("endpoint: per-principal limit reached")
	ErrInvalidState  = errors.New("endpoint: invalid state transition")
)

// Registry persists endpoints. Implementations must enforce, atomically:
//   - hostname uniqueness among non-RELEASED endpoints, and among tombstones;
//   - the per-principal cap passed to Create.
type Registry interface {
	// Create inserts e. limit > 0 caps the principal's non-released endpoints of e.Kind.
	Create(ctx context.Context, e Endpoint, limit int) error
	Get(ctx context.Context, id string) (Endpoint, error)
	// ByHostname returns the non-released endpoint with that hostname.
	ByHostname(ctx context.Context, hostname string) (Endpoint, error)
	ListByPrincipal(ctx context.Context, principalID string, includeReleased bool) ([]Endpoint, error)
	// Transition moves id to state to. changed is false if it was already
	// there (idempotent). tombstoneUntil, if non-zero and to==RELEASED, blocks
	// re-allocation of the hostname to other principals until then.
	Transition(ctx context.Context, id string, to State, at time.Time, tombstoneUntil time.Time) (e Endpoint, changed bool, err error)
	// SetPresence records tunnel connectivity. It refuses released endpoints.
	SetPresence(ctx context.Context, id string, connected bool, at time.Time) error
	// Available reports whether principalID could create an endpoint with this
	// hostname at `at`: it must not be live, and not tombstoned for others.
	Available(ctx context.Context, hostname, principalID string, at time.Time) error
	// ListInactiveFree returns ACTIVE random endpoints with LastActiveAt <= cutoff.
	ListInactiveFree(ctx context.Context, cutoff time.Time) ([]Endpoint, error)
	// ListAllActiveReserved returns non-released reserved endpoints.
	ListReserved(ctx context.Context) ([]Endpoint, error)
}

// InMemory is the development registry.
type InMemory struct {
	mu         sync.Mutex
	byID       map[string]Endpoint
	byHost     map[string]string // hostname -> id of non-released endpoint
	tombstones map[string]tombstone
}

type tombstone struct {
	until     time.Time
	principal string
}

// NewInMemory returns an empty registry.
func NewInMemory() *InMemory {
	return &InMemory{byID: map[string]Endpoint{}, byHost: map[string]string{}, tombstones: map[string]tombstone{}}
}

func (m *InMemory) Create(_ context.Context, e Endpoint, limit int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.byHost[e.Hostname]; ok {
		return ErrHostnameTaken
	}
	if t, ok := m.tombstones[e.Hostname]; ok && e.CreatedAt.Before(t.until) && t.principal != e.PrincipalID {
		return ErrHostnameTaken
	}
	if limit > 0 {
		n := 0
		for _, x := range m.byID {
			if x.PrincipalID == e.PrincipalID && x.Kind == e.Kind && x.State != StateReleased {
				n++
			}
		}
		if n >= limit {
			return ErrLimit
		}
	}
	delete(m.tombstones, e.Hostname)
	m.byID[e.ID] = e
	m.byHost[e.Hostname] = e.ID
	return nil
}

func (m *InMemory) Get(_ context.Context, id string) (Endpoint, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.byID[id]
	if !ok {
		return Endpoint{}, ErrNotFound
	}
	return e, nil
}

func (m *InMemory) ByHostname(_ context.Context, h string) (Endpoint, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.byHost[h]
	if !ok {
		return Endpoint{}, ErrNotFound
	}
	return m.byID[id], nil
}

func (m *InMemory) ListByPrincipal(_ context.Context, pid string, includeReleased bool) ([]Endpoint, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Endpoint
	for _, e := range m.byID {
		if e.PrincipalID == pid && (includeReleased || e.State != StateReleased) {
			out = append(out, e)
		}
	}
	sortByCreated(out)
	return out, nil
}

func sortByCreated(es []Endpoint) {
	for i := 1; i < len(es); i++ {
		for j := i; j > 0 && (es[j].CreatedAt.Before(es[j-1].CreatedAt) || (es[j].CreatedAt.Equal(es[j-1].CreatedAt) && es[j].ID < es[j-1].ID)); j-- {
			es[j], es[j-1] = es[j-1], es[j]
		}
	}
}

func (m *InMemory) Transition(_ context.Context, id string, to State, at, tombUntil time.Time) (Endpoint, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.byID[id]
	if !ok {
		return Endpoint{}, false, ErrNotFound
	}
	if e.State == to {
		return e, false, nil
	}
	if !CanTransition(e.State, to) {
		return e, false, fmt.Errorf("%w: %s -> %s", ErrInvalidState, e.State, to)
	}
	e.State, e.UpdatedAt = to, at
	if to == StateReleased {
		e.ReleasedAt, e.Connected = at, false
		delete(m.byHost, e.Hostname)
		if !tombUntil.IsZero() {
			m.tombstones[e.Hostname] = tombstone{until: tombUntil, principal: e.PrincipalID}
		}
	}
	m.byID[id] = e
	return e, true, nil
}

func (m *InMemory) SetPresence(_ context.Context, id string, connected bool, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.byID[id]
	if !ok {
		return ErrNotFound
	}
	if e.State == StateReleased {
		return ErrInvalidState
	}
	e.Connected = connected
	if at.After(e.LastActiveAt) {
		e.LastActiveAt = at
	}
	e.UpdatedAt = at
	m.byID[id] = e
	return nil
}

func (m *InMemory) Available(_ context.Context, hostname, principalID string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if id, ok := m.byHost[hostname]; ok {
		if m.byID[id].PrincipalID != principalID {
			return ErrHostnameTaken
		}
		return nil
	}
	if t, ok := m.tombstones[hostname]; ok && at.Before(t.until) && t.principal != principalID {
		return ErrHostnameTaken
	}
	return nil
}

func (m *InMemory) ListInactiveFree(_ context.Context, cutoff time.Time) ([]Endpoint, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Endpoint
	for _, e := range m.byID {
		if e.Kind == KindRandom && e.State == StateActive && !e.LastActiveAt.After(cutoff) {
			out = append(out, e)
		}
	}
	sortByCreated(out)
	return out, nil
}

func (m *InMemory) ListReserved(_ context.Context) ([]Endpoint, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Endpoint
	for _, e := range m.byID {
		if e.Kind == KindReserved && e.State != StateReleased {
			out = append(out, e)
		}
	}
	sortByCreated(out)
	return out, nil
}

// Config configures the Service.
type Config struct {
	MaxRandomPerPrincipal int
	Tombstone             time.Duration
	FreeInactivity        time.Duration
	MaxAllocAttempts      int
}

// Service implements endpoint use cases on top of a Registry.
type Service struct {
	cfg       Config
	reg       Registry
	alloc     NameAllocator
	validator NameValidator
	clk       clock.Clock
	ids       *ids.Generator
	// OnChange, if set, is called after any enforcement-relevant change.
	OnChange func(ctx context.Context, endpointID string)
	// OnReap counts released free endpoints (metric hook).
	OnReap func(n int)
}

// NewService builds a Service.
func NewService(cfg Config, reg Registry, alloc NameAllocator, v NameValidator, clk clock.Clock, g *ids.Generator) *Service {
	if cfg.MaxAllocAttempts <= 0 {
		cfg.MaxAllocAttempts = 8
	}
	if v == nil {
		v = DefaultNameValidator{}
	}
	return &Service{cfg: cfg, reg: reg, alloc: alloc, validator: v, clk: clk, ids: g}
}

func (s *Service) changed(ctx context.Context, id string) {
	if s.OnChange != nil {
		s.OnChange(ctx, id)
	}
}

func mapErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrNotFound):
		return apperr.ErrNotFound
	case errors.Is(err, ErrHostnameTaken):
		return apperr.ErrConflict.WithDetails(map[string]any{"reason": "hostname_unavailable"}).Wrap(err)
	case errors.Is(err, ErrLimit):
		return apperr.ErrRateLimited.WithDetails(map[string]any{"reason": "endpoint_limit_reached"}).Wrap(err)
	case errors.Is(err, ErrInvalidState):
		return apperr.ErrConflict.WithDetails(map[string]any{"reason": "invalid_state_transition"}).Wrap(err)
	}
	return apperr.ErrInternal.Wrap(err)
}

func (s *Service) newEndpoint(pid, host string, kind Kind) Endpoint {
	now := s.clk.Now()
	return Endpoint{ID: s.ids.New("ep"), PrincipalID: pid, Hostname: host, Kind: kind, State: StatePending,
		LastActiveAt: now, CreatedAt: now, UpdatedAt: now}
}

func (s *Service) activate(ctx context.Context, e Endpoint) (Endpoint, error) {
	out, _, err := s.reg.Transition(ctx, e.ID, StateActive, s.clk.Now(), time.Time{})
	if err != nil {
		return Endpoint{}, mapErr(err)
	}
	s.changed(ctx, out.ID)
	return out, nil
}

// CreateRandom allocates a random free endpoint. Name collisions are retried
// a bounded number of times; the registry's unique constraint decides.
func (s *Service) CreateRandom(ctx context.Context, principalID string) (Endpoint, error) {
	for i := 0; i < s.cfg.MaxAllocAttempts; i++ {
		name, err := s.alloc.Allocate(ctx)
		if err != nil {
			return Endpoint{}, apperr.ErrInternal.Wrap(err)
		}
		if _, err := ValidateName(s.validator, name); err != nil {
			continue
		}
		e := s.newEndpoint(principalID, name, KindRandom)
		if err := s.reg.Create(ctx, e, s.cfg.MaxRandomPerPrincipal); err != nil {
			if errors.Is(err, ErrHostnameTaken) {
				continue
			}
			return Endpoint{}, mapErr(err)
		}
		return s.activate(ctx, e)
	}
	return Endpoint{}, apperr.ErrUnavailable.WithDetails(map[string]any{"reason": "name_allocation_exhausted"})
}

// CreateReserved binds a validated reserved name. The caller (the reserve
// workflow) is responsible for having verified a matching active entitlement.
func (s *Service) CreateReserved(ctx context.Context, principalID, name string) (Endpoint, error) {
	n, err := ValidateName(s.validator, name)
	if err != nil {
		return Endpoint{}, apperr.ErrInvalidRequest.WithDetails(map[string]any{"field": "name", "reason": err.Error()})
	}
	e := s.newEndpoint(principalID, n, KindReserved)
	if err := s.reg.Create(ctx, e, 0); err != nil {
		return Endpoint{}, mapErr(err)
	}
	return s.activate(ctx, e)
}

// CheckName validates a candidate reserved name and reports availability
// without reserving it (non-binding).
func (s *Service) CheckName(ctx context.Context, principalID, name string) (string, error) {
	n, err := ValidateName(s.validator, name)
	if err != nil {
		return "", apperr.ErrInvalidRequest.WithDetails(map[string]any{"field": "name", "reason": err.Error()})
	}
	// Live endpoints and post-release tombstones both make a name unavailable:
	// an offer must never be issued for a name the buyer could not then obtain.
	if err := s.reg.Available(ctx, n, principalID, s.clk.Now()); err != nil {
		return "", mapErr(err)
	}
	return n, nil
}

// Get returns an endpoint owned by principalID. Other principals get NotFound,
// never Forbidden, so existence is not disclosed.
func (s *Service) Get(ctx context.Context, principalID, id string) (Endpoint, error) {
	e, err := s.reg.Get(ctx, id)
	if err != nil {
		return Endpoint{}, mapErr(err)
	}
	if e.PrincipalID != principalID {
		return Endpoint{}, apperr.ErrNotFound
	}
	return e, nil
}

// GetByID is the unauthenticated-by-owner lookup for internal callers.
func (s *Service) GetByID(ctx context.Context, id string) (Endpoint, error) {
	e, err := s.reg.Get(ctx, id)
	return e, mapErr(err)
}

// ByHostname resolves a live hostname.
func (s *Service) ByHostname(ctx context.Context, host string) (Endpoint, error) {
	e, err := s.reg.ByHostname(ctx, host)
	return e, mapErr(err)
}

// ListAll returns all of the principal's endpoints, including released ones.
func (s *Service) ListAll(ctx context.Context, principalID string) ([]Endpoint, error) {
	es, err := s.reg.ListByPrincipal(ctx, principalID, true)
	return es, mapErr(err)
}

// List returns the principal's non-released endpoints.
func (s *Service) List(ctx context.Context, principalID string) ([]Endpoint, error) {
	es, err := s.reg.ListByPrincipal(ctx, principalID, false)
	return es, mapErr(err)
}

// Release releases an owned endpoint (idempotent).
func (s *Service) Release(ctx context.Context, principalID, id string) (Endpoint, error) {
	if _, err := s.Get(ctx, principalID, id); err != nil {
		return Endpoint{}, err
	}
	return s.transition(ctx, id, StateReleased)
}

func (s *Service) transition(ctx context.Context, id string, to State) (Endpoint, error) {
	now := s.clk.Now()
	var tomb time.Time
	if to == StateReleased && s.cfg.Tombstone > 0 {
		tomb = now.Add(s.cfg.Tombstone)
	}
	e, changed, err := s.reg.Transition(ctx, id, to, now, tomb)
	if err != nil {
		return Endpoint{}, mapErr(err)
	}
	if changed {
		s.changed(ctx, id)
	}
	return e, nil
}

// Suspend, Unsuspend and Expire are administrative/system hooks (idempotent).
func (s *Service) Suspend(ctx context.Context, id string) (Endpoint, error) {
	return s.transition(ctx, id, StateSuspended)
}
func (s *Service) Unsuspend(ctx context.Context, id string) (Endpoint, error) {
	return s.transition(ctx, id, StateActive)
}
func (s *Service) Expire(ctx context.Context, id string) (Endpoint, error) {
	return s.transition(ctx, id, StateExpired)
}
func (s *Service) Reactivate(ctx context.Context, id string) (Endpoint, error) {
	return s.transition(ctx, id, StateActive)
}
func (s *Service) ReleaseByID(ctx context.Context, id string) (Endpoint, error) {
	return s.transition(ctx, id, StateReleased)
}

// SetPresence records edge-reported tunnel connectivity.
func (s *Service) SetPresence(ctx context.Context, id string, connected bool, at time.Time) error {
	return mapErr(s.reg.SetPresence(ctx, id, connected, at))
}

// ReapExpiredReserved releases reserved endpoints that have stayed EXPIRED for
// at least `after` (their entitlement lapsed and was not renewed). The name
// then enters the normal tombstone.
func (s *Service) ReapExpiredReserved(ctx context.Context, after time.Duration) (int, error) {
	es, err := s.reg.ListReserved(ctx)
	if err != nil {
		return 0, mapErr(err)
	}
	cutoff := s.clk.Now().Add(-after)
	n := 0
	for _, e := range es {
		if e.State == StateExpired && !e.UpdatedAt.After(cutoff) {
			if _, err := s.transition(ctx, e.ID, StateReleased); err != nil {
				return n, err
			}
			n++
		}
	}
	return n, nil
}

// Reap releases free endpoints that had no authenticated tunnel for the full
// inactivity window. last_active_at is refreshed by edge heartbeats while a
// tunnel is connected, so a connected endpoint never qualifies, and one whose
// edge died stops qualifying-out only after a full window without heartbeats.
func (s *Service) Reap(ctx context.Context) (int, error) {
	cutoff := s.clk.Now().Add(-s.cfg.FreeInactivity)
	es, err := s.reg.ListInactiveFree(ctx, cutoff)
	if err != nil {
		return 0, mapErr(err)
	}
	n := 0
	for _, e := range es {
		if _, err := s.transition(ctx, e.ID, StateReleased); err != nil {
			return n, err
		}
		n++
	}
	if n > 0 && s.OnReap != nil {
		s.OnReap(n)
	}
	return n, nil
}
