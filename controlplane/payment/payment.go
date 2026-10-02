package payment

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/127ohoh1/core/controlplane/audit"
	"github.com/127ohoh1/core/controlplane/offer"
	"github.com/127ohoh1/core/internal/apperr"
	"github.com/127ohoh1/core/internal/clock"
	"github.com/127ohoh1/core/internal/ids"
)

// Payment is one attempt to satisfy one offer.
type Payment struct {
	ID          string
	OfferID     string
	PrincipalID string
	Provider    string // "development"
	Reference   string // provider-side reference (unique per provider)
	State       State
	Amount      Money
	Network     string
	CreatedAt   time.Time
	UpdatedAt   time.Time
	SettledAt   time.Time
	// FailureReason is a stable machine code for FAILED/EXPIRED payments.
	FailureReason string
}

// Settlement is a verified economic event: "this payment was settled".
type Settlement struct {
	EventID   string // provider-unique event id; the idempotency key
	PaymentID string
	Amount    Money
	Network   string
	At        time.Time
}

// PaymentProof is what a verifier receives; its format is provider specific.
type PaymentProof struct {
	Provider  string
	Reference string
	Raw       string
}

// PaymentResult is the verifier's verdict on a proof.
type PaymentResult struct {
	Settled   bool
	EventID   string
	PaymentID string
	Amount    Money
	Network   string
}

// PaymentVerifier turns provider proof into a settlement fact. Verification
// (money moved?) is deliberately separate from entitlement (what does that
// buy?).
type PaymentVerifier interface {
	Verify(ctx context.Context, proof PaymentProof) (PaymentResult, error)
}

// PaymentService owns payment lifecycle and settlement processing.
type PaymentService interface {
	CreateForOffer(ctx context.Context, o offer.Offer) (Payment, error)
	Get(ctx context.Context, principalID, id string) (Payment, error)
	ProcessSettlement(ctx context.Context, s Settlement) (Payment, error)
}

// Store persists payments and the set of processed settlement events.
type Store interface {
	Create(ctx context.Context, p Payment) error // ErrDuplicateRef on (provider, reference) clash
	Get(ctx context.Context, id string) (Payment, error)
	ByOffer(ctx context.Context, offerID string) (Payment, error)
	Update(ctx context.Context, p Payment) error
	// BindEvent records that a settlement event id belongs to a payment. It is
	// idempotent for the same pair and fails with ErrEventReused if the id was
	// already bound to a different payment (a replay/forgery signal).
	BindEvent(ctx context.Context, eventID, paymentID string) error
}

// Store errors.
var (
	ErrNotFound     = errors.New("payment: not found")
	ErrDuplicateRef = errors.New("payment: duplicate provider reference")
	ErrEventReused  = errors.New("payment: settlement event id already bound to another payment")
)

// InMemory is the development store.
type InMemory struct {
	mu     sync.Mutex
	byID   map[string]Payment
	byRef  map[string]string
	byOff  map[string]string
	events map[string]string // event id -> payment id
}

// NewInMemory returns an empty store.
func NewInMemory() *InMemory {
	return &InMemory{byID: map[string]Payment{}, byRef: map[string]string{}, byOff: map[string]string{}, events: map[string]string{}}
}

func (m *InMemory) Create(_ context.Context, p Payment) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ref := p.Provider + "\x00" + p.Reference
	if _, ok := m.byRef[ref]; ok {
		return ErrDuplicateRef
	}
	m.byID[p.ID], m.byRef[ref], m.byOff[p.OfferID] = p, p.ID, p.ID
	return nil
}

func (m *InMemory) Get(_ context.Context, id string) (Payment, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.byID[id]
	if !ok {
		return Payment{}, ErrNotFound
	}
	return p, nil
}

func (m *InMemory) ByOffer(_ context.Context, offerID string) (Payment, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.byOff[offerID]
	if !ok {
		return Payment{}, ErrNotFound
	}
	return m.byID[id], nil
}

func (m *InMemory) Update(_ context.Context, p Payment) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.byID[p.ID]; !ok {
		return ErrNotFound
	}
	m.byID[p.ID] = p
	return nil
}

func (m *InMemory) BindEvent(_ context.Context, eventID, paymentID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if prev, ok := m.events[eventID]; ok && prev != paymentID {
		return ErrEventReused
	}
	m.events[eventID] = paymentID
	return nil
}

// EntitlementGranter is the narrow view of the entitlement service the
// payment flow needs. Granting must be idempotent per payment.
type EntitlementGranter interface {
	GrantFromSettlement(ctx context.Context, g Grant) error
}

// Grant is everything the entitlement service needs to turn one settlement
// into capabilities, snapshotted from the offer so later catalog changes
// cannot alter what was sold.
type Grant struct {
	SettlementID string // the payment id: one entitlement per settled payment
	OfferID      string
	PrincipalID  string
	ScopeName    string
	Terms        offer.Terms
	SettledAt    time.Time
}

// Service is the development PaymentService.
type Service struct {
	store    Store
	offers   *offer.Service
	grants   EntitlementGranter
	clk      clock.Clock
	ids      *ids.Generator
	audit    audit.Recorder
	network  string
	provider string

	lockMu sync.Mutex
	locks  map[string]*sync.Mutex
	// OnGranted, if set, is called after a settlement produced an entitlement.
	OnGranted func(ctx context.Context, name string)
}

// Development network / provider names appear in every payment method so
// nothing can be mistaken for a production payment.
const (
	DevProvider = "development"
	DevNetwork  = "development"
)

// NewService builds the development payment service.
func NewService(store Store, offers *offer.Service, grants EntitlementGranter, clk clock.Clock, g *ids.Generator, a audit.Recorder) *Service {
	if a == nil {
		a = audit.Nop{}
	}
	return &Service{store: store, offers: offers, grants: grants, clk: clk, ids: g, audit: a, network: DevNetwork, provider: DevProvider, locks: map[string]*sync.Mutex{}}
}

// paymentLock serialises processing per payment so duplicate concurrent
// deliveries of one settlement event cannot interleave.
func (s *Service) paymentLock(id string) *sync.Mutex {
	s.lockMu.Lock()
	defer s.lockMu.Unlock()
	l, ok := s.locks[id]
	if !ok {
		l = &sync.Mutex{}
		s.locks[id] = l
	}
	return l
}

// CreateForOffer creates (or returns) the payment for an offer and moves it
// to AWAITING_PAYMENT.
func (s *Service) CreateForOffer(ctx context.Context, o offer.Offer) (Payment, error) {
	if p, err := s.store.ByOffer(ctx, o.ID); err == nil {
		return p, nil
	}
	amt, err := ParseAmount(o.Terms.Amount, USDCDecimals)
	if err != nil {
		return Payment{}, apperr.ErrInternal.Wrap(err)
	}
	now := s.clk.Now()
	id := s.ids.New("pay")
	p := Payment{ID: id, OfferID: o.ID, PrincipalID: o.PrincipalID, Provider: s.provider, Reference: "dev-" + id, State: StateCreated,
		Amount: Money{Atomic: amt, Asset: o.Terms.Asset}, Network: s.network, CreatedAt: now, UpdatedAt: now}
	p.State = StateAwaitingPayment
	if err := s.store.Create(ctx, p); err != nil {
		if errors.Is(err, ErrDuplicateRef) {
			return Payment{}, apperr.ErrConflict.Wrap(err)
		}
		return Payment{}, apperr.ErrInternal.Wrap(err)
	}
	return p, nil
}

// ByOffer returns the payment for an offer (internal; callers check ownership of the offer).
func (s *Service) ByOffer(ctx context.Context, offerID string) (Payment, error) {
	p, err := s.store.ByOffer(ctx, offerID)
	if err != nil {
		return Payment{}, apperr.ErrNotFound
	}
	return p, nil
}

// Get returns a payment owned by principalID (NotFound otherwise).
func (s *Service) Get(ctx context.Context, principalID, id string) (Payment, error) {
	p, err := s.store.Get(ctx, id)
	if err != nil || p.PrincipalID != principalID {
		return Payment{}, apperr.ErrNotFound
	}
	return p, nil
}

func (s *Service) advance(p *Payment, to State) error {
	if p.State == to {
		return nil
	}
	if !CanTransition(p.State, to) {
		return &TransitionError{From: p.State, To: to}
	}
	p.State, p.UpdatedAt = to, s.clk.Now()
	return nil
}

// ProcessSettlement applies a verified settlement. It is idempotent: any
// number of deliveries of the same event (or of different events for an
// already settled payment) produce at most one entitlement, and re-delivery
// after a partial failure completes the remaining steps.
func (s *Service) ProcessSettlement(ctx context.Context, st Settlement) (Payment, error) {
	if st.EventID == "" || st.PaymentID == "" {
		return Payment{}, apperr.ErrInvalidRequest
	}
	lk := s.paymentLock(st.PaymentID)
	lk.Lock()
	defer lk.Unlock()

	p, err := s.store.Get(ctx, st.PaymentID)
	if err != nil {
		return Payment{}, apperr.ErrNotFound
	}
	// Re-entrant completion: a payment already at SETTLED (crash between
	// steps) continues; a fully granted one returns unchanged. This state check
	// under the per-payment lock is what makes duplicate delivery harmless.
	if p.State == StateEntitlementGranted {
		return p, nil
	}
	if p.State == StateExpired || p.State == StateFailed {
		return p, apperr.ErrConflict.WithDetails(map[string]any{"reason": "payment_" + string(p.State)})
	}
	o, err := s.offers.GetByID(ctx, p.OfferID)
	if err != nil {
		return p, err
	}
	now := s.clk.Now()

	if p.State != StateSettled {
		// The event is only "consumed" once we decided to act on it.
		if !now.Before(o.ExpiresAt) {
			p.FailureReason = "offer_expired"
			_ = s.advance(&p, StateExpired)
			_ = s.store.Update(ctx, p)
			_ = s.offers.MarkExpired(ctx, o.ID)
			return p, apperr.ErrConflict.WithDetails(map[string]any{"reason": "offer_expired"})
		}
		// Never trust the event's own claims: compare with the offer's immutable terms.
		if st.Amount.Atomic != p.Amount.Atomic || st.Amount.Asset != p.Amount.Asset || st.Network != p.Network {
			p.FailureReason = "settlement_mismatch"
			_ = s.advance(&p, StateFailed)
			_ = s.store.Update(ctx, p)
			s.audit.Record(ctx, audit.Event{ID: s.ids.New("aud"), Actor: "payment", Action: "payment.settle", Target: p.ID, Result: "denied", At: now,
				Metadata: map[string]string{"reason": "settlement_mismatch"}})
			return p, apperr.ErrConflict.WithDetails(map[string]any{"reason": "settlement_mismatch"})
		}
		if err := s.store.BindEvent(ctx, st.EventID, p.ID); err != nil {
			if errors.Is(err, ErrEventReused) {
				return p, apperr.ErrConflict.WithDetails(map[string]any{"reason": "event_reused"}).Wrap(err)
			}
			return p, apperr.ErrInternal.Wrap(err)
		}
		for _, to := range []State{StateSeen, StateConfirming, StateSettled} {
			if err := s.advance(&p, to); err != nil {
				return p, apperr.ErrConflict.Wrap(err)
			}
		}
		p.SettledAt = now
		if err := s.store.Update(ctx, p); err != nil {
			return p, apperr.ErrInternal.Wrap(err)
		}
	}

	// SETTLED -> grant (idempotent per payment) -> ENTITLEMENT_GRANTED.
	if err := s.grants.GrantFromSettlement(ctx, Grant{SettlementID: p.ID, OfferID: o.ID, PrincipalID: o.PrincipalID,
		ScopeName: o.ScopeName, Terms: o.Terms, SettledAt: p.SettledAt}); err != nil {
		return p, err // payment stays SETTLED; redelivery retries the grant
	}
	if err := s.advance(&p, StateEntitlementGranted); err != nil {
		return p, apperr.ErrInternal.Wrap(err)
	}
	if err := s.store.Update(ctx, p); err != nil {
		return p, apperr.ErrInternal.Wrap(err)
	}
	_ = s.offers.MarkPaid(ctx, o.ID)
	s.audit.Record(ctx, audit.Event{ID: s.ids.New("aud"), Actor: "payment", Action: "payment.settle", Target: p.ID, Result: "ok", At: now,
		Metadata: map[string]string{"offer": o.ID, "name": o.ScopeName, "plan": o.PlanID, "provider": p.Provider}})
	if s.OnGranted != nil {
		s.OnGranted(ctx, o.ScopeName)
	}
	return p, nil
}

// ExpireStale moves payments of expired offers to EXPIRED (background sweep).
func (s *Service) ExpireStale(ctx context.Context) int {
	n := 0
	for _, o := range s.offers.ExpireDue(ctx) {
		if p, err := s.store.ByOffer(ctx, o.ID); err == nil && !p.State.Terminal() && !p.State.Settled() {
			lk := s.paymentLock(p.ID)
			lk.Lock()
			p.FailureReason = "offer_expired"
			if s.advance(&p, StateExpired) == nil {
				_ = s.store.Update(ctx, p)
				n++
			}
			lk.Unlock()
		}
	}
	return n
}

func (p Payment) String() string { return fmt.Sprintf("payment(%s,%s)", p.ID, p.State) }
