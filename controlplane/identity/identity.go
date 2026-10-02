// Package identity implements principals and the Ed25519 challenge-response
// flow (spec section 8.2). A principal is a public key; no account, email or
// password is involved.
package identity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/127ohoh1/core/internal/apperr"
	"github.com/127ohoh1/core/internal/clock"
	"github.com/127ohoh1/core/internal/ids"
	"github.com/127ohoh1/core/protocol/auth"
)

// PrincipalState is the lifecycle state of a principal.
type PrincipalState string

const (
	PrincipalActive    PrincipalState = "active"
	PrincipalSuspended PrincipalState = "suspended"
)

// Principal is the cryptographic identity that owns endpoints.
type Principal struct {
	ID          string
	PublicKey   ed25519.PublicKey
	Fingerprint string
	State       PrincipalState
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Store persists principals. Implementations must enforce fingerprint
// uniqueness atomically (ErrExists on a race).
type Store interface {
	ByFingerprint(ctx context.Context, fp string) (Principal, error)
	ByID(ctx context.Context, id string) (Principal, error)
	Create(ctx context.Context, p Principal) error
	SetState(ctx context.Context, id string, s PrincipalState, at time.Time) error
}

// ChallengeStore holds short-lived challenges.
type ChallengeStore interface {
	Put(ctx context.Context, c StoredChallenge) error
	// Consume atomically marks the challenge consumed and returns it.
	// ErrChallengeReplayed is returned if it was already consumed,
	// ErrChallengeNotFound if unknown.
	Consume(ctx context.Context, id string, at time.Time) (StoredChallenge, error)
}

// StoredChallenge is the persisted challenge: only the nonce hash is kept.
type StoredChallenge struct {
	ID        string
	PublicKey ed25519.PublicKey
	NonceHash []byte
	Audience  string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// Sentinel errors.
var (
	ErrNotFound          = errors.New("identity: principal not found")
	ErrExists            = errors.New("identity: principal exists")
	ErrChallengeNotFound = errors.New("identity: challenge not found")
	ErrChallengeReplayed = errors.New("identity: challenge already consumed")
	ErrStoreFull         = errors.New("identity: challenge store full")
)

// Failure reasons reported through Config.OnFailure (metric labels).
const (
	FailBadKey    = "bad_key"
	FailUnknown   = "unknown_challenge"
	FailReplay    = "replay"
	FailExpired   = "expired"
	FailSignature = "bad_signature"
	FailSuspended = "suspended"
	FailNonce     = "bad_nonce"
	FailStoreFull = "store_full"
)

// Config configures the Service.
type Config struct {
	Audience     string // audience challenges are issued for
	SessionAud   string // audience of issued session tokens
	ChallengeTTL time.Duration
	SessionTTL   time.Duration
	// OnFailure, if set, observes authentication failures (never secrets).
	OnFailure func(reason string)
}

// Service issues challenges and sessions and authenticates bearer sessions.
type Service struct {
	cfg        Config
	principals Store
	challenges ChallengeStore
	signer     *auth.Signer
	keys       auth.KeySet
	clk        clock.Clock
	ids        *ids.Generator
	rand       func([]byte) error
}

// NewService builds a Service. keys must contain the signer's public key.
func NewService(cfg Config, p Store, c ChallengeStore, signer *auth.Signer, keys auth.KeySet, clk clock.Clock, g *ids.Generator) *Service {
	return &Service{cfg: cfg, principals: p, challenges: c, signer: signer, keys: keys, clk: clk, ids: g,
		rand: func(b []byte) error { _, err := rand.Read(b); return err }}
}

func (s *Service) fail(reason string, err error) error {
	if s.cfg.OnFailure != nil {
		s.cfg.OnFailure(reason)
	}
	return err
}

// Challenge is the public portion returned to the client.
type Challenge struct {
	ID        string
	Nonce     []byte
	Audience  string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// IssueChallenge validates the key format and returns a fresh single-use
// challenge. It does not create a principal: that only happens after the
// client proves possession.
func (s *Service) IssueChallenge(ctx context.Context, publicKey string) (Challenge, error) {
	pub, err := auth.ParsePublicKey(publicKey)
	if err != nil {
		return Challenge{}, s.fail(FailBadKey, apperr.ErrInvalidRequest.WithDetails(map[string]any{"field": "public_key"}))
	}
	nonce := make([]byte, 32)
	if err := s.rand(nonce); err != nil {
		return Challenge{}, apperr.ErrInternal.Wrap(err)
	}
	now := s.clk.Now()
	sc := StoredChallenge{
		ID: s.ids.New("ch"), PublicKey: pub, NonceHash: auth.NonceHash(nonce),
		Audience: s.cfg.Audience, IssuedAt: now, ExpiresAt: now.Add(s.cfg.ChallengeTTL),
	}
	if err := s.challenges.Put(ctx, sc); err != nil {
		if errors.Is(err, ErrStoreFull) {
			return Challenge{}, s.fail(FailStoreFull, apperr.ErrRateLimited.Wrap(err))
		}
		return Challenge{}, apperr.ErrInternal.Wrap(err)
	}
	return Challenge{ID: sc.ID, Nonce: nonce, Audience: sc.Audience, IssuedAt: now, ExpiresAt: sc.ExpiresAt}, nil
}

// Session is a short-lived control-plane credential.
type Session struct {
	Token       string
	ExpiresAt   time.Time
	PrincipalID string
	Fingerprint string
	Created     bool // true if this call created the principal
}

// CreateSession verifies a signed challenge and, on success, returns a session
// token for the (possibly newly created) principal.
//
// Order matters: the challenge is consumed *before* the signature is checked,
// so a failed attempt burns the challenge and cannot be used as a
// signature-guessing oracle; replays fail with the same generic error.
func (s *Service) CreateSession(ctx context.Context, challengeID string, nonce, signature []byte) (Session, error) {
	sc, err := s.challenges.Consume(ctx, challengeID, s.clk.Now())
	switch {
	case errors.Is(err, ErrChallengeNotFound):
		return Session{}, s.fail(FailUnknown, apperr.ErrUnauthorized)
	case errors.Is(err, ErrChallengeReplayed):
		return Session{}, s.fail(FailReplay, apperr.ErrUnauthorized)
	case err != nil:
		return Session{}, apperr.ErrInternal.Wrap(err)
	}
	now := s.clk.Now()
	if !now.Before(sc.ExpiresAt) {
		return Session{}, s.fail(FailExpired, apperr.ErrUnauthorized)
	}
	if sc.Audience != s.cfg.Audience {
		return Session{}, s.fail(FailSignature, apperr.ErrUnauthorized)
	}
	if !auth.HashEqual(auth.NonceHash(nonce), sc.NonceHash) {
		return Session{}, s.fail(FailNonce, apperr.ErrUnauthorized)
	}
	fp := auth.Fingerprint(sc.PublicKey)
	ch := auth.Challenge{ID: sc.ID, Nonce: nonce, Audience: sc.Audience, Fingerprint: fp, IssuedAt: sc.IssuedAt, ExpiresAt: sc.ExpiresAt}
	if err := auth.VerifyChallenge(sc.PublicKey, ch, signature); err != nil {
		return Session{}, s.fail(FailSignature, apperr.ErrUnauthorized)
	}
	p, created, err := s.ensurePrincipal(ctx, sc.PublicKey, fp)
	if err != nil {
		return Session{}, err
	}
	if p.State != PrincipalActive {
		return Session{}, s.fail(FailSuspended, apperr.ErrForbidden.WithDetails(map[string]any{"reason": "principal_suspended"}))
	}
	exp := now.Add(s.cfg.SessionTTL)
	tok, err := s.signer.Sign(auth.Claims{Type: auth.TypeSession, Subject: p.ID, Audience: s.cfg.SessionAud,
		PublicKey: auth.EncodeKey(p.PublicKey), ID: s.ids.New("tok"), IssuedAt: now.Unix(), ExpiresAt: exp.Unix()})
	if err != nil {
		return Session{}, apperr.ErrInternal.Wrap(err)
	}
	return Session{Token: tok, ExpiresAt: exp, PrincipalID: p.ID, Fingerprint: fp, Created: created}, nil
}

func (s *Service) ensurePrincipal(ctx context.Context, pub ed25519.PublicKey, fp string) (Principal, bool, error) {
	p, err := s.principals.ByFingerprint(ctx, fp)
	if err == nil {
		return p, false, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return Principal{}, false, apperr.ErrInternal.Wrap(err)
	}
	now := s.clk.Now()
	np := Principal{ID: s.ids.New("pr"), PublicKey: pub, Fingerprint: fp, State: PrincipalActive, CreatedAt: now, UpdatedAt: now}
	if err := s.principals.Create(ctx, np); err != nil {
		if errors.Is(err, ErrExists) { // lost a creation race; the unique constraint is authoritative
			p, err2 := s.principals.ByFingerprint(ctx, fp)
			if err2 != nil {
				return Principal{}, false, apperr.ErrInternal.Wrap(err2)
			}
			return p, false, nil
		}
		return Principal{}, false, apperr.ErrInternal.Wrap(err)
	}
	return np, true, nil
}

// Authenticate verifies a session bearer token and returns the principal. A
// suspended principal is rejected even if its token is still unexpired.
func (s *Service) Authenticate(ctx context.Context, token string) (Principal, error) {
	c, err := s.keys.Verify(token, auth.TypeSession, s.cfg.SessionAud, s.clk.Now())
	if err != nil {
		return Principal{}, apperr.ErrUnauthorized
	}
	p, err := s.principals.ByID(ctx, c.Subject)
	if err != nil {
		return Principal{}, apperr.ErrUnauthorized
	}
	if p.State != PrincipalActive {
		return Principal{}, apperr.ErrForbidden.WithDetails(map[string]any{"reason": "principal_suspended"})
	}
	return p, nil
}

// Principal returns a principal by id.
func (s *Service) Principal(ctx context.Context, id string) (Principal, error) {
	p, err := s.principals.ByID(ctx, id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return Principal{}, apperr.ErrNotFound
		}
		return Principal{}, apperr.ErrInternal.Wrap(err)
	}
	return p, nil
}

// Suspend suspends a principal (administrative hook). Idempotent.
func (s *Service) Suspend(ctx context.Context, id string) error {
	return s.setState(ctx, id, PrincipalSuspended)
}

// Unsuspend restores a principal. Idempotent.
func (s *Service) Unsuspend(ctx context.Context, id string) error {
	return s.setState(ctx, id, PrincipalActive)
}

func (s *Service) setState(ctx context.Context, id string, st PrincipalState) error {
	if err := s.principals.SetState(ctx, id, st, s.clk.Now()); err != nil {
		if errors.Is(err, ErrNotFound) {
			return apperr.ErrNotFound
		}
		return fmt.Errorf("set principal state: %w", err)
	}
	return nil
}

// InMemory is a development store for principals and challenges.
type InMemory struct {
	mu         sync.Mutex
	byID       map[string]Principal
	byFP       map[string]string
	challenges map[string]*memChallenge
	maxChal    int
}

type memChallenge struct {
	StoredChallenge
	consumed bool
}

// NewInMemory returns an empty development store. maxChallenges bounds
// outstanding challenges (registration-spam defence); 0 means 100000.
func NewInMemory(maxChallenges int) *InMemory {
	if maxChallenges <= 0 {
		maxChallenges = 100000
	}
	return &InMemory{byID: map[string]Principal{}, byFP: map[string]string{}, challenges: map[string]*memChallenge{}, maxChal: maxChallenges}
}

func (m *InMemory) ByFingerprint(_ context.Context, fp string) (Principal, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.byFP[fp]
	if !ok {
		return Principal{}, ErrNotFound
	}
	return m.byID[id], nil
}

func (m *InMemory) ByID(_ context.Context, id string) (Principal, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.byID[id]
	if !ok {
		return Principal{}, ErrNotFound
	}
	return p, nil
}

func (m *InMemory) Create(_ context.Context, p Principal) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.byFP[p.Fingerprint]; ok {
		return ErrExists
	}
	m.byID[p.ID] = p
	m.byFP[p.Fingerprint] = p.ID
	return nil
}

func (m *InMemory) SetState(_ context.Context, id string, s PrincipalState, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.byID[id]
	if !ok {
		return ErrNotFound
	}
	p.State, p.UpdatedAt = s, at
	m.byID[id] = p
	return nil
}

func (m *InMemory) Put(_ context.Context, c StoredChallenge) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.challenges) >= m.maxChal {
		// Prune what has expired long ago before refusing.
		for id, ch := range m.challenges {
			if c.IssuedAt.After(ch.ExpiresAt.Add(time.Minute)) {
				delete(m.challenges, id)
			}
		}
		if len(m.challenges) >= m.maxChal {
			return ErrStoreFull
		}
	}
	m.challenges[c.ID] = &memChallenge{StoredChallenge: c}
	return nil
}

func (m *InMemory) Consume(_ context.Context, id string, _ time.Time) (StoredChallenge, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.challenges[id]
	if !ok {
		return StoredChallenge{}, ErrChallengeNotFound
	}
	if c.consumed {
		return StoredChallenge{}, ErrChallengeReplayed
	}
	c.consumed = true
	return c.StoredChallenge, nil
}
