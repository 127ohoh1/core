package identity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/127ohoh1/core/internal/apperr"
	"github.com/127ohoh1/core/internal/clock"
	"github.com/127ohoh1/core/internal/ids"
	"github.com/127ohoh1/core/protocol/auth"
)

type env struct {
	svc      *Service
	clk      *clock.Fake
	store    *InMemory
	fmu      sync.Mutex
	failures []string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{clk: clock.NewFake(time.Date(2026, 9, 12, 20, 0, 0, 0, time.UTC)), store: NewInMemory(0)}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer := auth.NewSigner("k1", priv)
	e.svc = NewService(Config{Audience: "aud-control", SessionAud: "aud-control", ChallengeTTL: time.Minute, SessionTTL: 15 * time.Minute,
		OnFailure: func(r string) { e.fmu.Lock(); e.failures = append(e.failures, r); e.fmu.Unlock() }},
		e.store, e.store, signer, auth.KeySet{"k1": pub}, e.clk, ids.New(e.clk))
	return e
}

func sign(t *testing.T, priv ed25519.PrivateKey, pub ed25519.PublicKey, c Challenge) []byte {
	t.Helper()
	sig, err := auth.SignChallenge(priv, auth.Challenge{ID: c.ID, Nonce: c.Nonce, Audience: c.Audience,
		Fingerprint: auth.Fingerprint(pub), IssuedAt: c.IssuedAt, ExpiresAt: c.ExpiresAt})
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func TestHappyPathCreatesPrincipalOnce(t *testing.T) {
	e := newEnv(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	ctx := context.Background()
	c, err := e.svc.IssueChallenge(ctx, auth.EncodeKey(pub))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Nonce) < 16 {
		t.Fatal("nonce too short")
	}
	s, err := e.svc.CreateSession(ctx, c.ID, c.Nonce, sign(t, priv, pub, c))
	if err != nil || !s.Created {
		t.Fatalf("%v %+v", err, s)
	}
	p, err := e.svc.Authenticate(ctx, s.Token)
	if err != nil || p.ID != s.PrincipalID {
		t.Fatalf("authenticate: %v", err)
	}
	// Second login: same principal, not created.
	c2, _ := e.svc.IssueChallenge(ctx, auth.EncodeKey(pub))
	s2, err := e.svc.CreateSession(ctx, c2.ID, c2.Nonce, sign(t, priv, pub, c2))
	if err != nil || s2.Created || s2.PrincipalID != s.PrincipalID {
		t.Fatalf("second login: %v %+v", err, s2)
	}
}

func TestWrongKeyRejected(t *testing.T) {
	e := newEnv(t)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, evilPriv, _ := ed25519.GenerateKey(rand.Reader)
	c, _ := e.svc.IssueChallenge(context.Background(), auth.EncodeKey(pub))
	_, err := e.svc.CreateSession(context.Background(), c.ID, c.Nonce, sign(t, evilPriv, pub, c))
	if !errors.Is(err, apperr.ErrUnauthorized) {
		t.Fatalf("got %v", err)
	}
	if got := e.failures[len(e.failures)-1]; got != FailSignature {
		t.Fatalf("failure reason %q", got)
	}
}

func TestReplayRejected(t *testing.T) {
	e := newEnv(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	ctx := context.Background()
	c, _ := e.svc.IssueChallenge(ctx, auth.EncodeKey(pub))
	sig := sign(t, priv, pub, c)
	if _, err := e.svc.CreateSession(ctx, c.ID, c.Nonce, sig); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.CreateSession(ctx, c.ID, c.Nonce, sig); !errors.Is(err, apperr.ErrUnauthorized) {
		t.Fatalf("replay accepted: %v", err)
	}
	if e.failures[len(e.failures)-1] != FailReplay {
		t.Fatalf("reason %v", e.failures)
	}
}

func TestFailedAttemptBurnsChallenge(t *testing.T) {
	e := newEnv(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	ctx := context.Background()
	c, _ := e.svc.IssueChallenge(ctx, auth.EncodeKey(pub))
	if _, err := e.svc.CreateSession(ctx, c.ID, c.Nonce, make([]byte, 64)); err == nil {
		t.Fatal("garbage signature accepted")
	}
	if _, err := e.svc.CreateSession(ctx, c.ID, c.Nonce, sign(t, priv, pub, c)); err == nil {
		t.Fatal("challenge must be single use even after a failed attempt")
	}
}

func TestExpiredChallengeRejected(t *testing.T) {
	e := newEnv(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	c, _ := e.svc.IssueChallenge(context.Background(), auth.EncodeKey(pub))
	e.clk.Advance(time.Minute) // exactly at expiry: not valid
	_, err := e.svc.CreateSession(context.Background(), c.ID, c.Nonce, sign(t, priv, pub, c))
	if !errors.Is(err, apperr.ErrUnauthorized) || e.failures[len(e.failures)-1] != FailExpired {
		t.Fatalf("got %v %v", err, e.failures)
	}
}

func TestWrongNonceRejected(t *testing.T) {
	e := newEnv(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	c, _ := e.svc.IssueChallenge(context.Background(), auth.EncodeKey(pub))
	sig := sign(t, priv, pub, c)
	bad := append([]byte(nil), c.Nonce...)
	bad[0] ^= 1
	if _, err := e.svc.CreateSession(context.Background(), c.ID, bad, sig); err == nil {
		t.Fatal("wrong nonce accepted")
	}
}

func TestBadKeyFormatsRejected(t *testing.T) {
	e := newEnv(t)
	for _, k := range []string{"", "short", "not base64!!", "AAAA"} {
		if _, err := e.svc.IssueChallenge(context.Background(), k); !errors.Is(err, apperr.ErrInvalidRequest) {
			t.Errorf("%q: %v", k, err)
		}
	}
}

func TestSuspendedPrincipalRejected(t *testing.T) {
	e := newEnv(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	ctx := context.Background()
	c, _ := e.svc.IssueChallenge(ctx, auth.EncodeKey(pub))
	s, _ := e.svc.CreateSession(ctx, c.ID, c.Nonce, sign(t, priv, pub, c))
	if err := e.svc.Suspend(ctx, s.PrincipalID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Authenticate(ctx, s.Token); !errors.Is(err, apperr.ErrForbidden) {
		t.Fatalf("existing session must stop working: %v", err)
	}
	c2, _ := e.svc.IssueChallenge(ctx, auth.EncodeKey(pub))
	if _, err := e.svc.CreateSession(ctx, c2.ID, c2.Nonce, sign(t, priv, pub, c2)); !errors.Is(err, apperr.ErrForbidden) {
		t.Fatalf("new session must be refused: %v", err)
	}
	e.svc.Unsuspend(ctx, s.PrincipalID)
	if _, err := e.svc.Authenticate(ctx, s.Token); err != nil {
		t.Fatalf("restored: %v", err)
	}
}

func TestSessionExpires(t *testing.T) {
	e := newEnv(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	ctx := context.Background()
	c, _ := e.svc.IssueChallenge(ctx, auth.EncodeKey(pub))
	s, _ := e.svc.CreateSession(ctx, c.ID, c.Nonce, sign(t, priv, pub, c))
	e.clk.Advance(16 * time.Minute)
	if _, err := e.svc.Authenticate(ctx, s.Token); !errors.Is(err, apperr.ErrUnauthorized) {
		t.Fatalf("expired session accepted: %v", err)
	}
}

// Concurrent consumption of one challenge: exactly one wins.
func TestConcurrentConsumeSingleWinner(t *testing.T) {
	e := newEnv(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	c, _ := e.svc.IssueChallenge(context.Background(), auth.EncodeKey(pub))
	sig := sign(t, priv, pub, c)
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := e.svc.CreateSession(context.Background(), c.ID, c.Nonce, sig); err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("wins = %d, want 1", wins)
	}
}

func TestChallengeStoreBounded(t *testing.T) {
	e := newEnv(t)
	e.store = NewInMemory(2)
	e.svc.challenges = e.store
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	k := auth.EncodeKey(pub)
	e.svc.IssueChallenge(context.Background(), k)
	e.svc.IssueChallenge(context.Background(), k)
	if _, err := e.svc.IssueChallenge(context.Background(), k); !errors.Is(err, apperr.ErrRateLimited) {
		t.Fatalf("got %v", err)
	}
}
