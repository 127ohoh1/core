package api

import (
	"crypto/sha256"
	"errors"
	"sync"
	"time"

	"github.com/127ohoh1/core/internal/apperr"
	"github.com/127ohoh1/core/internal/clock"
)

// Idempotency stores results of state-changing requests keyed by
// (principal, operation, key). Re-using a key with a different request digest
// is a conflict; replays return the stored response. Development
// implementation: in memory, bounded, expiring.
type Idempotency struct {
	mu   sync.Mutex
	clk  clock.Clock
	ttl  time.Duration
	max  int
	recs map[string]*idemRecord
}

type idemRecord struct {
	digest  [32]byte
	done    bool
	status  int
	body    []byte
	expires time.Time
}

// NewIdempotency returns a store with the given ttl and capacity.
func NewIdempotency(clk clock.Clock, ttl time.Duration, max int) *Idempotency {
	return &Idempotency{clk: clk, ttl: ttl, max: max, recs: map[string]*idemRecord{}}
}

// Result is a stored response.
type Result struct {
	Status   int
	Body     []byte
	Replayed bool
}

// Digest hashes the parts that define request identity.
func Digest(parts ...[]byte) [32]byte {
	h := sha256.New()
	for _, p := range parts {
		var l [4]byte
		l[0], l[1], l[2], l[3] = byte(len(p)>>24), byte(len(p)>>16), byte(len(p)>>8), byte(len(p))
		h.Write(l[:])
		h.Write(p)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// Do runs fn at most once per (principal, op, key) while the record lives.
// fn's result is stored only if store(status) is true; other outcomes release
// the key so the caller may retry.
func (s *Idempotency) Do(principal, op, key string, digest [32]byte, store func(status int) bool, fn func() (int, []byte, error)) (Result, error) {
	k := principal + "\x00" + op + "\x00" + key
	now := s.clk.Now()
	s.mu.Lock()
	s.gc(now)
	if r, ok := s.recs[k]; ok {
		defer s.mu.Unlock()
		if r.digest != digest {
			return Result{}, apperr.ErrIdempotencyMismatch
		}
		if !r.done {
			return Result{}, apperr.ErrConflict.WithDetails(map[string]any{"reason": "request_in_progress"})
		}
		return Result{Status: r.status, Body: r.body, Replayed: true}, nil
	}
	if len(s.recs) >= s.max {
		s.mu.Unlock()
		return Result{}, apperr.ErrRateLimited
	}
	rec := &idemRecord{digest: digest, expires: now.Add(s.ttl)}
	s.recs[k] = rec
	s.mu.Unlock()

	status, body, err := fn()

	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil || !store(status) {
		delete(s.recs, k)
		return Result{Status: status, Body: body}, err
	}
	rec.done, rec.status, rec.body = true, status, body
	return Result{Status: status, Body: body}, nil
}

func (s *Idempotency) gc(now time.Time) {
	if len(s.recs) < s.max/2 {
		return
	}
	for k, r := range s.recs {
		if r.done && now.After(r.expires) {
			delete(s.recs, k)
		}
	}
}

// ValidKey reports whether an Idempotency-Key header value is acceptable.
func ValidKey(k string) error {
	if len(k) < 8 || len(k) > 128 {
		return errors.New("idempotency key must be 8-128 characters")
	}
	for i := 0; i < len(k); i++ {
		if c := k[i]; c < 0x21 || c > 0x7e {
			return errors.New("idempotency key must be printable ASCII")
		}
	}
	return nil
}
