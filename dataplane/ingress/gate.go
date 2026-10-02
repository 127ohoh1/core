package ingress

import (
	"context"
	"sync"
	"time"
)

// Direction of proxied body bytes.
type Direction int

const (
	ToTunnel   Direction = iota // request body: public caller -> origin
	FromTunnel                  // response body: origin -> public caller
)

// Limits are the per-request limits resolved from policy.
type Limits struct {
	MaxRequestHeaderBytes int
	MaxRequestBodyBytes   int64
}

// Refusal is a platform-generated rejection decided before forwarding.
type Refusal struct {
	Status     int
	Code       string // X-127ohoh1-Error value
	Message    string
	RetryAfter time.Duration
}

func (r *Refusal) Error() string { return r.Code + ": " + r.Message }

// Gate is the enforcement handle for one in-flight request. The ingress asks
// it before moving bytes; it knows nothing about plans, prices or payments,
// only resolved limits.
type Gate interface {
	Limits() Limits
	// Wait blocks until n bytes may be transferred (bandwidth token bucket).
	Wait(ctx context.Context, n int) error
	// Account meters n proxied body bytes. It returns *Refusal (quota
	// exhausted) if the endpoint may not transfer more; the ingress then
	// terminates the exchange consistently.
	Account(n int, d Direction) error
	// Release ends the request (concurrency slot).
	Release()
}

// Enforcer resolves an endpoint's policy into a Gate, or refuses the request.
type Enforcer interface {
	Acquire(ctx context.Context, endpointID string) (Gate, *Refusal)
}

// StaticEnforcer applies fixed limits with a per-endpoint concurrency cap and
// no bandwidth or quota enforcement. It is the development default until a
// policy-backed enforcer is wired.
type StaticEnforcer struct {
	L           Limits
	MaxInFlight int

	mu sync.Mutex
	in map[string]int
}

// NewStaticEnforcer returns a StaticEnforcer.
func NewStaticEnforcer(l Limits, maxInFlight int) *StaticEnforcer {
	return &StaticEnforcer{L: l, MaxInFlight: maxInFlight, in: map[string]int{}}
}

func (s *StaticEnforcer) Acquire(_ context.Context, id string) (Gate, *Refusal) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.MaxInFlight > 0 && s.in[id] >= s.MaxInFlight {
		return nil, &Refusal{Status: 429, Code: "too_many_requests", Message: "Too many concurrent requests for this endpoint.", RetryAfter: time.Second}
	}
	s.in[id]++
	return &staticGate{s: s, id: id}, nil
}

type staticGate struct {
	s    *StaticEnforcer
	id   string
	once sync.Once
}

func (g *staticGate) Limits() Limits                        { return g.s.L }
func (g *staticGate) Wait(ctx context.Context, _ int) error { return ctx.Err() }
func (g *staticGate) Account(int, Direction) error          { return nil }
func (g *staticGate) Release() {
	g.once.Do(func() {
		g.s.mu.Lock()
		if g.s.in[g.id]--; g.s.in[g.id] <= 0 {
			delete(g.s.in, g.id)
		}
		g.s.mu.Unlock()
	})
}
