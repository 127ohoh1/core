package cert

import (
	"context"
	"sync"
	"time"

	pp "github.com/127ohoh1/core/protocol/policy"
)

// IssuanceGate is the knownTenant check for NewAutocert. A tenant label may
// get a certificate when it has a live tunnel, or when the control plane
// confirms it is an active reserved (paid) name -- which lets the control
// plane warm the certificate right after payment, before the customer's
// first tunnel or visitor (ADR 0011).
//
// Labels without a tunnel cost a control-plane lookup, so those are bounded:
// a refused label is remembered for NegativeTTL, and at most Rate lookups
// per second (Burst at once) are made. Spraying never-reserved SNI names
// therefore neither triggers an issuance (the 2026-10-01 review finding)
// nor floods the control plane; at worst it delays a brand-new paid name
// until the next attempt.
type IssuanceGate struct {
	Live   func(ctx context.Context, label string) bool
	Lookup func(ctx context.Context, label string) (pp.HostnameStatus, error)
	Now    func() time.Time

	Rate        float64       // lookups per second (default 2)
	Burst       float64       // default 10
	NegativeTTL time.Duration // default 1 minute
	MaxRefused  int           // remembered refusals before the memory is reset (default 10,000)

	mu      sync.Mutex
	refused map[string]time.Time
	tokens  float64
	last    time.Time
}

// Allow reports whether label may be issued a certificate.
func (g *IssuanceGate) Allow(ctx context.Context, label string) bool {
	if g.Live != nil && g.Live(ctx, label) {
		return true
	}
	if g.Lookup == nil || !g.take(label) {
		return false
	}
	lctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	h, err := g.Lookup(lctx, label)
	if err == nil && h.CertificateIssuable() {
		return true
	}
	g.refuse(label)
	return false
}

func (g *IssuanceGate) now() time.Time {
	if g.Now != nil {
		return g.Now()
	}
	return time.Now()
}

// take spends a lookup token unless label was refused recently.
func (g *IssuanceGate) take(label string) bool {
	rate, burst, max := g.Rate, g.Burst, g.MaxRefused
	if rate <= 0 {
		rate = 2
	}
	if burst <= 0 {
		burst = 10
	}
	if max <= 0 {
		max = 10_000
	}
	now := g.now()
	g.mu.Lock()
	defer g.mu.Unlock()
	if until, ok := g.refused[label]; ok {
		if now.Before(until) {
			return false
		}
		delete(g.refused, label)
	}
	if g.last.IsZero() {
		g.tokens = burst
	} else {
		g.tokens = min(burst, g.tokens+now.Sub(g.last).Seconds()*rate)
	}
	g.last = now
	if g.tokens < 1 {
		return false
	}
	g.tokens--
	if len(g.refused) >= max {
		g.refused = nil
	}
	return true
}

func (g *IssuanceGate) refuse(label string) {
	ttl := g.NegativeTTL
	if ttl <= 0 {
		ttl = time.Minute
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.refused == nil {
		g.refused = map[string]time.Time{}
	}
	g.refused[label] = g.now().Add(ttl)
}
