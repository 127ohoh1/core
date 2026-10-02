// Package enforce turns cached, resolved policy into per-request decisions
// (ingress.Enforcer) and tunnel admission (tunnel.Admission). It knows limits
// and lifecycle state; it has no notion of plans, prices or payments.
//
// Quota behaviour (one documented choice): when the monthly quota is
// exhausted, *new* requests are refused immediately with 429 quota_exhausted,
// and requests already in flight are terminated at their next chunk boundary.
// Overshoot is therefore bounded by one chunk (<= 16 KiB) per in-flight stream
// plus whatever other edges have not yet reported (see ADR 0006).
package enforce

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/127ohoh1/core/dataplane/ingress"
	"github.com/127ohoh1/core/dataplane/metering"
	"github.com/127ohoh1/core/dataplane/policycache"
	"github.com/127ohoh1/core/dataplane/ratelimit"
	dtunnel "github.com/127ohoh1/core/dataplane/tunnel"
	"github.com/127ohoh1/core/internal/clock"
	"github.com/127ohoh1/core/internal/observability"
	pp "github.com/127ohoh1/core/protocol/policy"
)

// Metrics of the enforcer.
type Metrics struct {
	Throttle       *observability.Counter // edge_bandwidth_throttle_seconds_total
	QuotaExhausted *observability.Counter // edge_quota_exhausted_total{phase=new_request|in_flight}
}

// NewMetrics registers enforcer metrics.
func NewMetrics(r *observability.Registry) Metrics {
	return Metrics{
		Throttle:       r.Counter("edge_bandwidth_throttle_seconds_total", "Total time proxied transfers spent waiting for the token bucket."),
		QuotaExhausted: r.Counter("edge_quota_exhausted_total", "Requests refused or cut because the monthly quota is exhausted.", "phase"),
	}
}

// Enforcer implements ingress.Enforcer and tunnel.Admission.
type Enforcer struct {
	cache *policycache.Cache
	coll  *metering.Collector
	clk   clock.Clock
	m     Metrics

	mu     sync.Mutex
	states map[string]*endpointState
}

type endpointState struct {
	inflight int
	bucket   *ratelimit.Bucket
	meter    *metering.Meter
	// last applied policy identity, to avoid re-syncing on every request
	version int64
	used    int64
	period  time.Time
}

// New builds an Enforcer. coll may be nil (no metering: tests of pure policy).
func New(cache *policycache.Cache, coll *metering.Collector, clk clock.Clock, m Metrics) *Enforcer {
	return &Enforcer{cache: cache, coll: coll, clk: clk, m: m, states: map[string]*endpointState{}}
}

// stateRefusal maps a non-active state to the platform response.
func stateRefusal(s pp.State) *ingress.Refusal {
	switch s {
	case pp.StateSuspended:
		return &ingress.Refusal{Status: 403, Code: "endpoint_suspended", Message: "This endpoint has been suspended."}
	case pp.StateExpired:
		return &ingress.Refusal{Status: 403, Code: "endpoint_expired", Message: "This endpoint's entitlement has expired."}
	case pp.StateReleased:
		return &ingress.Refusal{Status: 404, Code: "endpoint_not_found", Message: "This endpoint no longer exists."}
	case pp.StatePending:
		return &ingress.Refusal{Status: 503, Code: "endpoint_pending", Message: "This endpoint is not active yet.", RetryAfter: 5 * time.Second}
	}
	return nil
}

func (e *Enforcer) entry(ctx context.Context, id string) (policycache.Entry, *ingress.Refusal) {
	ent, err := e.cache.Get(ctx, id)
	switch {
	case errors.Is(err, policycache.ErrNotFound):
		return ent, &ingress.Refusal{Status: 404, Code: "endpoint_not_found", Message: "This endpoint no longer exists."}
	case err != nil:
		return ent, &ingress.Refusal{Status: 503, Code: "policy_unavailable", Message: "Policy is temporarily unavailable.", RetryAfter: 5 * time.Second}
	}
	if ent.Status == policycache.Expired {
		// Past the stale grace: fail closed rather than serve on unbounded stale data.
		return ent, &ingress.Refusal{Status: 503, Code: "policy_expired", Message: "Policy could not be refreshed in time.", RetryAfter: 5 * time.Second}
	}
	if r := stateRefusal(ent.Policy.State); r != nil {
		return ent, r
	}
	return ent, nil
}

// Admit implements tunnel.Admission.
func (e *Enforcer) Admit(ctx context.Context, endpointID string) error {
	_, ref := e.entry(ctx, endpointID)
	switch {
	case ref == nil:
		return nil
	case ref.Code == "policy_unavailable", ref.Code == "policy_expired", ref.Code == "endpoint_pending":
		return dtunnel.ErrPolicyUnavailable
	}
	return dtunnel.ErrEndpointUnavailable
}

// stateFor returns the endpoint's enforcement state, syncing limiter and meter
// with the policy when it changed. Called with e.mu held.
func (e *Enforcer) stateFor(p pp.EndpointPolicy) *endpointState {
	st := e.states[p.EndpointID]
	if st == nil {
		st = &endpointState{bucket: ratelimit.New(e.clk, p.Limits.BandwidthBytesPerSecond, p.Limits.BurstBytes)}
		if e.coll != nil {
			st.meter = e.coll.Meter(p.EndpointID)
		}
		e.states[p.EndpointID] = st
		st.version = -1
	}
	if st.version != p.PolicyVersion || st.used != p.Usage.UsedBytes || !st.period.Equal(p.Usage.PeriodStart) {
		st.bucket.SetLimits(p.Limits.BandwidthBytesPerSecond, p.Limits.BurstBytes)
		if st.meter != nil {
			st.meter.Sync(p.Usage.PeriodStart, p.Usage.PeriodEnd, p.Limits.MonthlyTransferBytes, p.Usage.UsedBytes)
		}
		st.version, st.used, st.period = p.PolicyVersion, p.Usage.UsedBytes, p.Usage.PeriodStart
	}
	return st
}

func (e *Enforcer) quotaRefusal(st *endpointState) *ingress.Refusal {
	retry := time.Second
	if st.meter != nil {
		if d := st.meter.PeriodEnd().Sub(e.clk.Now()); d > 0 {
			retry = d
		}
	}
	return &ingress.Refusal{Status: 429, Code: "quota_exhausted", Message: "The endpoint has exhausted its monthly transfer allowance.", RetryAfter: retry}
}

// Acquire implements ingress.Enforcer.
func (e *Enforcer) Acquire(ctx context.Context, id string) (ingress.Gate, *ingress.Refusal) {
	ent, ref := e.entry(ctx, id)
	if ref != nil {
		return nil, ref
	}
	l := ent.Policy.Limits
	e.mu.Lock()
	defer e.mu.Unlock()
	st := e.stateFor(ent.Policy)
	if st.meter != nil && st.meter.Exhausted() {
		e.m.QuotaExhausted.Inc("new_request")
		return nil, e.quotaRefusal(st)
	}
	if l.ConcurrentRequests > 0 && st.inflight >= l.ConcurrentRequests {
		return nil, &ingress.Refusal{Status: 429, Code: "too_many_requests", Message: "Too many concurrent requests for this endpoint.", RetryAfter: time.Second}
	}
	st.inflight++
	return &gate{e: e, id: id, st: st, lim: ingress.Limits{MaxRequestHeaderBytes: l.MaxRequestHeaderBytes, MaxRequestBodyBytes: l.MaxRequestBodyBytes}}, nil
}

// Janitor drops state of endpoints that are idle and no longer cached, and
// releases their meters once everything was reported.
func (e *Enforcer) Janitor() {
	cached := map[string]bool{}
	for _, id := range e.cache.IDs() {
		cached[id] = true
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for id, st := range e.states {
		if st.inflight > 0 || cached[id] {
			continue
		}
		if e.coll == nil || e.coll.Forget(id) {
			delete(e.states, id)
		}
	}
}

type gate struct {
	e    *Enforcer
	id   string
	st   *endpointState
	lim  ingress.Limits
	once sync.Once
}

func (g *gate) Limits() ingress.Limits { return g.lim }

// Wait draws n bytes from the endpoint's shared token bucket.
func (g *gate) Wait(ctx context.Context, n int) error {
	start := g.e.clk.Now()
	err := g.st.bucket.Wait(ctx, n)
	if d := g.e.clk.Now().Sub(start); d > 0 {
		g.e.m.Throttle.Add(d.Seconds())
	}
	return err
}

// Account meters n body bytes; once the quota is used up it refuses further chunks.
func (g *gate) Account(n int, _ ingress.Direction) error {
	if g.st.meter == nil {
		return nil
	}
	if err := g.st.meter.Add(int64(n)); err != nil {
		g.e.m.QuotaExhausted.Inc("in_flight")
		g.e.mu.Lock()
		r := g.e.quotaRefusal(g.st)
		g.e.mu.Unlock()
		return r
	}
	return nil
}

func (g *gate) Release() {
	g.once.Do(func() {
		g.e.mu.Lock()
		g.st.inflight--
		g.e.mu.Unlock()
	})
}
