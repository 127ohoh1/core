package policy

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/127ohoh1/core/controlplane/endpoint"
	"github.com/127ohoh1/core/controlplane/identity"
	"github.com/127ohoh1/core/internal/clock"
	pp "github.com/127ohoh1/core/protocol/policy"
)

// Default per-request limits of the reference release.
const (
	DefaultConcurrentRequests  = 128
	DefaultMaxHeaderBytes      = 32768
	DefaultMaxRequestBodyBytes = 104857600
)

// MonthPeriod returns the UTC calendar-month period containing t. A "month"
// is always an explicit [start, end) pair, never a fixed number of seconds.
func MonthPeriod(t time.Time) (start, end time.Time) {
	t = t.UTC()
	start = time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC)
	return start, start.AddDate(0, 1, 0)
}

// UsageReader supplies the authoritative used bytes for a period.
type UsageReader interface {
	Used(ctx context.Context, endpointID string, periodStart time.Time) (int64, error)
}

// NoUsage reports zero usage (before a ledger is wired).
type NoUsage struct{}

func (NoUsage) Used(context.Context, string, time.Time) (int64, error) { return 0, nil }

// EntitlementLookup finds the active paid entitlement for a reserved name.
// The policy layer needs only the plan id; entitlement mechanics live in the
// entitlement package.
type EntitlementLookup interface {
	ActivePlan(ctx context.Context, principalID, name string, at time.Time) (planID string, ok bool, err error)
}

// PolicyResolver resolves the current policy inputs for an endpoint
// (spec section 11.2).
type PolicyResolver interface {
	ResolveEndpointPolicy(ctx context.Context, endpointID string, at time.Time) (pp.EndpointPolicy, error)
}

// Resolver combines lifecycle, entitlement and usage into an EndpointPolicy
// (without a version: versions are assigned by the Publisher).
//
// Precedence, highest first:
//  1. emergency global override
//  2. principal suspension / revocation
//  3. endpoint lifecycle state (suspended, expired, released, pending)
//  4. active entitlement and plan limits
//  5. current usage / quota state
//  6. safe defaults (free plan for random names)
type Resolver struct {
	Catalog      *Catalog
	Endpoints    *endpoint.Service
	Principals   *identity.Service
	Entitlements EntitlementLookup // may be nil (no paid plans wired)
	Usage        UsageReader
	Clock        clock.Clock
	TTL          time.Duration // policy validity window
	FreeInactive time.Duration

	emergency atomic.Bool
}

// SetEmergencyDeny toggles the global safety override: every endpoint
// resolves to suspended until cleared.
func (r *Resolver) SetEmergencyDeny(on bool) { r.emergency.Store(on) }

// EmergencyDeny reports the override state.
func (r *Resolver) EmergencyDeny() bool { return r.emergency.Load() }

// ErrNoEndpoint is returned for unknown endpoints.
var ErrNoEndpoint = errors.New("policy: endpoint not found")

func limitsFor(p Plan) pp.Limits {
	return pp.Limits{
		BandwidthBytesPerSecond: p.BandwidthBytesPerSecond,
		BurstBytes:              BurstSeconds * p.BandwidthBytesPerSecond,
		MonthlyTransferBytes:    p.MonthlyTransferBytes,
		ConcurrentRequests:      DefaultConcurrentRequests,
		MaxRequestHeaderBytes:   DefaultMaxHeaderBytes,
		MaxRequestBodyBytes:     DefaultMaxRequestBodyBytes,
	}
}

func (r *Resolver) ResolveEndpointPolicy(ctx context.Context, endpointID string, at time.Time) (pp.EndpointPolicy, error) {
	ep, err := r.Endpoints.GetByID(ctx, endpointID)
	if err != nil {
		return pp.EndpointPolicy{}, ErrNoEndpoint
	}
	start, end := MonthPeriod(at)
	free, _ := r.Catalog.Get(PlanFree)
	pol := pp.EndpointPolicy{
		EndpointID: ep.ID, State: pp.StateActive, Limits: limitsFor(free),
		Usage:      pp.Usage{PeriodStart: start, PeriodEnd: end},
		Hostname:   pp.Hostname{Kind: string(ep.Kind)},
		ValidUntil: minTime(at.Add(r.TTL), end),
	}
	if ep.Kind == endpoint.KindRandom {
		secs := int64(r.FreeInactive / time.Second)
		pol.Hostname.InactiveExpirySecond = &secs
	}

	// Plan selection: reserved names take their limits from the entitlement.
	plan := free
	entitled := true
	if ep.Kind == endpoint.KindReserved {
		entitled = false
		if r.Entitlements != nil {
			id, ok, err := r.Entitlements.ActivePlan(ctx, ep.PrincipalID, ep.Hostname, at)
			if err != nil {
				return pp.EndpointPolicy{}, err
			}
			if ok {
				if p, err := r.Catalog.Get(id); err == nil {
					plan, entitled = p, true
					pol.Limits = limitsFor(p)
				}
			}
		}
	}

	used, err := r.Usage.Used(ctx, ep.ID, start)
	if err != nil {
		return pp.EndpointPolicy{}, err
	}
	pol.Usage.UsedBytes = used
	_ = plan

	// Apply the precedence ladder from the top: the first matching rule wins.
	switch {
	case r.emergency.Load():
		pol.State = pp.StateSuspended
	case r.principalSuspended(ctx, ep.PrincipalID):
		pol.State = pp.StateSuspended
	case ep.State == endpoint.StateSuspended:
		pol.State = pp.StateSuspended
	case ep.State == endpoint.StateReleased:
		pol.State = pp.StateReleased
	case ep.State == endpoint.StateExpired:
		pol.State = pp.StateExpired
	case ep.State == endpoint.StatePending:
		pol.State = pp.StatePending
	case !entitled:
		pol.State = pp.StateExpired // reserved name without an active entitlement
	}
	return pol, nil
}

func (r *Resolver) principalSuspended(ctx context.Context, id string) bool {
	if r.Principals == nil {
		return false
	}
	p, err := r.Principals.Principal(ctx, id)
	return err == nil && p.State != identity.PrincipalActive
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// ---- publisher -------------------------------------------------------------

// PolicyPublisher publishes versioned policy snapshots and a change feed.
type PolicyPublisher interface {
	// Current returns the latest snapshot, refreshing volatile fields
	// (usage, valid_until) and bumping the version only if enforcement-relevant
	// state changed.
	Current(ctx context.Context, endpointID string) (pp.EndpointPolicy, error)
	// Recompute re-resolves after an input changed and publishes a change if needed.
	Recompute(ctx context.Context, endpointID string)
	// Changes long-polls the change feed.
	Changes(ctx context.Context, since int64, wait time.Duration) pp.Changes
}

// enforcementKey holds exactly the fields whose change must bump the version.
// Volatile fields (used_bytes, valid_until) are excluded; quota exhaustion is
// included so all edges learn about it promptly.
type enforcementKey struct {
	State     pp.State
	Limits    pp.Limits
	Kind      string
	Expiry    int64
	PeriodBeg time.Time
	Exhausted bool
}

func keyOf(p pp.EndpointPolicy) enforcementKey {
	k := enforcementKey{State: p.State, Limits: p.Limits, Kind: p.Hostname.Kind, PeriodBeg: p.Usage.PeriodStart,
		Exhausted: p.Limits.MonthlyTransferBytes > 0 && p.Usage.UsedBytes >= p.Limits.MonthlyTransferBytes}
	if p.Hostname.InactiveExpirySecond != nil {
		k.Expiry = *p.Hostname.InactiveExpirySecond
	}
	return k
}

const feedSize = 8192

// Publisher is the in-memory development PolicyPublisher. Snapshots are
// immutable; only their version counter and the feed are stored.
type Publisher struct {
	res *Resolver
	clk clock.Clock

	mu      sync.Mutex
	last    map[string]snapshot
	seq     int64
	feed    []pp.Change // ring: entries with seq in (seq-len, seq]
	waiters []chan struct{}
	// OnPublish is called (outside locks) for every published version bump.
	OnPublish func(p pp.EndpointPolicy)
}

type snapshot struct {
	key     enforcementKey
	version int64
}

// NewPublisher builds a Publisher.
func NewPublisher(res *Resolver, clk clock.Clock) *Publisher {
	return &Publisher{res: res, clk: clk, last: map[string]snapshot{}}
}

func (p *Publisher) resolve(ctx context.Context, id string) (pp.EndpointPolicy, bool, error) {
	now := p.clk.Now()
	pol, err := p.res.ResolveEndpointPolicy(ctx, id, now)
	if err != nil {
		return pp.EndpointPolicy{}, false, err
	}
	k := keyOf(pol)
	p.mu.Lock()
	prev, seen := p.last[id]
	bumped := false
	if !seen || prev.key != k {
		prev.version++
		prev.key = k
		p.last[id] = prev
		bumped = true
		p.seq++
		if len(p.feed) >= feedSize {
			p.feed = append(p.feed[:0], p.feed[len(p.feed)-feedSize+1:]...)
		}
		p.feed = append(p.feed, pp.Change{Seq: p.seq, EndpointID: id, Version: prev.version})
		for _, w := range p.waiters {
			close(w)
		}
		p.waiters = nil
	}
	pol.PolicyVersion = prev.version
	p.mu.Unlock()
	return pol, bumped, nil
}

func (p *Publisher) Current(ctx context.Context, id string) (pp.EndpointPolicy, error) {
	pol, bumped, err := p.resolve(ctx, id)
	if bumped && p.OnPublish != nil {
		p.OnPublish(pol)
	}
	return pol, err
}

func (p *Publisher) Recompute(ctx context.Context, id string) { _, _ = p.Current(ctx, id) }

// RecomputePrincipal re-resolves every live endpoint of a principal (used
// after principal suspension/restoration).
func (p *Publisher) RecomputePrincipal(ctx context.Context, eps *endpoint.Service, principalID string) {
	es, err := eps.ListAll(ctx, principalID)
	if err != nil {
		return
	}
	for _, e := range es {
		p.Recompute(ctx, e.ID)
	}
}

// RecomputeAll re-resolves every known endpoint (emergency override, catalog change).
func (p *Publisher) RecomputeAll(ctx context.Context, _ *endpoint.Service) {
	p.mu.Lock()
	ids := make([]string, 0, len(p.last))
	for id := range p.last {
		ids = append(ids, id)
	}
	p.mu.Unlock()
	for _, id := range ids {
		p.Recompute(ctx, id)
	}
}

func (p *Publisher) Changes(ctx context.Context, since int64, wait time.Duration) pp.Changes {
	for {
		p.mu.Lock()
		if p.seq > since {
			out := pp.Changes{Seq: p.seq}
			if len(p.feed) == 0 || since < p.feed[0].Seq-1 {
				out.Reset = true // consumer fell out of the ring
			} else {
				for _, c := range p.feed {
					if c.Seq > since {
						out.Changes = append(out.Changes, c)
					}
				}
			}
			p.mu.Unlock()
			return out
		}
		if since > p.seq { // consumer is ahead of us (control plane restarted): resync
			out := pp.Changes{Seq: p.seq, Reset: true}
			p.mu.Unlock()
			return out
		}
		ch := make(chan struct{})
		p.waiters = append(p.waiters, ch)
		seq := p.seq
		p.mu.Unlock()
		if wait <= 0 {
			return pp.Changes{Seq: seq}
		}
		t := time.NewTimer(wait)
		select {
		case <-ch:
			t.Stop()
			wait = 0 // re-check once, do not wait again
			// loop returns the new changes; if a spurious wake found none, return empty
			p.mu.Lock()
			has := p.seq > since
			s := p.seq
			p.mu.Unlock()
			if !has {
				return pp.Changes{Seq: s}
			}
		case <-t.C:
			return pp.Changes{Seq: seq}
		case <-ctx.Done():
			t.Stop()
			return pp.Changes{Seq: seq}
		}
	}
}
