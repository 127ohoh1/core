// Package policycache is the edge's local view of endpoint policy.
//
// Rules (ADR 0004):
//   - versions are monotonic: a lower version never overwrites a higher one;
//   - an entry is fresh until valid_until, then usable for StaleGrace (every
//     use is counted), then expired: new requests fail closed;
//   - a non-active state (suspended, released, expired) is applied the moment
//     it is received, at any version >= the cached one, and always takes
//     precedence over stale permissive entries;
//   - entries contain enforcement data only.
package policycache

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/127ohoh1/core/internal/clock"
	"github.com/127ohoh1/core/internal/observability"
	pp "github.com/127ohoh1/core/protocol/policy"
)

// Fetcher retrieves policy from the control plane.
type Fetcher interface {
	Policy(ctx context.Context, endpointID string) (pp.EndpointPolicy, error)
	PolicyChanges(ctx context.Context, since int64, wait time.Duration) (pp.Changes, error)
}

// Status is the freshness of an entry.
type Status int

const (
	Fresh   Status = iota
	Stale          // past valid_until but within the grace window (permissive, counted)
	Expired        // past grace: fail closed
)

func (s Status) String() string { return [...]string{"fresh", "stale", "expired"}[s] }

// Entry is a cached policy with its freshness.
type Entry struct {
	Policy pp.EndpointPolicy
	Status Status
}

// Errors.
var (
	ErrUnavailable = errors.New("policycache: policy unavailable")
	ErrNotFound    = errors.New("policycache: endpoint unknown to control plane")
)

// Config configures the cache.
type Config struct {
	StaleGrace    time.Duration
	Refresh       time.Duration // periodic refresh of entries in use
	MissTimeout   time.Duration
	IdleEvict     time.Duration // drop entries unused for this long
	FeedWait      time.Duration // change-feed long-poll duration
	MaxConcurrent int           // parallel refresh fetches
}

func (c *Config) defaults() {
	if c.Refresh <= 0 {
		c.Refresh = 30 * time.Second
	}
	if c.MissTimeout <= 0 {
		c.MissTimeout = 3 * time.Second
	}
	if c.IdleEvict <= 0 {
		c.IdleEvict = time.Hour
	}
	if c.FeedWait <= 0 {
		c.FeedWait = 20 * time.Second
	}
	if c.MaxConcurrent <= 0 {
		c.MaxConcurrent = 8
	}
}

// Metrics observed by the cache.
type Metrics struct {
	Requests        *observability.Counter // edge_policy_cache_requests_total{result=hit|miss|stale|expired}
	StaleUse        *observability.Counter // edge_policy_stale_use_total
	RejectedOld     *observability.Counter // edge_policy_rejected_lower_version_total
	RefreshFailures *observability.Counter // edge_policy_refresh_failures_total
	Entries         *observability.Gauge   // edge_policy_cache_entries
	MaxVersion      *observability.Gauge   // edge_policy_max_version
	CPReachable     *observability.Gauge   // edge_control_plane_reachable
}

// NewMetrics registers cache metrics.
func NewMetrics(r *observability.Registry) Metrics {
	return Metrics{
		Requests:        r.Counter("edge_policy_cache_requests_total", "Policy cache lookups by result.", "result"),
		StaleUse:        r.Counter("edge_policy_stale_use_total", "Requests served from a policy past valid_until (within grace)."),
		RejectedOld:     r.Counter("edge_policy_rejected_lower_version_total", "Policies rejected because a higher version is cached."),
		RefreshFailures: r.Counter("edge_policy_refresh_failures_total", "Failed policy refreshes."),
		Entries:         r.Gauge("edge_policy_cache_entries", "Cached endpoint policies."),
		MaxVersion:      r.Gauge("edge_policy_max_version", "Highest policy version seen."),
		CPReachable:     r.Gauge("edge_control_plane_reachable", "1 if the last control-plane policy call succeeded."),
	}
}

type entry struct {
	p        pp.EndpointPolicy
	lastUsed time.Time
}

// Cache is the policy cache.
type Cache struct {
	cfg Config
	f   Fetcher
	clk clock.Clock
	m   Metrics
	log func(msg string, kv ...any)

	mu       sync.Mutex
	entries  map[string]*entry
	inflight map[string]*call
	onChange func(old, cur pp.EndpointPolicy, hadOld bool)
	maxVer   int64
}

type call struct {
	done chan struct{}
	p    pp.EndpointPolicy
	err  error
}

// New builds a Cache. log may be nil.
func New(cfg Config, f Fetcher, clk clock.Clock, m Metrics, log func(string, ...any)) *Cache {
	cfg.defaults()
	if log == nil {
		log = func(string, ...any) {}
	}
	return &Cache{cfg: cfg, f: f, clk: clk, m: m, log: log, entries: map[string]*entry{}, inflight: map[string]*call{}}
}

// OnChange registers a callback invoked (outside locks) whenever an accepted
// update changes state or limits. The edge uses it to terminate tunnels of
// endpoints that are no longer allowed.
func (c *Cache) OnChange(f func(old, cur pp.EndpointPolicy, hadOld bool)) {
	c.mu.Lock()
	c.onChange = f
	c.mu.Unlock()
}

func (c *Cache) status(p pp.EndpointPolicy, now time.Time) Status {
	switch {
	case now.Before(p.ValidUntil):
		return Fresh
	case now.Before(p.ValidUntil.Add(c.cfg.StaleGrace)):
		return Stale
	}
	return Expired
}

// Put offers a policy to the cache and reports whether it was accepted.
func (c *Cache) Put(p pp.EndpointPolicy) bool {
	if err := p.Validate(); err != nil {
		return false
	}
	c.mu.Lock()
	cur, had := c.entries[p.EndpointID]
	var old pp.EndpointPolicy
	if had {
		old = cur.p
		if p.PolicyVersion < old.PolicyVersion {
			c.mu.Unlock()
			c.m.RejectedOld.Inc()
			return false
		}
	}
	now := c.clk.Now()
	if had && p.PolicyVersion == old.PolicyVersion {
		// Same enforcement inputs: an older fetch racing a newer one must not
		// shorten validity or lower the known usage.
		if old.ValidUntil.After(p.ValidUntil) {
			p.ValidUntil = old.ValidUntil
		}
		if old.Usage.PeriodStart.Equal(p.Usage.PeriodStart) && old.Usage.UsedBytes > p.Usage.UsedBytes {
			p.Usage.UsedBytes = old.Usage.UsedBytes
		}
	}
	if !had {
		c.entries[p.EndpointID] = &entry{p: p, lastUsed: now}
	} else {
		cur.p = p
	}
	if p.PolicyVersion > c.maxVer {
		c.maxVer = p.PolicyVersion
	}
	n, mv, cb := len(c.entries), c.maxVer, c.onChange
	c.mu.Unlock()
	c.m.Entries.Set(float64(n))
	c.m.MaxVersion.Set(float64(mv))
	if cb != nil && (!had || old.State != p.State || old.Limits != p.Limits || old.PolicyVersion != p.PolicyVersion) {
		cb(old, p, had)
	}
	return true
}

// Get returns the policy for an endpoint, fetching it on a miss (single
// flight, bounded by MissTimeout).
func (c *Cache) Get(ctx context.Context, id string) (Entry, error) {
	now := c.clk.Now()
	c.mu.Lock()
	if e, ok := c.entries[id]; ok {
		e.lastUsed = now
		st := c.status(e.p, now)
		p := e.p
		c.mu.Unlock()
		switch st {
		case Fresh:
			c.m.Requests.Inc("hit")
		case Stale:
			c.m.Requests.Inc("stale")
			c.m.StaleUse.Inc() // an operator-visible signal that the control plane is not refreshing us
		default:
			c.m.Requests.Inc("expired")
		}
		return Entry{Policy: p, Status: st}, nil
	}
	c.mu.Unlock()
	c.m.Requests.Inc("miss")
	p, err := c.fetchOnce(ctx, id)
	if err != nil {
		return Entry{}, err
	}
	return Entry{Policy: p, Status: c.status(p, c.clk.Now())}, nil
}

func (c *Cache) fetchOnce(ctx context.Context, id string) (pp.EndpointPolicy, error) {
	c.mu.Lock()
	if cl, ok := c.inflight[id]; ok {
		c.mu.Unlock()
		select {
		case <-cl.done:
			return cl.p, cl.err
		case <-ctx.Done():
			return pp.EndpointPolicy{}, ctx.Err()
		}
	}
	cl := &call{done: make(chan struct{})}
	c.inflight[id] = cl
	c.mu.Unlock()

	fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), c.cfg.MissTimeout)
	p, err := c.f.Policy(fctx, id)
	cancel()
	if err != nil {
		c.m.RefreshFailures.Inc()
		c.m.CPReachable.Set(0)
		err = wrapFetchErr(err)
	} else {
		c.m.CPReachable.Set(1)
		c.Put(p)
		// Return what the cache now holds: a concurrent newer update may have won.
		c.mu.Lock()
		if e, ok := c.entries[id]; ok {
			p = e.p
		}
		c.mu.Unlock()
	}
	cl.p, cl.err = p, err
	c.mu.Lock()
	delete(c.inflight, id)
	c.mu.Unlock()
	close(cl.done)
	return p, err
}

// StatusError lets fetchers signal a definitive "not found".
type StatusError interface{ HTTPStatus() int }

func wrapFetchErr(err error) error {
	var se StatusError
	if errors.As(err, &se) && se.HTTPStatus() == 404 {
		return ErrNotFound
	}
	return errors.Join(ErrUnavailable, err)
}

// Forget removes an entry.
func (c *Cache) Forget(id string) {
	c.mu.Lock()
	delete(c.entries, id)
	n := len(c.entries)
	c.mu.Unlock()
	c.m.Entries.Set(float64(n))
}

// IDs returns the cached endpoint ids.
func (c *Cache) IDs() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, 0, len(c.entries))
	for id := range c.entries {
		out = append(out, id)
	}
	return out
}

// Refresh re-fetches one endpoint. On failure the cached entry is kept (that
// is the whole point of the bounded stale grace).
func (c *Cache) Refresh(ctx context.Context, id string) error {
	rctx, cancel := context.WithTimeout(ctx, c.cfg.MissTimeout+2*time.Second)
	defer cancel()
	p, err := c.f.Policy(rctx, id)
	if err != nil {
		c.m.RefreshFailures.Inc()
		c.m.CPReachable.Set(0)
		return err
	}
	c.m.CPReachable.Set(1)
	c.Put(p)
	return nil
}

// RefreshAll refreshes every entry with bounded parallelism and evicts idle
// ones.
func (c *Cache) RefreshAll(ctx context.Context) {
	now := c.clk.Now()
	var ids []string
	c.mu.Lock()
	for id, e := range c.entries {
		if now.Sub(e.lastUsed) > c.cfg.IdleEvict {
			delete(c.entries, id)
			continue
		}
		ids = append(ids, id)
	}
	c.m.Entries.Set(float64(len(c.entries)))
	c.mu.Unlock()
	sem := make(chan struct{}, c.cfg.MaxConcurrent)
	var wg sync.WaitGroup
	for _, id := range ids {
		sem <- struct{}{}
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			defer func() { <-sem }()
			_ = c.Refresh(ctx, id)
		}(id)
	}
	wg.Wait()
}

// Run drives the periodic refresh and the change-feed watcher until ctx ends.
func (c *Cache) Run(ctx context.Context) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case <-c.clk.After(c.cfg.Refresh):
				c.RefreshAll(ctx)
			}
		}
	}()
	go func() { defer wg.Done(); c.watch(ctx) }()
	wg.Wait()
}

func (c *Cache) watch(ctx context.Context) {
	var since int64
	backoff := time.Second
	for ctx.Err() == nil {
		ch, err := c.f.PolicyChanges(ctx, since, c.cfg.FeedWait)
		if err != nil {
			c.m.CPReachable.Set(0)
			c.log("policy.feed_error", "err", err.Error())
			select {
			case <-ctx.Done():
				return
			case <-c.clk.After(backoff):
			}
			if backoff < 10*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = time.Second
		c.m.CPReachable.Set(1)
		if ch.Reset {
			c.RefreshAll(ctx)
		}
		for _, chg := range ch.Changes {
			c.mu.Lock()
			e, ok := c.entries[chg.EndpointID]
			need := ok && chg.Version > e.p.PolicyVersion
			c.mu.Unlock()
			if need {
				_ = c.Refresh(ctx, chg.EndpointID)
			}
		}
		since = ch.Seq
	}
}
