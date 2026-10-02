package policycache

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/127ohoh1/core/internal/clock"
	"github.com/127ohoh1/core/internal/observability"
	pp "github.com/127ohoh1/core/protocol/policy"
)

var t0 = time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)

func pol(id string, ver int64, st pp.State, validFor time.Duration) pp.EndpointPolicy {
	return pp.EndpointPolicy{EndpointID: id, PolicyVersion: ver, State: st,
		Limits:     pp.Limits{BandwidthBytesPerSecond: 100_000, BurstBytes: 200_000, MonthlyTransferBytes: 500_000_000, ConcurrentRequests: 128},
		Usage:      pp.Usage{PeriodStart: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), PeriodEnd: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)},
		Hostname:   pp.Hostname{Kind: "random"},
		ValidUntil: t0.Add(validFor)}
}

type fakeFetcher struct {
	mu      sync.Mutex
	pols    map[string]pp.EndpointPolicy
	down    bool
	calls   atomic.Int32
	block   chan struct{}
	feed    chan pp.Changes
	feedErr error
}

type httpErr int

func (e httpErr) Error() string   { return "http error" }
func (e httpErr) HTTPStatus() int { return int(e) }

func (f *fakeFetcher) Policy(ctx context.Context, id string) (pp.EndpointPolicy, error) {
	f.calls.Add(1)
	if f.block != nil {
		<-f.block
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return pp.EndpointPolicy{}, errors.New("connection refused")
	}
	p, ok := f.pols[id]
	if !ok {
		return pp.EndpointPolicy{}, httpErr(404)
	}
	return p, nil
}

func (f *fakeFetcher) PolicyChanges(ctx context.Context, since int64, wait time.Duration) (pp.Changes, error) {
	if f.feed == nil {
		<-ctx.Done()
		return pp.Changes{}, ctx.Err()
	}
	select {
	case c := <-f.feed:
		return c, f.feedErr
	case <-ctx.Done():
		return pp.Changes{}, ctx.Err()
	}
}

func (f *fakeFetcher) set(p pp.EndpointPolicy) { f.mu.Lock(); f.pols[p.EndpointID] = p; f.mu.Unlock() }
func (f *fakeFetcher) setDown(d bool)          { f.mu.Lock(); f.down = d; f.mu.Unlock() }

func newCache(grace time.Duration) (*Cache, *fakeFetcher, *clock.Fake, *observability.Registry) {
	clk := clock.NewFake(t0)
	f := &fakeFetcher{pols: map[string]pp.EndpointPolicy{}}
	reg := observability.NewRegistry()
	return New(Config{StaleGrace: grace, MissTimeout: time.Second}, f, clk, NewMetrics(reg), nil), f, clk, reg
}

func metric(reg *observability.Registry, line string) bool {
	var b bytes.Buffer
	reg.WriteText(&b)
	return strings.Contains(b.String(), line)
}

var bg = context.Background()

func TestLowerVersionNeverOverwritesHigher(t *testing.T) {
	c, _, _, reg := newCache(time.Minute)
	if !c.Put(pol("ep", 5, pp.StateActive, time.Minute)) {
		t.Fatal("initial put")
	}
	if c.Put(pol("ep", 4, pp.StateSuspended, time.Minute)) {
		t.Fatal("older version accepted")
	}
	e, _ := c.Get(bg, "ep")
	if e.Policy.PolicyVersion != 5 || e.Policy.State != pp.StateActive {
		t.Fatalf("%+v", e.Policy)
	}
	if !metric(reg, "edge_policy_rejected_lower_version_total 1") {
		t.Fatal("rejection not counted")
	}
	if !c.Put(pol("ep", 6, pp.StateSuspended, time.Minute)) {
		t.Fatal("higher version rejected")
	}
	if e, _ := c.Get(bg, "ep"); e.Policy.State != pp.StateSuspended {
		t.Fatal("suspension not applied on receipt")
	}
}

// Out-of-order delivery of the same version must not shorten validity or lower usage.
func TestEqualVersionMergesVolatileFields(t *testing.T) {
	c, _, _, _ := newCache(time.Minute)
	a := pol("ep", 3, pp.StateActive, 10*time.Minute)
	a.Usage.UsedBytes = 900
	older := pol("ep", 3, pp.StateActive, time.Minute)
	older.Usage.UsedBytes = 100
	c.Put(a)
	c.Put(older)
	e, _ := c.Get(bg, "ep")
	if !e.Policy.ValidUntil.Equal(t0.Add(10*time.Minute)) || e.Policy.Usage.UsedBytes != 900 {
		t.Fatalf("%+v", e.Policy)
	}
}

func TestFreshStaleExpiredAndFailClosed(t *testing.T) {
	c, _, clk, reg := newCache(5 * time.Minute)
	c.Put(pol("ep", 1, pp.StateActive, time.Minute))
	get := func() Status {
		e, err := c.Get(bg, "ep")
		if err != nil {
			t.Fatal(err)
		}
		return e.Status
	}
	if get() != Fresh {
		t.Fatal("fresh")
	}
	clk.Advance(time.Minute) // exactly at valid_until: no longer fresh
	if get() != Stale {
		t.Fatal("stale at valid_until")
	}
	if !metric(reg, "edge_policy_stale_use_total 1") {
		t.Fatal("stale use not counted")
	}
	clk.Advance(5*time.Minute - time.Second)
	if get() != Stale {
		t.Fatal("still within grace")
	}
	clk.Advance(time.Second)
	if get() != Expired {
		t.Fatal("expired after the grace window")
	}
}

func TestMissFetchesSingleFlightAndCaches(t *testing.T) {
	c, f, _, _ := newCache(time.Minute)
	f.set(pol("ep", 2, pp.StateActive, time.Minute))
	f.block = make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if e, err := c.Get(bg, "ep"); err != nil || e.Policy.PolicyVersion != 2 {
				t.Errorf("%v %+v", err, e)
			}
		}()
	}
	time.Sleep(50 * time.Millisecond)
	close(f.block)
	wg.Wait()
	if n := f.calls.Load(); n != 1 {
		t.Fatalf("%d fetches for 10 concurrent misses", n)
	}
	c.Get(bg, "ep")
	if f.calls.Load() != 1 {
		t.Fatal("second lookup must be a cache hit")
	}
}

func TestMissWhenControlPlaneDownIsUnavailableNotOpen(t *testing.T) {
	c, f, _, _ := newCache(time.Minute)
	f.setDown(true)
	if _, err := c.Get(bg, "ep"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("no cache + no control plane must not be permissive: %v", err)
	}
	f.setDown(false)
	if _, err := c.Get(bg, "ghost"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("404 must map to ErrNotFound: %v", err)
	}
}

func TestRefreshFailureKeepsEntry(t *testing.T) {
	c, f, _, reg := newCache(time.Minute)
	c.Put(pol("ep", 1, pp.StateActive, time.Minute))
	f.setDown(true)
	if err := c.Refresh(bg, "ep"); err == nil {
		t.Fatal("expected failure")
	}
	if e, err := c.Get(bg, "ep"); err != nil || e.Policy.PolicyVersion != 1 {
		t.Fatal("entry lost on failed refresh")
	}
	if !metric(reg, "edge_control_plane_reachable 0") || !metric(reg, "edge_policy_refresh_failures_total 1") {
		t.Fatal("outage not visible in metrics")
	}
	f.setDown(false)
	f.set(pol("ep", 2, pp.StateActive, 10*time.Minute))
	c.Refresh(bg, "ep")
	if !metric(reg, "edge_control_plane_reachable 1") {
		t.Fatal("recovery not visible")
	}
	if e, _ := c.Get(bg, "ep"); e.Policy.PolicyVersion != 2 {
		t.Fatal("refresh not applied")
	}
}

func TestOnChangeFiresForStateAndLimitChanges(t *testing.T) {
	c, _, _, _ := newCache(time.Minute)
	var mu sync.Mutex
	var seen []pp.State
	c.OnChange(func(old, cur pp.EndpointPolicy, had bool) { mu.Lock(); seen = append(seen, cur.State); mu.Unlock() })
	c.Put(pol("ep", 1, pp.StateActive, time.Minute))
	c.Put(pol("ep", 1, pp.StateActive, 2*time.Minute)) // volatile-only change at equal version: silent
	c.Put(pol("ep", 2, pp.StateSuspended, time.Minute))
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 2 || seen[0] != pp.StateActive || seen[1] != pp.StateSuspended {
		t.Fatalf("%v", seen)
	}
}

func TestInvalidPolicyRejected(t *testing.T) {
	c, _, _, _ := newCache(time.Minute)
	bad := pol("ep", 1, pp.StateActive, time.Minute)
	bad.Limits.BandwidthBytesPerSecond = 0
	if c.Put(bad) {
		t.Fatal("accepted an active policy with zero bandwidth")
	}
}

func TestChangeFeedTriggersRefresh(t *testing.T) {
	c, f, _, _ := newCache(time.Minute)
	f.feed = make(chan pp.Changes, 4)
	c.Put(pol("ep", 1, pp.StateActive, time.Hour))
	ctx, cancel := context.WithCancel(bg)
	done := make(chan struct{})
	go func() { c.Run(ctx); close(done) }()
	f.set(pol("ep", 2, pp.StateSuspended, time.Hour))
	f.feed <- pp.Changes{Seq: 1, Changes: []pp.Change{{Seq: 1, EndpointID: "ep", Version: 2}, {Seq: 1, EndpointID: "unrelated", Version: 9}}}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if e, _ := c.Get(bg, "ep"); e.Policy.State == pp.StateSuspended {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if e, _ := c.Get(bg, "ep"); e.Policy.State != pp.StateSuspended {
		t.Fatal("feed change not applied")
	}
	for _, id := range c.IDs() {
		if id == "unrelated" {
			t.Fatal("feed must not populate unrelated endpoints")
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not stop on cancel")
	}
}

func TestIdleEntriesEvicted(t *testing.T) {
	c, f, clk, _ := newCache(time.Minute)
	f.set(pol("ep", 1, pp.StateActive, time.Hour))
	c.Put(pol("ep", 1, pp.StateActive, time.Hour))
	clk.Advance(2 * time.Hour)
	c.RefreshAll(bg)
	if len(c.IDs()) != 0 {
		t.Fatal("idle entry not evicted")
	}
}
