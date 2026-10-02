package policy

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/127ohoh1/core/controlplane/endpoint"
	"github.com/127ohoh1/core/controlplane/identity"
	"github.com/127ohoh1/core/internal/clock"
	"github.com/127ohoh1/core/internal/ids"
	pp "github.com/127ohoh1/core/protocol/policy"
)

// The exact table from the specification, section 3. These literals are
// intentionally NOT derived from the constants under test.
func TestCanonicalPlansExact(t *testing.T) {
	want := []struct {
		id, price string
		bps, mo   int64
		host      string
	}{
		{"free", "0", 100_000, 500_000_000, "random"},
		{"tier_1", "1", 1_000_000, 10_000_000_000, "reserved"},
		{"tier_2", "2", 3_000_000, 100_000_000_000, "reserved"},
		{"tier_3", "4", 5_000_000, 500_000_000_000, "reserved"},
	}
	c := DefaultCatalog()
	if len(c.List()) != len(want) {
		t.Fatalf("catalog has %d plans", len(c.List()))
	}
	for _, w := range want {
		p, err := c.Get(w.id)
		if err != nil {
			t.Fatal(err)
		}
		if p.PriceAmount != w.price || p.PriceAsset != "USDC" || p.Interval != "month" || p.Unit != "name" ||
			p.BandwidthBytesPerSecond != w.bps || p.MonthlyTransferBytes != w.mo || p.HostnameKind != w.host {
			t.Errorf("%s: %+v", w.id, p)
		}
		if l := limitsFor(p); l.BurstBytes != 2*w.bps || l.BandwidthBytesPerSecond != w.bps || l.MonthlyTransferBytes != w.mo {
			t.Errorf("%s limits: %+v", w.id, l)
		}
	}
	if got := []string{c.List()[0].ID, c.List()[1].ID, c.List()[2].ID, c.List()[3].ID}; strings.Join(got, ",") != "free,tier_1,tier_2,tier_3" {
		t.Errorf("order %v", got)
	}
	if _, err := c.Get("tier_9"); err == nil {
		t.Error("unknown plan accepted")
	}
}

func TestMonthPeriodBoundaries(t *testing.T) {
	cases := []struct {
		in, start, end string
	}{
		{"2026-09-21T12:00:00Z", "2026-09-01T00:00:00Z", "2026-10-01T00:00:00Z"},
		{"2026-09-01T00:00:00Z", "2026-09-01T00:00:00Z", "2026-10-01T00:00:00Z"},
		{"2026-09-30T23:59:59.999999999Z", "2026-09-01T00:00:00Z", "2026-10-01T00:00:00Z"},
		{"2026-12-31T23:59:59Z", "2026-12-01T00:00:00Z", "2027-01-01T00:00:00Z"},
		{"2028-02-29T10:00:00Z", "2028-02-01T00:00:00Z", "2028-03-01T00:00:00Z"}, // leap year
		{"2026-02-15T00:00:00+05:00", "2026-02-14T00:00:00Z", ""},                // zone-normalised to UTC (see below)
	}
	for _, c := range cases[:5] {
		in, _ := time.Parse(time.RFC3339Nano, c.in)
		s, e := MonthPeriod(in)
		if s.Format(time.RFC3339) != c.start || e.Format(time.RFC3339) != c.end {
			t.Errorf("%s: %v %v", c.in, s, e)
		}
	}
	// A local time late on the 31st in a UTC+ zone belongs to the UTC month.
	loc := time.FixedZone("x", 5*3600)
	s, _ := MonthPeriod(time.Date(2026, 10, 1, 2, 0, 0, 0, loc)) // = 2026-09-30T21:00Z
	if s.Month() != time.September {
		t.Errorf("period not computed in UTC: %v", s)
	}
}

type fx struct {
	res  *Resolver
	pub  *Publisher
	eps  *endpoint.Service
	clk  *clock.Fake
	used map[string]int64
	ent  map[string]string // "principal/name" -> plan
	mu   sync.Mutex
}

func (f *fx) Used(_ context.Context, id string, _ time.Time) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.used[id], nil
}

func (f *fx) ActivePlan(_ context.Context, pr, name string, _ time.Time) (string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.ent[pr+"/"+name]
	return p, ok, nil
}

func newFx(t *testing.T) *fx {
	f := &fx{clk: clock.NewFake(time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)), used: map[string]int64{}, ent: map[string]string{}}
	f.eps = endpoint.NewService(endpoint.Config{MaxRandomPerPrincipal: 5, Tombstone: time.Hour, FreeInactivity: 24 * time.Hour},
		endpoint.NewInMemory(), endpoint.NewRandomAllocator(nil), nil, f.clk, ids.New(f.clk))
	f.res = &Resolver{Catalog: DefaultCatalog(), Endpoints: f.eps, Usage: f, Entitlements: f, Clock: f.clk, TTL: 5 * time.Minute, FreeInactive: 24 * time.Hour}
	f.pub = NewPublisher(f.res, f.clk)
	f.eps.OnChange = func(ctx context.Context, id string) { f.pub.Recompute(ctx, id) }
	return f
}

var bg = context.Background()

func TestFreePolicyMatchesSpecExample(t *testing.T) {
	f := newFx(t)
	e, _ := f.eps.CreateRandom(bg, "pr_1")
	p, err := f.pub.Current(bg, e.ID)
	if err != nil {
		t.Fatal(err)
	}
	if p.State != pp.StateActive || p.Limits.BandwidthBytesPerSecond != 100_000 || p.Limits.BurstBytes != 200_000 ||
		p.Limits.MonthlyTransferBytes != 500_000_000 || p.Limits.ConcurrentRequests != 128 ||
		p.Limits.MaxRequestHeaderBytes != 32768 || p.Limits.MaxRequestBodyBytes != 104857600 {
		t.Fatalf("%+v", p)
	}
	if !p.Usage.PeriodStart.Equal(time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)) || !p.Usage.PeriodEnd.Equal(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("period %v-%v", p.Usage.PeriodStart, p.Usage.PeriodEnd)
	}
	if p.Hostname.Kind != "random" || p.Hostname.InactiveExpirySecond == nil || *p.Hostname.InactiveExpirySecond != 86400 {
		t.Fatalf("hostname %+v", p.Hostname)
	}
	if !p.ValidUntil.Equal(f.clk.Now().Add(5 * time.Minute)) {
		t.Fatalf("valid_until %v", p.ValidUntil)
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
}

// valid_until never extends past the period end, so an edge always refreshes
// (and re-reads usage) at the month boundary.
func TestValidUntilCappedAtPeriodEnd(t *testing.T) {
	f := newFx(t)
	e, _ := f.eps.CreateRandom(bg, "pr_1")
	f.clk.Advance(9*24*time.Hour + 11*time.Hour + 58*time.Minute) // 2 minutes before Oct 1 00:00 UTC
	p, _ := f.pub.Current(bg, e.ID)
	if !p.ValidUntil.Equal(p.Usage.PeriodEnd) {
		t.Fatalf("valid_until %v, period end %v", p.ValidUntil, p.Usage.PeriodEnd)
	}
}

func TestReservedTiersResolveExactLimits(t *testing.T) {
	f := newFx(t)
	cases := map[string][3]int64{
		"tier_1": {1_000_000, 2_000_000, 10_000_000_000},
		"tier_2": {3_000_000, 6_000_000, 100_000_000_000},
		"tier_3": {5_000_000, 10_000_000, 500_000_000_000},
	}
	i := 0
	for plan, w := range cases {
		i++
		name := "paid-name-" + string(rune('a'+i))
		e, err := f.eps.CreateReserved(bg, "pr_1", name)
		if err != nil {
			t.Fatal(err)
		}
		f.mu.Lock()
		f.ent["pr_1/"+name] = plan
		f.mu.Unlock()
		p, _ := f.pub.Current(bg, e.ID)
		if p.State != pp.StateActive || p.Limits.BandwidthBytesPerSecond != w[0] || p.Limits.BurstBytes != w[1] || p.Limits.MonthlyTransferBytes != w[2] {
			t.Errorf("%s: %+v", plan, p.Limits)
		}
		if p.Hostname.Kind != "reserved" || p.Hostname.InactiveExpirySecond != nil {
			t.Errorf("%s hostname %+v", plan, p.Hostname)
		}
	}
}

func TestPrecedenceLadder(t *testing.T) {
	f := newFx(t)
	pr := &identity.Principal{}
	_ = pr
	e, _ := f.eps.CreateReserved(bg, "pr_1", "myproject")
	f.ent["pr_1/myproject"] = "tier_3"
	if p, _ := f.pub.Current(bg, e.ID); p.State != pp.StateActive {
		t.Fatal("baseline")
	}
	// Suspension beats an otherwise permissive entitlement.
	f.eps.Suspend(bg, e.ID)
	if p, _ := f.pub.Current(bg, e.ID); p.State != pp.StateSuspended {
		t.Fatalf("suspension must win over entitlement: %s", p.State)
	}
	f.eps.Unsuspend(bg, e.ID)
	// Entitlement lapse -> expired, even though the endpoint row is still ACTIVE.
	delete(f.ent, "pr_1/myproject")
	if p, _ := f.pub.Current(bg, e.ID); p.State != pp.StateExpired {
		t.Fatalf("no entitlement must expire: %s", p.State)
	}
	f.ent["pr_1/myproject"] = "tier_1"
	if p, _ := f.pub.Current(bg, e.ID); p.State != pp.StateActive || p.Limits.BandwidthBytesPerSecond != 1_000_000 {
		t.Fatal("re-entitled")
	}
	// Emergency override beats everything, including a healthy entitled endpoint.
	f.res.SetEmergencyDeny(true)
	if p, _ := f.pub.Current(bg, e.ID); p.State != pp.StateSuspended {
		t.Fatalf("emergency override: %s", p.State)
	}
	f.res.SetEmergencyDeny(false)
	f.eps.Release(bg, "pr_1", e.ID)
	if p, _ := f.pub.Current(bg, e.ID); p.State != pp.StateReleased {
		t.Fatalf("released: %s", p.State)
	}
}

func TestVersionsMonotonicAndBumpOnlyOnEnforcementChange(t *testing.T) {
	f := newFx(t)
	e, _ := f.eps.CreateRandom(bg, "pr_1")
	p1, _ := f.pub.Current(bg, e.ID)
	// Usage growth and time passing do not bump the version (volatile fields).
	f.used[e.ID] = 1234
	f.clk.Advance(time.Minute)
	p2, _ := f.pub.Current(bg, e.ID)
	if p2.PolicyVersion != p1.PolicyVersion || p2.Usage.UsedBytes != 1234 {
		t.Fatalf("v %d -> %d, used %d", p1.PolicyVersion, p2.PolicyVersion, p2.Usage.UsedBytes)
	}
	// Quota exhaustion is enforcement-relevant.
	f.used[e.ID] = 500_000_000
	p3, _ := f.pub.Current(bg, e.ID)
	if p3.PolicyVersion != p2.PolicyVersion+1 {
		t.Fatalf("exhaustion did not bump: %d -> %d", p2.PolicyVersion, p3.PolicyVersion)
	}
	f.eps.Suspend(bg, e.ID)
	p4, _ := f.pub.Current(bg, e.ID)
	f.eps.Unsuspend(bg, e.ID)
	p5, _ := f.pub.Current(bg, e.ID)
	if !(p4.PolicyVersion > p3.PolicyVersion && p5.PolicyVersion > p4.PolicyVersion) {
		t.Fatalf("versions not monotonic: %d %d %d", p3.PolicyVersion, p4.PolicyVersion, p5.PolicyVersion)
	}
	// Month rollover changes the period => new version, usage restarts.
	f.clk.Advance(10 * 24 * time.Hour)
	f.used[e.ID] = 0
	p6, _ := f.pub.Current(bg, e.ID)
	if p6.PolicyVersion <= p5.PolicyVersion || p6.Usage.PeriodStart.Month() != time.October {
		t.Fatalf("rollover: %+v", p6)
	}
}

func TestChangeFeed(t *testing.T) {
	f := newFx(t)
	e1, _ := f.eps.CreateRandom(bg, "pr_1") // OnChange -> version 1 published
	seq0 := f.pub.Changes(bg, 0, 0).Seq
	if seq0 < 1 {
		t.Fatalf("no change published for creation: %d", seq0)
	}
	// Long poll wakes on a change.
	got := make(chan pp.Changes, 1)
	go func() { got <- f.pub.Changes(bg, seq0, 5*time.Second) }()
	time.Sleep(50 * time.Millisecond)
	f.eps.Suspend(bg, e1.ID)
	select {
	case c := <-got:
		if len(c.Changes) != 1 || c.Changes[0].EndpointID != e1.ID || c.Changes[0].Version < 2 || c.Reset {
			t.Fatalf("%+v", c)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("long poll did not wake")
	}
	// Timeout returns empty at the same sequence.
	c := f.pub.Changes(bg, f.pub.Changes(bg, 0, 0).Seq, 50*time.Millisecond)
	if len(c.Changes) != 0 || c.Reset {
		t.Fatalf("%+v", c)
	}
	// A consumer ahead of the server (control plane restarted) must resync.
	if c := f.pub.Changes(bg, 9999, 0); !c.Reset {
		t.Fatal("consumer ahead of feed must be told to reset")
	}
}

func TestFeedOverflowForcesReset(t *testing.T) {
	f := newFx(t)
	e, _ := f.eps.CreateRandom(bg, "pr_1")
	for i := 0; i < feedSize+10; i++ {
		f.used[e.ID] = int64(i%2) * 500_000_000 // flips exhaustion each time
		f.pub.Current(bg, e.ID)
	}
	if c := f.pub.Changes(bg, 0, 0); !c.Reset {
		t.Fatal("stale consumer must be told to refresh everything")
	}
}

func TestPolicyCarriesNoCommercialFields(t *testing.T) {
	f := newFx(t)
	e, _ := f.eps.CreateReserved(bg, "pr_1", "myproject")
	f.ent["pr_1/myproject"] = "tier_2"
	p, _ := f.pub.Current(bg, e.ID)
	b, _ := json.Marshal(p)
	for _, forbidden := range []string{"price", "usdc", "asset", "wallet", "transaction", "subscription", "payment", "tier", "plan", "invoice", "amount", "settle"} {
		if strings.Contains(strings.ToLower(string(b)), forbidden) {
			t.Errorf("policy JSON leaks commercial concept %q: %s", forbidden, b)
		}
	}
}

func TestPolicyValidateRejectsNonsense(t *testing.T) {
	f := newFx(t)
	e, _ := f.eps.CreateRandom(bg, "pr_1")
	good, _ := f.pub.Current(bg, e.ID)
	mut := []func(*pp.EndpointPolicy){
		func(p *pp.EndpointPolicy) { p.State = "bogus" },
		func(p *pp.EndpointPolicy) { p.Limits.BandwidthBytesPerSecond = 0 }, // active with zero rate
		func(p *pp.EndpointPolicy) { p.Limits.BurstBytes = 0 },
		func(p *pp.EndpointPolicy) { p.Limits.MonthlyTransferBytes = -1 },
		func(p *pp.EndpointPolicy) { p.Usage.UsedBytes = -5 },
		func(p *pp.EndpointPolicy) { p.EndpointID = "" },
		func(p *pp.EndpointPolicy) { p.Usage.PeriodEnd = p.Usage.PeriodStart },
	}
	for i, m := range mut {
		p := good
		m(&p)
		if p.Validate() == nil {
			t.Errorf("mutation %d accepted", i)
		}
	}
	if _, err := pp.Decode([]byte(`{"state":"active"}`)); err == nil {
		t.Error("decoded garbage")
	}
}

func TestPrincipalSuspensionSuspendsEndpoints(t *testing.T) {
	f := newFx(t)
	st := identity.NewInMemory(0)
	f.res.Principals = identity.NewService(identity.Config{}, st, st, nil, nil, f.clk, ids.New(f.clk))
	pr := identity.Principal{ID: "pr_1", Fingerprint: "fp", State: identity.PrincipalActive}
	st.Create(bg, pr)
	e, _ := f.eps.CreateRandom(bg, "pr_1")
	if p, _ := f.pub.Current(bg, e.ID); p.State != pp.StateActive {
		t.Fatal("baseline")
	}
	f.res.Principals.Suspend(bg, "pr_1")
	f.pub.RecomputePrincipal(bg, f.eps, "pr_1")
	if p, _ := f.pub.Current(bg, e.ID); p.State != pp.StateSuspended {
		t.Fatalf("principal suspension not applied: %s", p.State)
	}
	f.res.Principals.Unsuspend(bg, "pr_1")
	f.pub.RecomputePrincipal(bg, f.eps, "pr_1")
	if p, _ := f.pub.Current(bg, e.ID); p.State != pp.StateActive {
		t.Fatal("restoration not applied")
	}
}
