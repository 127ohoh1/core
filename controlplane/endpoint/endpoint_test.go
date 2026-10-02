package endpoint

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/127ohoh1/core/internal/apperr"
	"github.com/127ohoh1/core/internal/clock"
	"github.com/127ohoh1/core/internal/ids"
)

func TestNormalizeName(t *testing.T) {
	long := strings.Repeat("a", 63)
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"MyProject", "myproject", true},
		{"a-b", "a-b", true},
		{"abc", "abc", true},
		{long, long, true},
		{long + "a", "", false},
		{"ab", "", false},
		{"-abc", "", false},
		{"abc-", "", false},
		{"a_b", "", false},
		{"a.b", "", false},
		{"my project", "", false},
		{" abc", "", false},
		{"ünicode", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		got, err := NormalizeName(c.in)
		if (err == nil) != c.ok || got != c.want {
			t.Errorf("%q: got %q %v", c.in, got, err)
		}
	}
}

func TestReservedAndConfusableNames(t *testing.T) {
	v := DefaultNameValidator{}
	for _, n := range []string{"api", "www", "admin", "status", "ingress", "edge", "support"} {
		if _, err := ValidateName(v, n); !errors.Is(err, ErrNameReserved) {
			t.Errorf("%s: %v", n, err)
		}
	}
	for _, n := range []string{"xn--abc", "ab--cd"} {
		if _, err := ValidateName(v, n); !errors.Is(err, ErrNameRejected) {
			t.Errorf("%s: %v", n, err)
		}
	}
	if _, err := ValidateName(v, "API"); err == nil {
		t.Error("uppercase reserved label must be normalized then denied")
	}
	if _, err := ValidateName(v, "myproject"); err != nil {
		t.Error(err)
	}
}

func TestStateMachine(t *testing.T) {
	all := []State{StatePending, StateActive, StateSuspended, StateExpired, StateReleased}
	valid := map[[2]State]bool{
		{StatePending, StateActive}: true, {StatePending, StateReleased}: true,
		{StateActive, StateSuspended}: true, {StateActive, StateExpired}: true, {StateActive, StateReleased}: true,
		{StateSuspended, StateActive}: true, {StateSuspended, StateExpired}: true, {StateSuspended, StateReleased}: true,
		{StateExpired, StateActive}: true, {StateExpired, StateReleased}: true,
	}
	for _, a := range all {
		for _, b := range all {
			if got := CanTransition(a, b); got != valid[[2]State{a, b}] {
				t.Errorf("%s -> %s: got %v", a, b, got)
			}
		}
	}
}

type fixture struct {
	svc *Service
	reg *InMemory
	clk *clock.Fake
	ch  []string
	mu  sync.Mutex
}

func newFixture(alloc NameAllocator) *fixture {
	f := &fixture{reg: NewInMemory(), clk: clock.NewFake(time.Date(2026, 9, 12, 20, 0, 0, 0, time.UTC))}
	if alloc == nil {
		alloc = NewRandomAllocator(nil)
	}
	f.svc = NewService(Config{MaxRandomPerPrincipal: 2, Tombstone: time.Hour, FreeInactivity: 24 * time.Hour}, f.reg, alloc, nil, f.clk, ids.New(f.clk))
	f.svc.OnChange = func(_ context.Context, id string) { f.mu.Lock(); f.ch = append(f.ch, id); f.mu.Unlock() }
	return f
}

func TestCreateRandomDNSSafeAndActive(t *testing.T) {
	f := newFixture(nil)
	e, err := f.svc.CreateRandom(context.Background(), "pr_1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NormalizeName(e.Hostname); err != nil || e.State != StateActive || e.Kind != KindRandom {
		t.Fatalf("%+v %v", e, err)
	}
	if len(f.ch) != 1 {
		t.Fatalf("OnChange calls: %v", f.ch)
	}
}

func TestPerPrincipalCap(t *testing.T) {
	f := newFixture(nil)
	ctx := context.Background()
	f.svc.CreateRandom(ctx, "pr_1")
	f.svc.CreateRandom(ctx, "pr_1")
	if _, err := f.svc.CreateRandom(ctx, "pr_1"); !errors.Is(err, apperr.ErrRateLimited) {
		t.Fatalf("got %v", err)
	}
	if _, err := f.svc.CreateRandom(ctx, "pr_2"); err != nil {
		t.Fatalf("other principal must be unaffected: %v", err)
	}
}

type seqAlloc struct{ names []string }

func (s *seqAlloc) Allocate(context.Context) (string, error) {
	n := s.names[0]
	if len(s.names) > 1 {
		s.names = s.names[1:]
	}
	return n, nil
}

func TestCollisionRetriesBoundedly(t *testing.T) {
	ctx := context.Background()
	f := newFixture(&seqAlloc{names: []string{"quiet-river-0001", "quiet-river-0001", "calm-delta-0002"}})
	if _, err := f.svc.CreateRandom(ctx, "pr_1"); err != nil {
		t.Fatal(err)
	}
	e, err := f.svc.CreateRandom(ctx, "pr_2") // collides once, then succeeds
	if err != nil || e.Hostname != "calm-delta-0002" {
		t.Fatalf("%+v %v", e, err)
	}
	// An allocator that only yields a taken name must give up, not spin.
	g := newFixture(&seqAlloc{names: []string{"same-name-0000"}})
	g.svc.CreateRandom(ctx, "pr_1")
	if _, err := g.svc.CreateRandom(ctx, "pr_2"); !errors.Is(err, apperr.ErrUnavailable) {
		t.Fatalf("got %v", err)
	}
}

func TestConcurrentSameNameSingleWinner(t *testing.T) {
	f := newFixture(nil)
	ctx := context.Background()
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			pid := "pr_" + string(rune('a'+i))
			if _, err := f.svc.CreateReserved(ctx, pid, "myproject"); err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("wins = %d", wins)
	}
}

func TestOwnershipHidesExistence(t *testing.T) {
	f := newFixture(nil)
	ctx := context.Background()
	e, _ := f.svc.CreateRandom(ctx, "pr_1")
	if _, err := f.svc.Get(ctx, "pr_2", e.ID); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("got %v", err)
	}
	if _, err := f.svc.Release(ctx, "pr_2", e.ID); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("got %v", err)
	}
}

func TestReleaseIdempotentAndTombstone(t *testing.T) {
	f := newFixture(nil)
	ctx := context.Background()
	e, _ := f.svc.CreateReserved(ctx, "pr_1", "myproject")
	if _, err := f.svc.Release(ctx, "pr_1", e.ID); err != nil {
		t.Fatal(err)
	}
	n := len(f.ch)
	if _, err := f.svc.Release(ctx, "pr_1", e.ID); err != nil {
		t.Fatalf("second release must be a no-op: %v", err)
	}
	if len(f.ch) != n {
		t.Fatal("idempotent release must not re-publish")
	}
	// Within the tombstone another principal cannot take the name; the old owner can.
	if _, err := f.svc.CreateReserved(ctx, "pr_2", "myproject"); !errors.Is(err, apperr.ErrConflict) {
		t.Fatalf("takeover during tombstone: %v", err)
	}
	f.clk.Advance(time.Hour + time.Second)
	if _, err := f.svc.CreateReserved(ctx, "pr_2", "myproject"); err != nil {
		t.Fatalf("after tombstone: %v", err)
	}
	// Released state is terminal.
	if _, err := f.svc.Unsuspend(ctx, e.ID); !errors.Is(err, apperr.ErrConflict) {
		t.Fatalf("released must be terminal: %v", err)
	}
}

func TestSuspendIdempotentAndReversible(t *testing.T) {
	f := newFixture(nil)
	ctx := context.Background()
	e, _ := f.svc.CreateRandom(ctx, "pr_1")
	for i := 0; i < 2; i++ {
		if got, err := f.svc.Suspend(ctx, e.ID); err != nil || got.State != StateSuspended {
			t.Fatalf("%v %+v", err, got)
		}
	}
	if got, _ := f.svc.Unsuspend(ctx, e.ID); got.State != StateActive {
		t.Fatal("unsuspend failed")
	}
}

func TestFreeNameInactivityReaping(t *testing.T) {
	f := newFixture(nil)
	ctx := context.Background()
	e, _ := f.svc.CreateRandom(ctx, "pr_1")
	reserved, _ := f.svc.CreateReserved(ctx, "pr_1", "keepme")

	// Connected: heartbeats keep last_active_at fresh, so it never qualifies.
	f.svc.SetPresence(ctx, e.ID, true, f.clk.Now())
	f.clk.Advance(23 * time.Hour)
	f.svc.SetPresence(ctx, e.ID, true, f.clk.Now()) // heartbeat
	f.clk.Advance(2 * time.Hour)
	if n, _ := f.svc.Reap(ctx); n != 0 {
		t.Fatal("connected endpoint reaped")
	}
	// Disconnect starts the window.
	f.svc.SetPresence(ctx, e.ID, false, f.clk.Now())
	f.clk.Advance(24*time.Hour - time.Second)
	if n, _ := f.svc.Reap(ctx); n != 0 {
		t.Fatal("released before 24h of inactivity")
	}
	// Reconnect before expiry resets the clock.
	f.svc.SetPresence(ctx, e.ID, true, f.clk.Now())
	f.svc.SetPresence(ctx, e.ID, false, f.clk.Now())
	f.clk.Advance(24*time.Hour - time.Second)
	if n, _ := f.svc.Reap(ctx); n != 0 {
		t.Fatal("reconnect did not reset inactivity")
	}
	f.clk.Advance(time.Second)
	if n, err := f.svc.Reap(ctx); n != 1 || err != nil {
		t.Fatalf("expected release at exactly 24h: %d %v", n, err)
	}
	if got, _ := f.svc.GetByID(ctx, e.ID); got.State != StateReleased {
		t.Fatal("not released")
	}
	if got, _ := f.svc.GetByID(ctx, reserved.ID); got.State != StateActive {
		t.Fatal("reserved names are not subject to the free reaper")
	}
	if n, _ := f.svc.Reap(ctx); n != 0 {
		t.Fatal("reap must be idempotent")
	}
	// The old id cannot be reused: presence on a released endpoint fails.
	if err := f.svc.SetPresence(ctx, e.ID, true, f.clk.Now()); err == nil {
		t.Fatal("released endpoint accepted presence")
	}
}

func TestRandomAllocatorDeterministic(t *testing.T) {
	a := NewRandomAllocator(bytes.NewReader([]byte{0, 0, 0xab, 0xcd}))
	n, _ := a.Allocate(context.Background())
	if n != "quiet-river-abcd" {
		t.Fatalf("got %s", n)
	}
	if _, err := ValidateName(DefaultNameValidator{}, n); err != nil {
		t.Fatal(err)
	}
}

func FuzzNormalizeName(f *testing.F) {
	for _, s := range []string{"myproject", "A-B", "", "-", "xn--a", strings.Repeat("a", 64), "a b", "ü"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		n, err := ValidateName(DefaultNameValidator{}, s)
		if err != nil {
			return
		}
		if n != strings.ToLower(n) || len(n) < 3 || len(n) > 63 || n[0] == '-' || n[len(n)-1] == '-' {
			t.Fatalf("accepted invalid name %q -> %q", s, n)
		}
		if again, err := ValidateName(DefaultNameValidator{}, n); err != nil || again != n {
			t.Fatalf("not idempotent: %q", n)
		}
	})
}

func TestCheckNameRespectsTombstoneForOthersOnly(t *testing.T) {
	f := newFixture(nil)
	ctx := context.Background()
	e, _ := f.svc.CreateReserved(ctx, "pr_1", "myproject")
	if _, err := f.svc.CheckName(ctx, "pr_2", "myproject"); !errors.Is(err, apperr.ErrConflict) {
		t.Fatalf("live name: %v", err)
	}
	f.svc.Release(ctx, "pr_1", e.ID)
	if _, err := f.svc.CheckName(ctx, "pr_2", "myproject"); !errors.Is(err, apperr.ErrConflict) {
		t.Fatalf("tombstoned name must be unavailable to others: %v", err)
	}
	if _, err := f.svc.CheckName(ctx, "pr_1", "myproject"); err != nil {
		t.Fatalf("the previous owner may recover the name: %v", err)
	}
	f.clk.Advance(time.Hour + time.Second)
	if _, err := f.svc.CheckName(ctx, "pr_2", "myproject"); err != nil {
		t.Fatalf("after the tombstone: %v", err)
	}
}
