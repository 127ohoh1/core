package usage

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/127ohoh1/core/internal/clock"
)

var (
	now = time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	sep = time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	aug = time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	bg  = context.Background()
)

func batch(id string, items ...Item) Batch { return Batch{EdgeID: "edge-1", BatchID: id, Items: items} }

func TestApplyAndDuplicateDelivery(t *testing.T) {
	l := NewInMemory(0)
	b := batch("b1", Item{"ep1", sep, 1000}, Item{"ep2", sep, 5})
	r1, err := l.Apply(bg, b, now, nil)
	if err != nil || r1.Duplicate || r1.Totals["ep1"].UsedBytes != 1000 {
		t.Fatalf("%+v %v", r1, err)
	}
	// Delivering the same batch again (retry after a lost response) applies nothing.
	for i := 0; i < 3; i++ {
		r, err := l.Apply(bg, b, now, nil)
		if err != nil || !r.Duplicate || r.Totals["ep1"].UsedBytes != 1000 {
			t.Fatalf("dup #%d: %+v %v", i, r, err)
		}
	}
	if u, _ := l.Used(bg, "ep1", sep); u != 1000 {
		t.Fatalf("double applied: %d", u)
	}
	// Same batch id from a different edge is a different batch.
	other := b
	other.EdgeID = "edge-2"
	if r, _ := l.Apply(bg, other, now, nil); r.Duplicate {
		t.Fatal("batch ids are scoped per edge")
	}
	if u, _ := l.Used(bg, "ep1", sep); u != 2000 {
		t.Fatalf("%d", u)
	}
}

func TestDuplicateReportsCurrentTotals(t *testing.T) {
	l := NewInMemory(0)
	l.Apply(bg, batch("b1", Item{"ep", sep, 100}), now, nil)
	l.Apply(bg, batch("b2", Item{"ep", sep, 900}), now, nil)
	r, _ := l.Apply(bg, batch("b1", Item{"ep", sep, 100}), now, nil)
	if !r.Duplicate || r.Totals["ep"].UsedBytes != 1000 {
		t.Fatalf("a duplicate must return the current total, got %+v", r)
	}
}

func TestItemValidationRejectsPerItem(t *testing.T) {
	l := NewInMemory(0)
	known := func(id string) bool { return id != "ghost" }
	b := batch("b1",
		Item{"good", sep, 10},
		Item{"ghost", sep, 10},                    // unknown endpoint
		Item{"neg", sep, -5},                      // negative
		Item{"zero", sep, 0},                      // zero
		Item{"huge", sep, MaxItemBytes + 1},       // implausible
		Item{"mid-month", sep.Add(time.Hour), 10}, // not a month start
		Item{"future", time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC), 10},
		Item{"ancient", time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), 10},
		Item{"prev-month", aug, 7}, // previous month is allowed
	)
	r, err := l.Apply(bg, b, now, known)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Rejected) != 7 {
		t.Fatalf("rejected %v", r.Rejected)
	}
	if u, _ := l.Used(bg, "good", sep); u != 10 {
		t.Fatal("valid item dropped alongside invalid ones")
	}
	if u, _ := l.Used(bg, "prev-month", aug); u != 7 {
		t.Fatal("late report for the previous month must be accepted")
	}
	for _, id := range []string{"ghost", "neg", "zero", "huge", "mid-month", "future", "ancient"} {
		if u, _ := l.Used(bg, id, sep); u != 0 {
			t.Errorf("%s applied", id)
		}
	}
}

func TestBatchShapeLimits(t *testing.T) {
	l := NewInMemory(0)
	if _, err := l.Apply(bg, Batch{EdgeID: "e", BatchID: "b"}, now, nil); err == nil {
		t.Fatal("empty batch accepted")
	}
	items := make([]Item, MaxItemsPerBatch+1)
	for i := range items {
		items[i] = Item{"ep", sep, 1}
	}
	if _, err := l.Apply(bg, Batch{EdgeID: "e", BatchID: "b", Items: items}, now, nil); err == nil {
		t.Fatal("oversize batch accepted")
	}
	if _, err := l.Apply(bg, Batch{BatchID: "b", Items: items[:1]}, now, nil); err == nil {
		t.Fatal("missing edge id accepted")
	}
}

func TestPeriodsAreIndependent(t *testing.T) {
	l := NewInMemory(0)
	l.Apply(bg, batch("b1", Item{"ep", aug, 400}), now, nil)
	l.Apply(bg, batch("b2", Item{"ep", sep, 30}), now, nil)
	a, _ := l.Used(bg, "ep", aug)
	s, _ := l.Used(bg, "ep", sep)
	if a != 400 || s != 30 {
		t.Fatalf("%d %d", a, s)
	}
}

func TestConcurrentDuplicateDeliveryAppliesOnce(t *testing.T) {
	l := NewInMemory(0)
	b := batch("same", Item{"ep", sep, 1000})
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); l.Apply(bg, b, now, nil) }()
	}
	wg.Wait()
	if u, _ := l.Used(bg, "ep", sep); u != 1000 {
		t.Fatalf("applied %d times", u/1000)
	}
}

func TestServiceNotifiesOnlyForFreshBatches(t *testing.T) {
	var mu sync.Mutex
	notified := map[string]int{}
	s := &Service{Ledger: NewInMemory(0), Clock: clock.NewFake(now),
		Known:   func(context.Context, string) bool { return true },
		Updated: func(_ context.Context, id string) { mu.Lock(); notified[id]++; mu.Unlock() }}
	b := batch("b1", Item{"ep", sep, 10})
	s.Apply(bg, b)
	s.Apply(bg, b)
	if notified["ep"] != 1 {
		t.Fatalf("notified %d", notified["ep"])
	}
}
