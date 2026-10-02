package session

import (
	"testing"
	"time"
)

func TestBackoffCappedExponentialFullJitter(t *testing.T) {
	max := func() float64 { return 0.999999 }
	zero := func() float64 { return 0 }
	b := Backoff{Base: 500 * time.Millisecond, Max: 30 * time.Second, Rand: max}
	want := []time.Duration{500 * time.Millisecond, time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 30 * time.Second, 30 * time.Second}
	for i, w := range want {
		got := b.Delay(i)
		if got > w || got < w-w/100 {
			t.Errorf("attempt %d: got %v, ceiling %v", i, got, w)
		}
	}
	if d := b.Delay(1000); d > 30*time.Second {
		t.Errorf("uncapped for huge attempt: %v", d)
	}
	b.Rand = zero
	if b.Delay(5) != 0 {
		t.Error("full jitter must reach 0")
	}
}

// Jitter must actually spread delays (guards against a constant "jitter").
func TestBackoffSpreads(t *testing.T) {
	b := Backoff{Base: time.Second, Max: 30 * time.Second}
	seen := map[time.Duration]bool{}
	for i := 0; i < 50; i++ {
		seen[b.Delay(4)] = true
	}
	if len(seen) < 25 {
		t.Fatalf("only %d distinct delays in 50 draws", len(seen))
	}
}
