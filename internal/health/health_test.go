package health

import (
	"testing"
	"time"
)

func TestWatchdogStallDetection(t *testing.T) {
	w := NewWatchdog()
	now := time.Now()
	w.now = func() time.Time { return now }
	w.Register("fast", time.Second)
	w.Register("slow", time.Minute)
	if s := w.Stalled(); len(s) != 0 {
		t.Fatalf("%v", s)
	}
	now = now.Add(11 * time.Second) // fast loop: 5x period floors at 10 s
	if s := w.Stalled(); len(s) != 1 || s[0] != "fast" {
		t.Fatalf("%v", s)
	}
	w.Beat("fast")
	if s := w.Stalled(); len(s) != 0 {
		t.Fatalf("beat did not clear the stall: %v", s)
	}
	now = now.Add(6 * time.Minute)
	if s := w.Stalled(); len(s) != 2 {
		t.Fatalf("%v", s)
	}
	w.Beat("unknown") // ignored, must not panic
}
