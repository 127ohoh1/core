// Package health separates liveness from readiness.
//
//   - Readiness answers "should traffic be sent here?" and may depend on
//     dependencies and drain state.
//   - Liveness answers "is this process deadlocked or wedged beyond recovery?"
//     and must NOT fail because a dependency (control plane, Redis, database)
//     is temporarily down: restarting the process would not fix that and would
//     drop established tunnels.
//
// Liveness is implemented as a watchdog: every long-running loop reports a
// heartbeat, and a loop that stops beating for far longer than its period
// marks the process unhealthy.
package health

import (
	"sort"
	"sync"
	"time"
)

// Watchdog tracks loop heartbeats.
type Watchdog struct {
	mu    sync.Mutex
	now   func() time.Time
	beats map[string]beat
}

type beat struct {
	at     time.Time
	period time.Duration
}

// NewWatchdog returns a watchdog using the wall clock (loops are real-time
// goroutines even when a component's business clock is faked in tests).
func NewWatchdog() *Watchdog { return &Watchdog{now: time.Now, beats: map[string]beat{}} }

// Register declares a loop that should beat at least every period.
func (w *Watchdog) Register(name string, period time.Duration) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.beats[name] = beat{at: w.now(), period: period}
}

// Beat records that the loop is alive.
func (w *Watchdog) Beat(name string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if b, ok := w.beats[name]; ok {
		b.at = w.now()
		w.beats[name] = b
	}
}

// Stalled returns loops that have not beaten for more than 5x their period
// (and at least 10 s), sorted by name.
func (w *Watchdog) Stalled() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []string
	now := w.now()
	for name, b := range w.beats {
		limit := 5 * b.period
		if limit < 10*time.Second {
			limit = 10 * time.Second
		}
		if now.Sub(b.at) > limit {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}
