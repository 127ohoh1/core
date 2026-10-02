// Package presence reports which endpoints have an authenticated tunnel so the
// control plane can run the free-name inactivity clock (last_active_at).
//
// Semantics: while a tunnel is connected the edge sends heartbeats, so
// last_active_at keeps advancing; on disconnect the last update carries the
// disconnect time, and the 24 h window runs from there. If an edge dies, its
// endpoints stop receiving heartbeats and age out exactly as if they had
// disconnected at the last heartbeat.
package presence

import (
	"context"
	"sync"
	"time"

	"github.com/127ohoh1/core/dataplane/controlclient"
	"github.com/127ohoh1/core/internal/clock"
)

// Sender delivers presence updates.
type Sender interface {
	Presence(ctx context.Context, edgeID string, updates []controlclient.PresenceUpdate) error
}

// MaxPending bounds the coalescing map.
const MaxPending = 20000

// Reporter batches and retries presence updates. Only the latest state per
// endpoint is kept, so memory is bounded by the number of endpoints.
type Reporter struct {
	edgeID    string
	sender    Sender
	clk       clock.Clock
	connected func() []string // currently connected endpoint ids

	mu      sync.Mutex
	pending map[string]controlclient.PresenceUpdate

	// Tick, if set, is called on every loop iteration (liveness heartbeat).
	Tick func()
}

// New builds a Reporter.
func New(edgeID string, s Sender, clk clock.Clock, connected func() []string) *Reporter {
	return &Reporter{edgeID: edgeID, sender: s, clk: clk, connected: connected, pending: map[string]controlclient.PresenceUpdate{}}
}

func (r *Reporter) set(id string, connected bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.pending[id]; !ok && len(r.pending) >= MaxPending {
		return
	}
	r.pending[id] = controlclient.PresenceUpdate{EndpointID: id, Connected: connected, At: r.clk.Now()}
}

// Connected records a tunnel coming up.
func (r *Reporter) Connected(id string) { r.set(id, true) }

// Disconnected records a tunnel going away.
func (r *Reporter) Disconnected(id string) { r.set(id, false) }

// Heartbeat marks every currently connected endpoint as active now.
func (r *Reporter) Heartbeat() {
	for _, id := range r.connected() {
		r.set(id, true)
	}
}

// Flush sends pending updates (in chunks). Failed chunks are re-queued unless
// a newer state arrived meanwhile.
func (r *Reporter) Flush(ctx context.Context) error {
	r.mu.Lock()
	batch := make([]controlclient.PresenceUpdate, 0, len(r.pending))
	for _, u := range r.pending {
		batch = append(batch, u)
	}
	r.pending = map[string]controlclient.PresenceUpdate{}
	r.mu.Unlock()

	var firstErr error
	for len(batch) > 0 {
		n := min(len(batch), 500)
		chunk := batch[:n]
		batch = batch[n:]
		if err := r.sender.Presence(ctx, r.edgeID, chunk); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			r.mu.Lock()
			for _, u := range chunk {
				if _, newer := r.pending[u.EndpointID]; !newer {
					r.pending[u.EndpointID] = u
				}
			}
			r.mu.Unlock()
		}
	}
	return firstErr
}

// Run flushes every flushEvery and heartbeats every heartbeatEvery.
func (r *Reporter) Run(ctx context.Context, flushEvery, heartbeatEvery time.Duration) {
	var lastHB time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-r.clk.After(flushEvery):
		}
		if r.Tick != nil {
			r.Tick()
		}
		if now := r.clk.Now(); now.Sub(lastHB) >= heartbeatEvery {
			r.Heartbeat()
			lastHB = now
		}
		fctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		_ = r.Flush(fctx)
		cancel()
	}
}
