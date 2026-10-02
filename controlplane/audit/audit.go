// Package audit records security-sensitive control-plane mutations.
package audit

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// Event is one immutable audit record. Metadata must not contain secrets.
type Event struct {
	ID        string
	Actor     string // principal id, "edge:<id>", "admin", "system"
	Action    string
	Target    string
	Result    string // "ok" or "denied"/"error"
	RequestID string
	At        time.Time
	Metadata  map[string]string
}

// Recorder persists audit events.
type Recorder interface {
	Record(ctx context.Context, e Event)
}

// InMemory keeps a bounded ring of events and mirrors them to the logger.
// Development implementation: contents are lost on restart.
type InMemory struct {
	mu     sync.Mutex
	events []Event
	max    int
	log    *slog.Logger
}

// NewInMemory returns a recorder holding at most max events (oldest dropped).
func NewInMemory(log *slog.Logger, max int) *InMemory {
	if max <= 0 {
		max = 10000
	}
	return &InMemory{max: max, log: log}
}

func (m *InMemory) Record(_ context.Context, e Event) {
	m.mu.Lock()
	if len(m.events) >= m.max {
		m.events = append(m.events[:0], m.events[1:]...)
	}
	m.events = append(m.events, e)
	m.mu.Unlock()
	if m.log != nil {
		m.log.Info("audit", "event", "audit."+e.Action, "actor", e.Actor, "target", e.Target, "result", e.Result, "request_id", e.RequestID)
	}
}

// Events returns a copy of the recorded events.
func (m *InMemory) Events() []Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Event(nil), m.events...)
}

// Nop discards events.
type Nop struct{}

func (Nop) Record(context.Context, Event) {}
