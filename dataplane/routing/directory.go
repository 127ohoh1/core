// Package routing resolves hostnames to endpoints and tunnel owners.
package routing

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/127ohoh1/core/internal/clock"
)

// Owner identifies the edge session that currently serves an endpoint.
type Owner struct {
	EndpointID   string `json:"endpoint_id"`
	Hostname     string `json:"hostname"`
	EdgeID       string `json:"edge_id"`
	SessionID    string `json:"session_id"`
	InternalAddr string `json:"internal_addr"` // where other edges can reach the owner (multi-edge profile)
}

// Directory errors.
var (
	ErrNotFound   = errors.New("routing: no owner")
	ErrSuperseded = errors.New("routing: lease lost (superseded or expired)")
)

// TunnelDirectory maps hostname -> endpoint -> owning edge -> session.
// Ownership is a short lease: it must be refreshed by Heartbeat, so an edge
// that dies stops owning its endpoints within one TTL.
type TunnelDirectory interface {
	// Claim makes o the owner, returning the previous live owner if any.
	Claim(ctx context.Context, o Owner, ttl time.Duration) (previous *Owner, err error)
	// Heartbeat extends the lease; ErrSuperseded if sessionID no longer owns it.
	Heartbeat(ctx context.Context, endpointID, sessionID string, ttl time.Duration) error
	// Release drops ownership if sessionID still owns the endpoint.
	Release(ctx context.Context, endpointID, sessionID string) error
	// Lookup resolves a hostname label to its live owner.
	Lookup(ctx context.Context, hostname string) (Owner, error)
}

// InMemory is the single-edge development directory.
type InMemory struct {
	mu     sync.Mutex
	clk    clock.Clock
	byEP   map[string]lease
	byHost map[string]string
}

type lease struct {
	o       Owner
	expires time.Time
}

// NewInMemory returns an empty directory.
func NewInMemory(clk clock.Clock) *InMemory {
	return &InMemory{clk: clk, byEP: map[string]lease{}, byHost: map[string]string{}}
}

func (m *InMemory) live(endpointID string) (lease, bool) {
	l, ok := m.byEP[endpointID]
	if !ok || !m.clk.Now().Before(l.expires) {
		return lease{}, false
	}
	return l, true
}

func (m *InMemory) Claim(_ context.Context, o Owner, ttl time.Duration) (*Owner, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var prev *Owner
	if l, ok := m.live(o.EndpointID); ok {
		p := l.o
		prev = &p
	}
	m.byEP[o.EndpointID] = lease{o: o, expires: m.clk.Now().Add(ttl)}
	m.byHost[o.Hostname] = o.EndpointID
	return prev, nil
}

func (m *InMemory) Heartbeat(_ context.Context, endpointID, sessionID string, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	l, ok := m.live(endpointID)
	if !ok || l.o.SessionID != sessionID {
		return ErrSuperseded
	}
	l.expires = m.clk.Now().Add(ttl)
	m.byEP[endpointID] = l
	return nil
}

func (m *InMemory) Release(_ context.Context, endpointID, sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if l, ok := m.byEP[endpointID]; ok && l.o.SessionID == sessionID {
		delete(m.byEP, endpointID)
		if m.byHost[l.o.Hostname] == endpointID {
			delete(m.byHost, l.o.Hostname)
		}
	}
	return nil
}

func (m *InMemory) Lookup(_ context.Context, hostname string) (Owner, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.byHost[hostname]
	if !ok {
		return Owner{}, ErrNotFound
	}
	l, ok := m.live(id)
	if !ok {
		return Owner{}, ErrNotFound
	}
	return l.o, nil
}
