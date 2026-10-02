// Package tunnel is the edge side of the tunnel: handshake, authentication
// and the registry of live sessions.
package tunnel

import (
	"sync"
	"time"

	proto "github.com/127ohoh1/core/protocol/tunnel"
)

// Live is an authenticated, registered tunnel session.
type Live struct {
	EndpointID  string
	Hostname    string
	PrincipalID string
	SessionID   string
	TokenID     string
	Session     *proto.Session
	ConnectedAt time.Time
	RemoteAddr  string
}

// Registry tracks live sessions by endpoint and hostname. At most one session
// serves an endpoint: adding a second supersedes the first.
type Registry struct {
	mu     sync.RWMutex
	byEP   map[string]*Live
	byHost map[string]*Live
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{byEP: map[string]*Live{}, byHost: map[string]*Live{}}
}

// Add registers l and returns the session it supersedes, if any.
func (r *Registry) Add(l *Live) (old *Live) {
	r.mu.Lock()
	defer r.mu.Unlock()
	old = r.byEP[l.EndpointID]
	if old != nil && old.Hostname != l.Hostname {
		delete(r.byHost, old.Hostname)
	}
	r.byEP[l.EndpointID] = l
	r.byHost[l.Hostname] = l
	return old
}

// Remove unregisters l only if it is still the current session for its
// endpoint (a superseded session must not evict its successor).
func (r *Registry) Remove(l *Live) (wasCurrent bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if cur := r.byEP[l.EndpointID]; cur == l {
		delete(r.byEP, l.EndpointID)
		if r.byHost[l.Hostname] == l {
			delete(r.byHost, l.Hostname)
		}
		return true
	}
	return false
}

// ByHostname returns the live session for a tenant label.
func (r *Registry) ByHostname(h string) (*Live, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	l, ok := r.byHost[h]
	return l, ok
}

// ByEndpoint returns the live session for an endpoint id.
func (r *Registry) ByEndpoint(id string) (*Live, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	l, ok := r.byEP[id]
	return l, ok
}

// Count returns the number of live sessions.
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.byEP)
}

// Snapshot returns all live sessions.
func (r *Registry) Snapshot() []*Live {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Live, 0, len(r.byEP))
	for _, l := range r.byEP {
		out = append(out, l)
	}
	return out
}
