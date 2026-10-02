package api

import (
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/127ohoh1/core/internal/clock"
)

// ipLimiter is a bounded per-client token bucket used for unauthenticated
// endpoints (challenge issuance, abuse reports). The client identity is the
// TCP peer address; forwarded headers are not trusted.
type ipLimiter struct {
	mu      sync.Mutex
	clk     clock.Clock
	rate    float64 // tokens per second
	burst   float64
	max     int
	buckets map[string]*ipBucket
}

type ipBucket struct {
	tokens float64
	at     time.Time
}

func newIPLimiter(clk clock.Clock, perMinute, burst, maxClients int) *ipLimiter {
	return &ipLimiter{clk: clk, rate: float64(perMinute) / 60, burst: float64(burst), max: maxClients, buckets: map[string]*ipBucket{}}
}

func (l *ipLimiter) allow(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	now := l.clk.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[host]
	if !ok {
		if len(l.buckets) >= l.max { // bounded memory: drop idle entries, else refuse
			for k, x := range l.buckets {
				if now.Sub(x.at) > time.Minute {
					delete(l.buckets, k)
				}
			}
			if len(l.buckets) >= l.max {
				return false
			}
		}
		b = &ipBucket{tokens: l.burst, at: now}
		l.buckets[host] = b
	}
	b.tokens += now.Sub(b.at).Seconds() * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.at = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
