// Package ratelimit implements the per-endpoint bandwidth token bucket.
//
// One bucket is shared by *all* streams of an endpoint and by both transfer
// directions, so opening more concurrent streams cannot multiply the plan
// rate. Waiting is reservation based: each caller takes its tokens
// immediately (the balance may go negative, i.e. "debt") and sleeps until the
// debt is repaid by refill. Reservations therefore complete in arrival order,
// which gives reasonable fairness without per-endpoint goroutines or timers:
// waiting costs one timer per blocked caller and nothing when idle.
package ratelimit

import (
	"context"
	"sync"
	"time"

	"github.com/127ohoh1/core/internal/clock"
)

// Bucket is a concurrency-safe token bucket measured in bytes.
type Bucket struct {
	mu     sync.Mutex
	clk    clock.Clock
	rate   float64 // bytes per second
	burst  float64 // capacity in bytes
	tokens float64 // may be negative (debt)
	last   time.Time
	waited time.Duration // total throttle time handed out (metrics)
}

// New returns a full bucket. rate and burst must be positive.
func New(clk clock.Clock, ratePerSecond, burstBytes int64) *Bucket {
	b := &Bucket{clk: clk, rate: float64(ratePerSecond), burst: float64(burstBytes), last: clk.Now()}
	b.tokens = b.burst
	return b
}

// SetLimits applies new limits (policy update). Existing debt is kept; a
// balance above the new burst is clamped.
func (b *Bucket) SetLimits(ratePerSecond, burstBytes int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.refillLocked()
	b.rate, b.burst = float64(ratePerSecond), float64(burstBytes)
	if b.tokens > b.burst {
		b.tokens = b.burst
	}
}

// Limits returns the current rate and burst.
func (b *Bucket) Limits() (rate, burst int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return int64(b.rate), int64(b.burst)
}

func (b *Bucket) refillLocked() {
	now := b.clk.Now()
	if el := now.Sub(b.last); el > 0 {
		b.tokens += el.Seconds() * b.rate
		if b.tokens > b.burst {
			b.tokens = b.burst
		}
	}
	b.last = now
}

// reserve takes n tokens and returns how long the caller must wait before
// using them.
func (b *Bucket) reserve(n float64) time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.refillLocked()
	b.tokens -= n
	if b.tokens >= 0 {
		return 0
	}
	d := time.Duration(-b.tokens / b.rate * float64(time.Second))
	b.waited += d
	return d
}

func (b *Bucket) refund(n float64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.tokens += n
	if b.tokens > b.burst {
		b.tokens = b.burst
	}
}

// Wait blocks until n bytes may be transferred. Requests larger than the
// burst are split so a single call can never require an impossible balance.
// If ctx is cancelled the unspent tokens are returned to the bucket.
func (b *Bucket) Wait(ctx context.Context, n int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	for n > 0 {
		b.mu.Lock()
		maxChunk := int(b.burst)
		b.mu.Unlock()
		if maxChunk < 1 {
			maxChunk = 1
		}
		c := min(n, maxChunk)
		d := b.reserve(float64(c))
		if d > 0 {
			if err := b.clk.Sleep(ctx, d); err != nil {
				b.refund(float64(c))
				return err
			}
		}
		n -= c
	}
	return nil
}

// ThrottleTime returns the cumulative wait time handed out (for metrics).
func (b *Bucket) ThrottleTime() time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.waited
}
