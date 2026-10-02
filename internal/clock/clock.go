// Package clock provides an injectable time source so that time-dependent
// logic (token buckets, expiry, reapers) can be tested deterministically.
package clock

import (
	"context"
	"sync"
	"time"
)

// Clock is the time source used across the code base.
type Clock interface {
	Now() time.Time
	// After returns a channel that receives once after d.
	After(d time.Duration) <-chan time.Time
	// Sleep blocks for d or until ctx is done, returning ctx.Err() in the latter case.
	Sleep(ctx context.Context, d time.Duration) error
}

// Real is the wall clock. time.Now carries a monotonic reading, so durations
// computed with Sub are immune to wall-clock steps.
type Real struct{}

func (Real) Now() time.Time                         { return time.Now() }
func (Real) After(d time.Duration) <-chan time.Time { return time.After(d) }
func (Real) Sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Fake is a manually advanced clock for tests.
type Fake struct {
	mu      sync.Mutex
	cond    *sync.Cond
	now     time.Time
	waiters []*waiter
}

type waiter struct {
	at time.Time
	ch chan time.Time
}

// NewFake returns a fake clock starting at start.
func NewFake(start time.Time) *Fake {
	f := &Fake{now: start}
	f.cond = sync.NewCond(&f.mu)
	return f
}

func (f *Fake) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

func (f *Fake) add(d time.Duration) (*waiter, <-chan time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w := &waiter{at: f.now.Add(d), ch: make(chan time.Time, 1)}
	if d <= 0 {
		w.ch <- f.now
		return w, w.ch
	}
	f.waiters = append(f.waiters, w)
	f.cond.Broadcast()
	return w, w.ch
}

func (f *Fake) remove(w *waiter) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, x := range f.waiters {
		if x == w {
			f.waiters = append(f.waiters[:i], f.waiters[i+1:]...)
			break
		}
	}
	f.cond.Broadcast()
}

func (f *Fake) After(d time.Duration) <-chan time.Time {
	_, ch := f.add(d)
	return ch
}

func (f *Fake) Sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	w, ch := f.add(d)
	select {
	case <-ch:
		return nil
	case <-ctx.Done():
		f.remove(w)
		return ctx.Err()
	}
}

// Advance moves time forward and fires every waiter that became due.
func (f *Fake) Advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
	kept := f.waiters[:0]
	for _, w := range f.waiters {
		if !w.at.After(f.now) {
			w.ch <- f.now
		} else {
			kept = append(kept, w)
		}
	}
	f.waiters = kept
	f.cond.Broadcast()
}

// BlockUntil blocks until at least n goroutines are waiting on the clock.
// It replaces sleeps for synchronisation in tests.
func (f *Fake) BlockUntil(n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for len(f.waiters) < n {
		f.cond.Wait()
	}
}

// Waiters reports the number of pending timers.
func (f *Fake) Waiters() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.waiters)
}
