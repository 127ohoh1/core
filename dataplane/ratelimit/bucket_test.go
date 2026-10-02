package ratelimit

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/127ohoh1/core/internal/clock"
)

var t0 = time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
var bg = context.Background()

func TestBurstThenSustainedRate(t *testing.T) {
	clk := clock.NewFake(t0)
	b := New(clk, 100_000, 200_000) // free plan: 100 kB/s, 2 s burst
	// The initial burst is available immediately.
	if err := b.Wait(bg, 200_000); err != nil {
		t.Fatal(err)
	}
	if clk.Waiters() != 0 {
		t.Fatal("burst must not block")
	}
	// The next 100,000 bytes must take exactly one second.
	done := make(chan struct{})
	go func() { b.Wait(bg, 100_000); close(done) }()
	clk.BlockUntil(1)
	clk.Advance(999 * time.Millisecond)
	select {
	case <-done:
		t.Fatal("released early")
	default:
	}
	clk.Advance(time.Millisecond)
	<-done
}

func TestRefillCapsAtBurst(t *testing.T) {
	clk := clock.NewFake(t0)
	b := New(clk, 1000, 2000)
	b.Wait(bg, 2000)
	clk.Advance(time.Hour) // far more than enough to refill
	b.Wait(bg, 2000)       // full burst again, no wait
	if clk.Waiters() != 0 {
		t.Fatal("blocked after long idle")
	}
	done := make(chan struct{})
	go func() { b.Wait(bg, 1); close(done) }() // but not more than burst was saved
	clk.BlockUntil(1)
	clk.Advance(time.Second)
	<-done
}

// Sequential accuracy: moving N bytes takes (N - burst) / rate seconds.
func TestSustainedRateAccuracy(t *testing.T) {
	clk := clock.NewFake(t0)
	b := New(clk, 100_000, 200_000)
	total := 0
	start := clk.Now()
	for total < 5_000_000 {
		// Advance the fake clock exactly when the limiter asks for a sleep.
		done := make(chan struct{})
		go func() { b.Wait(bg, 16_384); close(done) }()
		for {
			select {
			case <-done:
				goto next
			default:
			}
			if clk.Waiters() > 0 {
				clk.Advance(time.Millisecond)
			} else {
				time.Sleep(50 * time.Microsecond)
			}
		}
	next:
		total += 16_384
	}
	elapsed := clk.Now().Sub(start).Seconds()
	want := float64(total-200_000) / 100_000
	if elapsed < want-0.05 || elapsed > want+0.05 {
		t.Fatalf("moved %d bytes in %.3fs, want %.3fs", total, elapsed, want)
	}
}

func TestCancelWakesWaiterAndRefunds(t *testing.T) {
	clk := clock.NewFake(t0)
	b := New(clk, 1000, 1000)
	b.Wait(bg, 1000)
	ctx, cancel := context.WithCancel(bg)
	errc := make(chan error, 1)
	go func() { errc <- b.Wait(ctx, 1000) }()
	clk.BlockUntil(1)
	cancel()
	if err := <-errc; err != context.Canceled {
		t.Fatalf("got %v", err)
	}
	if clk.Waiters() != 0 {
		t.Fatal("timer leaked")
	}
	// The cancelled reservation was refunded: a new waiter needs only its own tokens.
	done := make(chan struct{})
	go func() { b.Wait(bg, 1000); close(done) }()
	clk.BlockUntil(1)
	clk.Advance(time.Second)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("refund missing: waiter still blocked")
	}
}

func TestLargerThanBurstIsSplit(t *testing.T) {
	clk := clock.NewFake(t0)
	b := New(clk, 1000, 1000)
	done := make(chan struct{})
	go func() { b.Wait(bg, 5000); close(done) }() // 5x the burst
	for {
		select {
		case <-done:
			if got := clk.Now().Sub(t0); got < 3900*time.Millisecond || got > 4100*time.Millisecond {
				t.Fatalf("5000 bytes at 1000 B/s with a 1000 burst took %v", got)
			}
			return
		default:
		}
		if clk.Waiters() > 0 {
			clk.Advance(10 * time.Millisecond)
		} else {
			time.Sleep(50 * time.Microsecond)
		}
	}
}

func TestSetLimitsClampsAndKeepsDebt(t *testing.T) {
	clk := clock.NewFake(t0)
	b := New(clk, 1000, 10_000)
	b.SetLimits(500, 1000) // downgrade: balance clamped to the new burst
	b.Wait(bg, 1000)
	done := make(chan struct{})
	go func() { b.Wait(bg, 500); close(done) }()
	clk.BlockUntil(1)
	clk.Advance(time.Second) // 500 B/s
	<-done
	if r, bu := b.Limits(); r != 500 || bu != 1000 {
		t.Fatalf("%d %d", r, bu)
	}
}

// The shared bucket bounds the aggregate rate regardless of stream count.
func TestManyConcurrentWaitersShareOneRate(t *testing.T) {
	clk := clock.NewFake(t0)
	b := New(clk, 100_000, 200_000)
	const workers, per = 32, 25_000 // 800 kB total
	var wg sync.WaitGroup
	var finished atomic.Int32
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); b.Wait(bg, per); finished.Add(1) }()
	}
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			if clk.Waiters() > 0 {
				clk.Advance(time.Millisecond)
			} else {
				time.Sleep(20 * time.Microsecond)
			}
		}
	}()
	wg.Wait()
	close(stop)
	elapsed := clk.Now().Sub(t0).Seconds()
	want := float64(workers*per-200_000) / 100_000 // 6.0 s
	if elapsed < want-0.3 || elapsed > want+0.3 {  // fake-clock step is 1 ms; multiplication would give ~0.2 s, not ~6 s
		t.Fatalf("%d streams moved %d bytes in %.2fs, want %.2fs (rate multiplied by concurrency?)", workers, workers*per, elapsed, want)
	}
}

func TestRealClockThroughput(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	b := New(clock.Real{}, 2_000_000, 200_000) // 2 MB/s
	start := time.Now()
	for i := 0; i < 8; i++ {
		b.Wait(bg, 250_000) // 2 MB total
	}
	el := time.Since(start).Seconds()
	want := float64(2_000_000-200_000) / 2_000_000 // 0.9 s
	if el < want*0.9 || el > want*1.3 {
		t.Fatalf("real-clock transfer took %.3fs, want ~%.3fs", el, want)
	}
}

func BenchmarkWaitUncontended(bm *testing.B) {
	b := New(clock.Real{}, 1<<40, 1<<40)
	for i := 0; i < bm.N; i++ {
		b.Wait(bg, 16_384)
	}
}

func BenchmarkWaitParallel(bm *testing.B) {
	b := New(clock.Real{}, 1<<40, 1<<40)
	bm.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			b.Wait(bg, 16_384)
		}
	})
}
