package clock

import (
	"context"
	"testing"
	"time"
)

func TestFakeSleepAdvance(t *testing.T) {
	f := NewFake(time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC))
	done := make(chan error, 1)
	go func() { done <- f.Sleep(context.Background(), time.Minute) }()
	f.BlockUntil(1)
	f.Advance(59 * time.Second)
	select {
	case <-done:
		t.Fatal("woke early")
	default:
	}
	f.Advance(time.Second)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if f.Waiters() != 0 {
		t.Fatal("waiter leaked")
	}
}

func TestFakeSleepCancel(t *testing.T) {
	f := NewFake(time.Unix(0, 0))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- f.Sleep(ctx, time.Hour) }()
	f.BlockUntil(1)
	cancel()
	if err := <-done; err != context.Canceled {
		t.Fatalf("got %v", err)
	}
	if f.Waiters() != 0 {
		t.Fatal("waiter leaked after cancel")
	}
}

func TestFakeAfter(t *testing.T) {
	f := NewFake(time.Unix(0, 0))
	ch := f.After(time.Second)
	f.Advance(time.Second)
	select {
	case <-ch:
	default:
		t.Fatal("After did not fire")
	}
}
