package routing

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/127ohoh1/core/internal/clock"
)

// directoryContract is run against every TunnelDirectory implementation with
// real time (Redis expires keys by its own clock).
func directoryContract(t *testing.T, mk func(t *testing.T) TunnelDirectory) {
	ctx := context.Background()
	const ttl = 500 * time.Millisecond
	owner := func(sess, edge string) Owner {
		return Owner{EndpointID: "ep_c1", Hostname: "contract-host", EdgeID: edge, SessionID: sess, InternalAddr: edge + ":9000"}
	}

	t.Run("claim lookup release", func(t *testing.T) {
		d := mk(t)
		if _, err := d.Lookup(ctx, "contract-host"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("empty directory: %v", err)
		}
		if prev, err := d.Claim(ctx, owner("s1", "e1"), ttl); err != nil || prev != nil {
			t.Fatalf("%v %v", prev, err)
		}
		o, err := d.Lookup(ctx, "contract-host")
		if err != nil || o.SessionID != "s1" || o.EdgeID != "e1" || o.InternalAddr != "e1:9000" || o.EndpointID != "ep_c1" {
			t.Fatalf("%+v %v", o, err)
		}
		if err := d.Release(ctx, "ep_c1", "s1"); err != nil {
			t.Fatal(err)
		}
		if _, err := d.Lookup(ctx, "contract-host"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("still routable after release: %v", err)
		}
		if err := d.Release(ctx, "ep_c1", "s1"); err != nil { // idempotent
			t.Fatal(err)
		}
	})

	t.Run("supersede", func(t *testing.T) {
		d := mk(t)
		d.Claim(ctx, owner("s1", "e1"), ttl)
		prev, err := d.Claim(ctx, owner("s2", "e2"), ttl)
		if err != nil || prev == nil || prev.SessionID != "s1" || prev.EdgeID != "e1" {
			t.Fatalf("previous owner must be reported: %+v %v", prev, err)
		}
		if err := d.Heartbeat(ctx, "ep_c1", "s1", ttl); !errors.Is(err, ErrSuperseded) {
			t.Fatalf("superseded session heartbeat: %v", err)
		}
		if err := d.Heartbeat(ctx, "ep_c1", "s2", ttl); err != nil {
			t.Fatal(err)
		}
		// A superseded session releasing itself must not evict the new owner.
		d.Release(ctx, "ep_c1", "s1")
		if o, err := d.Lookup(ctx, "contract-host"); err != nil || o.SessionID != "s2" {
			t.Fatalf("new owner evicted: %+v %v", o, err)
		}
	})

	t.Run("lease expiry and heartbeat", func(t *testing.T) {
		d := mk(t)
		d.Claim(ctx, owner("s1", "e1"), ttl)
		time.Sleep(300 * time.Millisecond)
		if err := d.Heartbeat(ctx, "ep_c1", "s1", ttl); err != nil {
			t.Fatal(err)
		}
		time.Sleep(300 * time.Millisecond) // 600 ms since claim, but the heartbeat extended it
		if _, err := d.Lookup(ctx, "contract-host"); err != nil {
			t.Fatalf("heartbeat did not extend the lease: %v", err)
		}
		time.Sleep(600 * time.Millisecond) // no heartbeat: the owner (edge killed) disappears
		if _, err := d.Lookup(ctx, "contract-host"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("expired lease still routable: %v", err)
		}
		if err := d.Heartbeat(ctx, "ep_c1", "s1", ttl); !errors.Is(err, ErrSuperseded) {
			t.Fatalf("heartbeat after expiry: %v", err)
		}
		if prev, _ := d.Claim(ctx, owner("s3", "e3"), ttl); prev != nil {
			t.Fatalf("an expired owner must not be reported as previous: %+v", prev)
		}
	})

	t.Run("concurrent claims leave exactly one owner", func(t *testing.T) {
		d := mk(t)
		var wg sync.WaitGroup
		for i := 0; i < 16; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				d.Claim(ctx, owner("s"+string(rune('a'+i)), "e"), ttl)
			}(i)
		}
		wg.Wait()
		o, err := d.Lookup(ctx, "contract-host")
		if err != nil {
			t.Fatal(err)
		}
		// The winner is whichever claim ran last; every other session must now see itself superseded.
		superseded := 0
		for i := 0; i < 16; i++ {
			if d.Heartbeat(ctx, "ep_c1", "s"+string(rune('a'+i)), ttl) == ErrSuperseded {
				superseded++
			}
		}
		if superseded != 15 {
			t.Fatalf("owner %s but %d/16 sessions superseded, want 15", o.SessionID, superseded)
		}
	})
}

func TestInMemoryDirectoryContract(t *testing.T) {
	directoryContract(t, func(*testing.T) TunnelDirectory { return NewInMemory(clock.Real{}) })
}

// Runs against a real Redis when OHOH_TEST_REDIS=host:port is set (see Makefile target test-redis).
func TestRedisDirectoryContract(t *testing.T) {
	addr := os.Getenv("OHOH_TEST_REDIS")
	if addr == "" {
		t.Skip("set OHOH_TEST_REDIS=host:port to run the Redis directory contract")
	}
	directoryContract(t, func(t *testing.T) TunnelDirectory {
		d, err := NewRedis("redis://" + addr + "/15")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			d.c.Do(context.Background(), "FLUSHDB")
			d.Close()
		})
		d.c.Do(context.Background(), "FLUSHDB")
		return d
	})
}

func TestRedisDirectoryUnavailableIsAnError(t *testing.T) {
	d, err := NewRedis("redis://127.0.0.1:1/0") // nothing listens
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := d.Claim(ctx, Owner{EndpointID: "e", Hostname: "h", SessionID: "s"}, time.Second); err == nil {
		t.Fatal("claim must fail when Redis is down")
	}
	if _, err := d.Lookup(ctx, "h"); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("an unreachable directory is not 'not found': %v", err)
	}
}
