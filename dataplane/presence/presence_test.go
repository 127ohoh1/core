package presence

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/127ohoh1/core/dataplane/controlclient"
	"github.com/127ohoh1/core/internal/clock"
)

type fakeSender struct {
	mu   sync.Mutex
	got  []controlclient.PresenceUpdate
	fail bool
}

func (f *fakeSender) Presence(_ context.Context, _ string, u []controlclient.PresenceUpdate) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return errors.New("down")
	}
	f.got = append(f.got, u...)
	return nil
}

func TestCoalescesToLatestStateAndRetries(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC))
	s := &fakeSender{fail: true}
	r := New("edge-1", s, clk, func() []string { return []string{"ep2"} })
	r.Connected("ep1")
	clk.Advance(time.Second)
	r.Disconnected("ep1") // latest state wins
	r.Heartbeat()
	if err := r.Flush(context.Background()); err == nil {
		t.Fatal("expected failure")
	}
	s.mu.Lock()
	s.fail = false
	s.mu.Unlock()
	if err := r.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	byID := map[string]controlclient.PresenceUpdate{}
	for _, u := range s.got {
		byID[u.EndpointID] = u
	}
	if byID["ep1"].Connected || !byID["ep1"].At.Equal(clk.Now()) || !byID["ep2"].Connected {
		t.Fatalf("%+v", byID)
	}
	if err := r.Flush(context.Background()); err != nil || len(s.got) != 2 {
		t.Fatalf("nothing pending expected, got %d sends", len(s.got))
	}
}

func TestNewerStateWinsOverRetriedOne(t *testing.T) {
	clk := clock.NewFake(time.Now())
	s := &fakeSender{fail: true}
	r := New("e", s, clk, func() []string { return nil })
	r.Connected("ep")
	r.Flush(context.Background()) // fails, re-queues "connected"
	r.Disconnected("ep")          // newer state arrives before the retry
	s.mu.Lock()
	s.fail = false
	s.mu.Unlock()
	r.Flush(context.Background())
	if len(s.got) != 1 || s.got[0].Connected {
		t.Fatalf("a stale retry overwrote newer state: %+v", s.got)
	}
}
