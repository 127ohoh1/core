package cert

import (
	"context"
	"errors"
	"testing"
	"time"

	pp "github.com/127ohoh1/core/protocol/policy"
)

func TestIssuanceGate(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	lookups := 0
	g := &IssuanceGate{
		Live: func(_ context.Context, l string) bool { return l == "tunnel" },
		Lookup: func(_ context.Context, l string) (pp.HostnameStatus, error) {
			lookups++
			switch l {
			case "paid":
				return pp.HostnameStatus{Kind: "reserved", State: pp.StateActive}, nil
			case "unpaid":
				return pp.HostnameStatus{Kind: "reserved", State: pp.StateExpired}, nil
			case "free":
				return pp.HostnameStatus{Kind: "random", State: pp.StateActive}, nil
			}
			return pp.HostnameStatus{}, errors.New("404")
		},
		Now:   func() time.Time { return now },
		Rate:  1,
		Burst: 5,
	}
	ctx := context.Background()
	if !g.Allow(ctx, "tunnel") || lookups != 0 {
		t.Fatal("a live tunnel needs no lookup")
	}
	if !g.Allow(ctx, "paid") {
		t.Fatal("an active reserved name is issuable before its first tunnel")
	}
	for _, l := range []string{"unpaid", "free", "sprayed"} {
		if g.Allow(ctx, l) {
			t.Fatalf("%s must be refused", l)
		}
	}
	// Refusals are remembered: no second lookup within the TTL.
	before := lookups
	if g.Allow(ctx, "sprayed") || lookups != before {
		t.Fatalf("refused label looked up again (%d -> %d)", before, lookups)
	}
	// The burst is spent (4 lookups so far, one token left): spraying stops
	// reaching the control plane.
	g.Allow(ctx, "spray-1")
	before = lookups
	for i := range 20 {
		g.Allow(ctx, "spray-x"+string(rune('a'+i)))
	}
	if lookups != before {
		t.Fatalf("lookups beyond the rate: %d", lookups-before)
	}
	// Tokens refill, and the refusal expires.
	now = now.Add(2 * time.Minute)
	if !g.Allow(ctx, "paid") || g.Allow(ctx, "sprayed") || lookups != before+2 {
		t.Fatalf("after refill: lookups %d", lookups-before)
	}
}
