package controlclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/127ohoh1/core/protocol/auth"
)

func TestKeyCacheRefreshOnUnknownKidAndRateLimit(t *testing.T) {
	pub1, priv1, _ := ed25519.GenerateKey(rand.Reader)
	pub2, priv2, _ := ed25519.GenerateKey(rand.Reader)
	published := auth.KeySet{"k1": pub1}
	fetches := 0
	fail := false
	kc := NewKeyCache(func(context.Context) (auth.KeySet, error) {
		fetches++
		if fail {
			return nil, errors.New("control plane down")
		}
		return published, nil
	})
	clk := time.Date(2026, 9, 12, 20, 0, 0, 0, time.UTC)
	kc.now = func() time.Time { return clk }
	if err := kc.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	claims := func(kid string, priv ed25519.PrivateKey) string {
		tok, _ := auth.NewSigner(kid, priv).Sign(auth.Claims{Type: auth.TypeTunnel, Subject: "p", Audience: "a", ID: "t", IssuedAt: clk.Unix(), ExpiresAt: clk.Add(time.Minute).Unix()})
		return tok
	}
	ctx := context.Background()
	if _, err := kc.Verify(ctx, claims("k1", priv1), auth.TypeTunnel, "a", clk); err != nil {
		t.Fatal(err)
	}
	// Rotation: control plane starts publishing k2; an unknown kid triggers a
	// refresh, but only once per interval.
	published = auth.KeySet{"k1": pub1, "k2": pub2}
	clk = clk.Add(10 * time.Second) // past the on-demand refresh spacing
	before := fetches
	if _, err := kc.Verify(ctx, claims("k2", priv2), auth.TypeTunnel, "a", clk); err != nil {
		t.Fatalf("rotated key rejected: %v", err)
	}
	if fetches != before+1 {
		t.Fatalf("fetches %d", fetches-before)
	}
	// A forged unknown kid must not let an attacker hammer the control plane.
	_, evil, _ := ed25519.GenerateKey(rand.Reader)
	for i := 0; i < 50; i++ {
		kc.Verify(ctx, claims("nope", evil), auth.TypeTunnel, "a", clk)
	}
	if fetches > before+2 {
		t.Fatalf("unknown-kid refresh not rate limited: %d fetches", fetches-before)
	}
	// Control plane outage: cached keys keep verifying.
	fail = true
	if _, err := kc.Verify(ctx, claims("k1", priv1), auth.TypeTunnel, "a", clk); err != nil {
		t.Fatalf("cached key must survive an outage: %v", err)
	}
	if err := kc.Refresh(ctx); err == nil {
		t.Fatal("expected failure")
	}
	if len(kc.Keys()) != 2 {
		t.Fatal("failed refresh must retain the previous key set")
	}
}
