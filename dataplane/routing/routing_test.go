package routing

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/127ohoh1/core/internal/clock"
)

func TestParseTenantHost(t *testing.T) {
	const base = "127ohoh1.com"
	ok := map[string]string{
		"quiet-river-7f2c.127ohoh1.com":      "quiet-river-7f2c",
		"QUIET-RIVER-7F2C.127OHOH1.COM":      "quiet-river-7f2c",
		"quiet-river-7f2c.127ohoh1.com:8443": "quiet-river-7f2c",
		"a1.127ohoh1.com:443":                "a1",
	}
	for in, want := range ok {
		if got, err := ParseTenantHost(in, base); err != nil || got != want {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
	bad := []string{
		"", "127ohoh1.com", "evil.com", "a.b.127ohoh1.com", "a.127ohoh1.com.evil.com", "x.127ohoh1.com.",
		"1.2.3.4", "[::1]:80", "a.127ohoh1.com:", "a.127ohoh1.com:80:80", "user@a.127ohoh1.com", "a b.127ohoh1.com",
		"-a.127ohoh1.com", "a-.127ohoh1.com", "a_b.127ohoh1.com", "a/b.127ohoh1.com", "xn--a.127ohoh1.com:x/y",
		strings.Repeat("a", 64) + ".127ohoh1.com", ".127ohoh1.com", "ü.127ohoh1.com", "notdomain127ohoh1.com",
	}
	for _, in := range bad {
		if got, err := ParseTenantHost(in, base); err == nil {
			t.Errorf("accepted %q -> %q", in, got)
		}
	}
}

func TestCheckSNI(t *testing.T) {
	const base = "127ohoh1.com"
	if err := CheckSNI("a.127ohoh1.com", "a", base, false); err != nil {
		t.Fatal(err)
	}
	if err := CheckSNI("A.127ohoh1.com", "a", base, false); err != nil {
		t.Fatalf("SNI is case-insensitive: %v", err)
	}
	for _, sni := range []string{"b.127ohoh1.com", "127ohoh1.com", "evil.com", ""} {
		if err := CheckSNI(sni, "a", base, false); !errors.Is(err, ErrHostMismatch) {
			t.Errorf("%q: %v", sni, err)
		}
	}
	if err := CheckSNI("", "a", base, true); err != nil {
		t.Fatal("empty SNI allowed for dev HTTP")
	}
}

func FuzzParseTenantHost(f *testing.F) {
	for _, s := range []string{"a.127ohoh1.com", "a.127ohoh1.com:1", "", "[::1]", "a..b", "\x00"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		l, err := ParseTenantHost(s, "127ohoh1.com")
		if err != nil {
			return
		}
		if l == "" || len(l) > 63 || strings.ContainsAny(l, ".:/@ ") || l != strings.ToLower(l) {
			t.Fatalf("bad label %q from %q", l, s)
		}
	})
}

func TestDirectoryLeaseSemantics(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 9, 12, 20, 0, 0, 0, time.UTC))
	d := NewInMemory(clk)
	ctx := context.Background()
	a := Owner{EndpointID: "ep1", Hostname: "h", EdgeID: "e1", SessionID: "s1"}
	if prev, err := d.Claim(ctx, a, 30*time.Second); err != nil || prev != nil {
		t.Fatal(prev, err)
	}
	if o, err := d.Lookup(ctx, "h"); err != nil || o.SessionID != "s1" {
		t.Fatal(o, err)
	}
	// Superseding claim returns the previous owner and invalidates its heartbeat.
	b := a
	b.SessionID, b.EdgeID = "s2", "e2"
	if prev, _ := d.Claim(ctx, b, 30*time.Second); prev == nil || prev.SessionID != "s1" {
		t.Fatalf("previous owner not reported: %v", prev)
	}
	if err := d.Heartbeat(ctx, "ep1", "s1", time.Minute); !errors.Is(err, ErrSuperseded) {
		t.Fatalf("stale heartbeat accepted: %v", err)
	}
	if err := d.Release(ctx, "ep1", "s1"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Lookup(ctx, "h"); err != nil {
		t.Fatal("release by non-owner must not drop the lease")
	}
	// Lease expiry without heartbeat: the owner disappears (edge killed).
	clk.Advance(29 * time.Second)
	if err := d.Heartbeat(ctx, "ep1", "s2", 30*time.Second); err != nil {
		t.Fatal(err)
	}
	clk.Advance(29 * time.Second)
	if _, err := d.Lookup(ctx, "h"); err != nil {
		t.Fatal("heartbeat must extend lease")
	}
	clk.Advance(2 * time.Second)
	if _, err := d.Lookup(ctx, "h"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired lease still routable: %v", err)
	}
	if prev, _ := d.Claim(ctx, a, time.Minute); prev != nil {
		t.Fatal("expired owner must not be reported as previous")
	}
	d.Release(ctx, "ep1", "s1")
	if _, err := d.Lookup(ctx, "h"); !errors.Is(err, ErrNotFound) {
		t.Fatal("release failed")
	}
}
