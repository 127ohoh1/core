package ids

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/127ohoh1/core/internal/clock"
)

func TestFormatAndTime(t *testing.T) {
	now := time.Date(2026, 9, 12, 20, 0, 0, 0, time.UTC)
	g := New(clock.NewFake(now))
	id := g.New("ep")
	if !strings.HasPrefix(id, "ep_") || len(id) != 3+26 {
		t.Fatalf("bad id %q", id)
	}
	got, ok := Time(id)
	if !ok || !got.Equal(now) {
		t.Fatalf("Time(%q) = %v %v", id, got, ok)
	}
}

func TestDeterministicAndUnique(t *testing.T) {
	clk := clock.NewFake(time.Unix(1_700_000_000, 0))
	g := NewWithRand(clk, bytes.NewReader(seq()))
	a, b := g.New("x"), g.New("x")
	if a == b {
		t.Fatal("expected different ids")
	}
	g2 := NewWithRand(clk, bytes.NewReader(seq()))
	if g2.New("x") != a {
		t.Fatal("not deterministic")
	}
}

func TestSortableByTime(t *testing.T) {
	clk := clock.NewFake(time.Unix(1_700_000_000, 0))
	g := New(clk)
	a := g.New("r")
	clk.Advance(time.Second)
	if b := g.New("r"); !(a < b) {
		t.Fatalf("%s !< %s", a, b)
	}
}

func seq() []byte {
	b := make([]byte, 64)
	for i := range b {
		b[i] = byte(i*7 + 3)
	}
	return b
}
