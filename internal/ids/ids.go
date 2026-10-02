// Package ids generates opaque, sortable, prefixed identifiers such as
// ep_01J8... (a ULID: 48-bit millisecond timestamp + 80 bits of randomness).
package ids

import (
	"crypto/rand"
	"io"
	"sync"
	"time"

	"github.com/127ohoh1/core/internal/clock"
)

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// Generator produces IDs from an injectable clock and randomness source.
type Generator struct {
	clk  clock.Clock
	mu   sync.Mutex
	rand io.Reader
}

// New returns a generator using crypto/rand.
func New(clk clock.Clock) *Generator { return NewWithRand(clk, rand.Reader) }

// NewWithRand returns a generator with a deterministic randomness source (tests).
func NewWithRand(clk clock.Clock, r io.Reader) *Generator {
	return &Generator{clk: clk, rand: r}
}

// New returns "<prefix>_<ULID>".
func (g *Generator) New(prefix string) string {
	var b [16]byte
	ms := uint64(g.clk.Now().UnixMilli())
	for i := 5; i >= 0; i-- {
		b[i] = byte(ms)
		ms >>= 8
	}
	g.mu.Lock()
	_, err := io.ReadFull(g.rand, b[6:])
	g.mu.Unlock()
	if err != nil {
		panic("ids: randomness source failed: " + err.Error())
	}
	return prefix + "_" + encode(b)
}

// encode renders 128 bits as 26 Crockford base32 characters (top 2 bits zero).
func encode(b [16]byte) string {
	var out [26]byte
	var hi, lo uint64
	for i := 0; i < 8; i++ {
		hi = hi<<8 | uint64(b[i])
		lo = lo<<8 | uint64(b[8+i])
	}
	for i := 25; i >= 0; i-- {
		out[i] = crockford[lo&31]
		lo = lo>>5 | hi<<59
		hi >>= 5
	}
	return string(out[:])
}

// Time extracts the creation time embedded in an ID's ULID part, or false.
func Time(id string) (time.Time, bool) {
	if len(id) < 27 {
		return time.Time{}, false
	}
	s := id[len(id)-26:]
	var ms uint64
	for i := 0; i < 10; i++ {
		var v int = -1
		for j := 0; j < len(crockford); j++ {
			if crockford[j] == s[i] {
				v = j
				break
			}
		}
		if v < 0 {
			return time.Time{}, false
		}
		ms = ms<<5 | uint64(v)
	}
	return time.UnixMilli(int64(ms)).UTC(), true
}
