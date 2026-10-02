package endpoint

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"sync"
)

// Name validation errors.
var (
	ErrNameInvalid  = errors.New("endpoint: invalid name")
	ErrNameReserved = errors.New("endpoint: name is reserved by the platform")
	ErrNameRejected = errors.New("endpoint: name rejected by policy")
)

// platformLabels can never be allocated to tenants.
var platformLabels = map[string]bool{
	"api": true, "www": true, "admin": true, "status": true, "ingress": true, "edge": true, "support": true,
	"app": true, "auth": true, "billing": true, "control": true, "dashboard": true, "docs": true, "mail": true,
	"metrics": true, "root": true, "security": true, "abuse": true, "tunnel": true, "cdn": true, "static": true,
}

// NormalizeName lowercases and validates a DNS label: 3-63 ASCII characters,
// [a-z0-9-], alphanumeric at both ends. Whitespace is not trimmed: a name
// with spaces is an error, not silently repaired.
func NormalizeName(s string) (string, error) {
	n := strings.ToLower(s)
	if len(n) < 3 || len(n) > 63 {
		return "", ErrNameInvalid
	}
	for i := 0; i < len(n); i++ {
		c := n[i]
		ok := c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-'
		if !ok {
			return "", ErrNameInvalid
		}
	}
	if n[0] == '-' || n[len(n)-1] == '-' {
		return "", ErrNameInvalid
	}
	return n, nil
}

// NameValidator is the replaceable policy hook for reserved and confusable names.
type NameValidator interface {
	Validate(name string) error
}

// DefaultNameValidator denies platform labels, punycode (xn--, a homograph
// vector) and other "--" at positions 3-4 that are reserved by IDNA.
type DefaultNameValidator struct{}

func (DefaultNameValidator) Validate(name string) error {
	if platformLabels[name] {
		return ErrNameReserved
	}
	if strings.HasPrefix(name, "xn--") || (len(name) >= 4 && name[2:4] == "--") {
		return ErrNameRejected
	}
	return nil
}

// ValidateName normalizes then applies the validator.
func ValidateName(v NameValidator, s string) (string, error) {
	n, err := NormalizeName(s)
	if err != nil {
		return "", err
	}
	if err := v.Validate(n); err != nil {
		return "", err
	}
	return n, nil
}

// NameAllocator produces candidate random hostnames.
type NameAllocator interface {
	Allocate(ctx context.Context) (string, error)
}

var adjectives = []string{"quiet", "brave", "calm", "eager", "fancy", "gentle", "happy", "icy", "jolly", "keen",
	"lucky", "merry", "noble", "proud", "rapid", "shiny", "swift", "tidy", "vivid", "witty", "young", "zesty",
	"amber", "bright", "clever", "dusty", "early", "fuzzy", "golden", "hollow", "ivory", "misty"}

var nouns = []string{"river", "meadow", "falcon", "harbor", "island", "jungle", "koala", "lagoon", "maple", "nebula",
	"orchid", "pebble", "quartz", "rocket", "summit", "tundra", "valley", "willow", "yonder", "zephyr",
	"anchor", "beacon", "canyon", "delta", "ember", "forest", "glacier", "horizon", "iris", "juniper", "lantern", "marsh"}

// RandomAllocator generates "adjective-noun-xxxx" (32*32*65536 ~ 6.7e7
// combinations). Uniqueness is *not* guaranteed here; the registry's unique
// constraint is authoritative and callers retry boundedly.
type RandomAllocator struct {
	mu   sync.Mutex
	rand io.Reader
}

// NewRandomAllocator uses crypto/rand. Pass a reader for deterministic tests.
func NewRandomAllocator(r io.Reader) *RandomAllocator {
	if r == nil {
		r = rand.Reader
	}
	return &RandomAllocator{rand: r}
}

func (a *RandomAllocator) Allocate(ctx context.Context) (string, error) {
	var b [4]byte
	a.mu.Lock()
	_, err := io.ReadFull(a.rand, b[:])
	a.mu.Unlock()
	if err != nil {
		return "", err
	}
	adj := adjectives[int(b[0])%len(adjectives)]
	noun := nouns[int(b[1])%len(nouns)]
	return adj + "-" + noun + "-" + hex.EncodeToString(b[2:]), nil
}
