package auth

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Token types.
const (
	TypeSession = "session" // control-plane API access for one principal
	TypeTunnel  = "tunnel"  // edge tunnel access for one endpoint
)

// MaxTokenLen bounds accepted token size before any parsing.
const MaxTokenLen = 4096

// clockSkew tolerated on exp/iat checks.
const clockSkew = 5 * time.Second

// Claims are the signed contents of a credential.
type Claims struct {
	Type      string `json:"typ"`
	Subject   string `json:"sub"`          // principal id
	Audience  string `json:"aud"`          // service the token is for
	Endpoint  string `json:"ep,omitempty"` // tunnel tokens: endpoint id
	Hostname  string `json:"host,omitempty"`
	PublicKey string `json:"pk,omitempty"` // tunnel tokens: key that must prove possession
	ID        string `json:"jti"`          // unique, for audit and revocation
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

// Signer issues tokens under one key id.
type Signer struct {
	kid  string
	priv ed25519.PrivateKey
}

// NewSigner returns a signer for key id kid.
func NewSigner(kid string, priv ed25519.PrivateKey) *Signer { return &Signer{kid: kid, priv: priv} }

// KeyID returns the id under which tokens are signed.
func (s *Signer) KeyID() string { return s.kid }

// PublicKey returns the verification key.
func (s *Signer) PublicKey() ed25519.PublicKey { return s.priv.Public().(ed25519.PublicKey) }

func tokenInput(kid string, payload []byte) []byte {
	b := append([]byte(domainToken), kid...)
	b = append(b, 0)
	return append(b, payload...)
}

// Sign returns "v1.<kid>.<payload>.<sig>" (all base64url, no padding).
func (s *Signer) Sign(c Claims) (string, error) {
	payload, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(s.priv, tokenInput(s.kid, payload))
	return "v1." + s.kid + "." + b64.EncodeToString(payload) + "." + b64.EncodeToString(sig), nil
}

// KeySet is the set of accepted verification keys. Several keys may be live
// at once, which allows overlapping verification during key rotation.
type KeySet map[string]ed25519.PublicKey

// Token verification errors.
var (
	ErrTokenMalformed  = errors.New("auth: malformed token")
	ErrTokenUnknownKey = errors.New("auth: unknown signing key")
	ErrTokenExpired    = errors.New("auth: token expired")
	ErrTokenAudience   = errors.New("auth: wrong audience or type")
)

// Verify checks signature, expiry, type and audience. The signature is
// verified before the payload is trusted or fully decoded.
func (ks KeySet) Verify(token, wantType, wantAudience string, now time.Time) (Claims, error) {
	var zero Claims
	if len(token) == 0 || len(token) > MaxTokenLen {
		return zero, ErrTokenMalformed
	}
	parts := strings.Split(token, ".")
	if len(parts) != 4 || parts[0] != "v1" || parts[1] == "" || len(parts[1]) > 64 {
		return zero, ErrTokenMalformed
	}
	pub, ok := ks[parts[1]]
	if !ok {
		return zero, ErrTokenUnknownKey
	}
	payload, err := b64.Strict().DecodeString(parts[2])
	if err != nil {
		return zero, ErrTokenMalformed
	}
	sig, err := b64.Strict().DecodeString(parts[3])
	if err != nil || len(sig) != ed25519.SignatureSize {
		return zero, ErrTokenMalformed
	}
	if !ed25519.Verify(pub, tokenInput(parts[1], payload), sig) {
		return zero, ErrBadSignature
	}
	var c Claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return zero, ErrTokenMalformed
	}
	if c.Type != wantType || c.Audience != wantAudience {
		return zero, ErrTokenAudience
	}
	if c.ID == "" || c.Subject == "" {
		return zero, ErrTokenMalformed
	}
	if now.Unix() >= c.ExpiresAt+int64(clockSkew/time.Second) {
		return zero, ErrTokenExpired
	}
	if c.IssuedAt > now.Add(clockSkew).Unix() {
		return zero, fmt.Errorf("%w: issued in the future", ErrTokenMalformed)
	}
	return c, nil
}

// PeekClaims decodes token claims WITHOUT verifying the signature. It exists
// so a client can read its own credential's ids (jti, endpoint); the result
// must never be used for any trust decision.
func PeekClaims(token string) (Claims, error) {
	var c Claims
	parts := strings.Split(token, ".")
	if len(token) > MaxTokenLen || len(parts) != 4 || parts[0] != "v1" {
		return c, ErrTokenMalformed
	}
	payload, err := b64.Strict().DecodeString(parts[2])
	if err != nil || json.Unmarshal(payload, &c) != nil {
		return Claims{}, ErrTokenMalformed
	}
	return c, nil
}
