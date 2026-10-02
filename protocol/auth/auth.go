// Package auth defines the cryptographic primitives shared by client, control
// plane and edge: key fingerprints, the canonical challenge signature input,
// and short-lived signed credentials.
//
// Design rules (see docs/threat-model.md):
//   - public keys are identifiers, never bearer credentials;
//   - every signature input is domain-separated and length-prefixed, so no
//     field boundary is ambiguous;
//   - credentials are scoped (audience, type, endpoint) and expire quickly.
package auth

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// Version is the authentication protocol version embedded in signed bytes.
const Version uint16 = 1

const (
	domainChallenge = "127ohoh1/auth-challenge/v1\x00"
	domainToken     = "127ohoh1/token/v1\x00"
	domainTunnel    = "127ohoh1/tunnel-proof/v1\x00"

	// MinNonceBytes is the minimum entropy of a challenge nonce (128 bits).
	MinNonceBytes = 16
	// MaxFieldLen bounds every field that enters a signed byte string.
	MaxFieldLen = 1024
)

// Errors returned by verification. Callers must not distinguish them to
// unauthenticated peers beyond what the API contract states.
var (
	ErrBadKey       = errors.New("auth: invalid public key")
	ErrBadSignature = errors.New("auth: signature verification failed")
	ErrBadField     = errors.New("auth: invalid field")
)

var b64 = base64.RawURLEncoding

// EncodeKey renders a public key as unpadded base64url.
func EncodeKey(pub ed25519.PublicKey) string { return b64.EncodeToString(pub) }

// ParsePublicKey accepts exactly a 32-byte Ed25519 key in unpadded base64url.
// Any other format (length, padding, alphabet) is rejected.
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	if len(s) != b64.EncodedLen(ed25519.PublicKeySize) {
		return nil, ErrBadKey
	}
	raw, err := b64.Strict().DecodeString(s)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, ErrBadKey
	}
	return ed25519.PublicKey(raw), nil
}

// NonceDecode decodes a base64url nonce or signature string (strict, unpadded).
func NonceDecode(s string) ([]byte, error) { return b64.Strict().DecodeString(s) }

// EncodeSig renders signature bytes as unpadded base64url.
func EncodeSig(sig []byte) string { return b64.EncodeToString(sig) }

// Fingerprint is base64url(sha256(public key bytes)). It identifies a key but
// proves nothing about possession of the private key.
func Fingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return b64.EncodeToString(sum[:])
}

// Challenge is the server-issued material a client signs.
type Challenge struct {
	ID          string
	Nonce       []byte // >= MinNonceBytes of CSPRNG output
	Audience    string
	Fingerprint string // key the challenge was issued to
	IssuedAt    time.Time
	ExpiresAt   time.Time
}

func appendField(b, f []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(f)))
	return append(b, f...)
}

func appendU64(b []byte, v uint64) []byte { return binary.BigEndian.AppendUint64(b, v) }

// ChallengeBytes returns the canonical signing input:
//
//	domain || u16 version || lp(id) || lp(nonce) || lp(audience) || lp(fingerprint) || u64 issued || u64 expires
//
// where lp is a u32 big-endian length prefix. It is deterministic and
// injective for valid inputs.
func ChallengeBytes(c Challenge) ([]byte, error) {
	if len(c.Nonce) < MinNonceBytes {
		return nil, fmt.Errorf("%w: nonce shorter than %d bytes", ErrBadField, MinNonceBytes)
	}
	for _, f := range []string{c.ID, c.Audience, c.Fingerprint} {
		if f == "" || len(f) > MaxFieldLen {
			return nil, ErrBadField
		}
	}
	if len(c.Nonce) > MaxFieldLen {
		return nil, ErrBadField
	}
	b := make([]byte, 0, 128+len(c.Nonce))
	b = append(b, domainChallenge...)
	b = binary.BigEndian.AppendUint16(b, Version)
	b = appendField(b, []byte(c.ID))
	b = appendField(b, c.Nonce)
	b = appendField(b, []byte(c.Audience))
	b = appendField(b, []byte(c.Fingerprint))
	b = appendU64(b, uint64(c.IssuedAt.Unix()))
	b = appendU64(b, uint64(c.ExpiresAt.Unix()))
	return b, nil
}

// SignChallenge signs the canonical challenge bytes.
func SignChallenge(priv ed25519.PrivateKey, c Challenge) ([]byte, error) {
	b, err := ChallengeBytes(c)
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(priv, b), nil
}

// VerifyChallenge verifies sig over the canonical bytes. It does not check
// expiry or single use; that is the caller's (atomic) responsibility.
func VerifyChallenge(pub ed25519.PublicKey, c Challenge, sig []byte) error {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return ErrBadSignature
	}
	b, err := ChallengeBytes(c)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, b, sig) {
		return ErrBadSignature
	}
	return nil
}

// NonceHash is the stored form of a nonce; the server keeps only the hash.
func NonceHash(nonce []byte) []byte {
	h := sha256.Sum256(nonce)
	return h[:]
}

// HashEqual compares two hashes in constant time.
func HashEqual(a, b []byte) bool { return subtle.ConstantTimeCompare(a, b) == 1 }

// TunnelProofBytes is what a tunnel client signs to prove possession of the
// key named in its credential. It binds the proof to (a) this TLS connection
// via the RFC 5705/8446 exporter value, (b) the edge's per-connection nonce,
// (c) the credential id and (d) the endpoint, so a captured proof cannot be
// replayed on another connection or for another endpoint.
func TunnelProofBytes(exporter, serverNonce []byte, jti, endpointID string) []byte {
	b := make([]byte, 0, 160)
	b = append(b, domainTunnel...)
	b = binary.BigEndian.AppendUint16(b, Version)
	b = appendField(b, exporter)
	b = appendField(b, serverNonce)
	b = appendField(b, []byte(jti))
	b = appendField(b, []byte(endpointID))
	return b
}
