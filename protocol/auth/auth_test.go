package auth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 9, 12, 20, 0, 0, 0, time.UTC)

func newKey(t testing.TB) (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func chal(pub ed25519.PublicKey) Challenge {
	return Challenge{ID: "ch_1", Nonce: bytes.Repeat([]byte{9}, 32), Audience: "127ohoh1-control",
		Fingerprint: Fingerprint(pub), IssuedAt: t0, ExpiresAt: t0.Add(time.Minute)}
}

func TestChallengeSignVerify(t *testing.T) {
	pub, priv := newKey(t)
	c := chal(pub)
	sig, err := SignChallenge(priv, c)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyChallenge(pub, c, sig); err != nil {
		t.Fatal(err)
	}
	other, _ := newKey(t)
	if err := VerifyChallenge(other, c, sig); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("wrong key accepted: %v", err)
	}
}

// Every field is bound: changing any of them invalidates the signature.
func TestChallengeFieldsAreBound(t *testing.T) {
	pub, priv := newKey(t)
	c := chal(pub)
	sig, _ := SignChallenge(priv, c)
	mut := []func(*Challenge){
		func(c *Challenge) { c.ID = "ch_2" },
		func(c *Challenge) { c.Nonce = bytes.Repeat([]byte{8}, 32) },
		func(c *Challenge) { c.Audience = "other" },
		func(c *Challenge) { c.Fingerprint = "x" },
		func(c *Challenge) { c.ExpiresAt = c.ExpiresAt.Add(time.Second) },
		func(c *Challenge) { c.IssuedAt = c.IssuedAt.Add(time.Second) },
	}
	for i, m := range mut {
		c2 := c
		m(&c2)
		if VerifyChallenge(pub, c2, sig) == nil {
			t.Errorf("mutation %d not detected", i)
		}
	}
}

// Field boundaries must be unambiguous: moving bytes between adjacent fields
// must change the canonical encoding.
func TestCanonicalEncodingUnambiguous(t *testing.T) {
	pub, _ := newKey(t)
	a := chal(pub)
	b := a
	a.ID, a.Audience = "ab", "c"
	b.ID, b.Audience = "a", "bc"
	ba, _ := ChallengeBytes(a)
	bb, _ := ChallengeBytes(b)
	if bytes.Equal(ba, bb) {
		t.Fatal("ambiguous canonical encoding")
	}
}

func TestShortNonceRejected(t *testing.T) {
	pub, _ := newKey(t)
	c := chal(pub)
	c.Nonce = make([]byte, 15)
	if _, err := ChallengeBytes(c); err == nil {
		t.Fatal("nonce below 128 bits must be rejected")
	}
}

func TestParsePublicKey(t *testing.T) {
	pub, _ := newKey(t)
	s := EncodeKey(pub)
	got, err := ParsePublicKey(s)
	if err != nil || !bytes.Equal(got, pub) {
		t.Fatalf("roundtrip: %v", err)
	}
	for _, bad := range []string{"", "abc", s + "=", s[:len(s)-1], s + "A", strings.Repeat("A", 44)} {
		if _, err := ParsePublicKey(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestTunnelProofBinding(t *testing.T) {
	a := TunnelProofBytes([]byte("exp"), []byte("n"), "jti", "ep_1")
	for _, b := range [][]byte{
		TunnelProofBytes([]byte("exq"), []byte("n"), "jti", "ep_1"),
		TunnelProofBytes([]byte("exp"), []byte("m"), "jti", "ep_1"),
		TunnelProofBytes([]byte("exp"), []byte("n"), "jt2", "ep_1"),
		TunnelProofBytes([]byte("exp"), []byte("n"), "jti", "ep_2"),
	} {
		if bytes.Equal(a, b) {
			t.Fatal("proof not bound to all inputs")
		}
	}
}

func claims(typ, aud string, exp time.Time) Claims {
	return Claims{Type: typ, Subject: "pr_1", Audience: aud, ID: "tok_1", IssuedAt: t0.Unix(), ExpiresAt: exp.Unix()}
}

func TestTokenRoundTripAndRejections(t *testing.T) {
	pub, priv := newKey(t)
	s := NewSigner("k1", priv)
	ks := KeySet{"k1": pub}
	tok, err := s.Sign(claims(TypeSession, "control", t0.Add(time.Minute)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ks.Verify(tok, TypeSession, "control", t0); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		fn   func() error
		want error
	}{
		{"expired", func() error { _, e := ks.Verify(tok, TypeSession, "control", t0.Add(2*time.Minute)); return e }, ErrTokenExpired},
		{"audience", func() error { _, e := ks.Verify(tok, TypeSession, "edge", t0); return e }, ErrTokenAudience},
		{"type", func() error { _, e := ks.Verify(tok, TypeTunnel, "control", t0); return e }, ErrTokenAudience},
		{"unknown kid", func() error { _, e := KeySet{}.Verify(tok, TypeSession, "control", t0); return e }, ErrTokenUnknownKey},
		{"tampered", func() error {
			p := strings.Split(tok, ".")
			p[2] = b64.EncodeToString([]byte(`{"typ":"session","sub":"evil","aud":"control","jti":"x","exp":9999999999}`))
			_, e := ks.Verify(strings.Join(p, "."), TypeSession, "control", t0)
			return e
		}, ErrBadSignature},
		{"other key", func() error {
			p2, _ := newKey(t)
			_, e := KeySet{"k1": p2}.Verify(tok, TypeSession, "control", t0)
			return e
		}, ErrBadSignature},
		{"garbage", func() error { _, e := ks.Verify("a.b", TypeSession, "control", t0); return e }, ErrTokenMalformed},
		{"oversize", func() error {
			_, e := ks.Verify(strings.Repeat("a", MaxTokenLen+1), TypeSession, "control", t0)
			return e
		}, ErrTokenMalformed},
	}
	for _, c := range cases {
		if err := c.fn(); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v want %v", c.name, err, c.want)
		}
	}
}

// Rotation: tokens from the old key verify while both keys are published.
func TestKeyRotationOverlap(t *testing.T) {
	pub1, priv1 := newKey(t)
	pub2, priv2 := newKey(t)
	old, _ := NewSigner("k1", priv1).Sign(claims(TypeSession, "control", t0.Add(time.Minute)))
	neu, _ := NewSigner("k2", priv2).Sign(claims(TypeSession, "control", t0.Add(time.Minute)))
	both := KeySet{"k1": pub1, "k2": pub2}
	for _, tok := range []string{old, neu} {
		if _, err := both.Verify(tok, TypeSession, "control", t0); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := (KeySet{"k2": pub2}).Verify(old, TypeSession, "control", t0); !errors.Is(err, ErrTokenUnknownKey) {
		t.Fatal("retired key must stop verifying")
	}
}

func FuzzParsePublicKey(f *testing.F) {
	pub, _ := newKey(f)
	f.Add(EncodeKey(pub))
	f.Add("")
	f.Add("====")
	f.Fuzz(func(t *testing.T, s string) {
		k, err := ParsePublicKey(s)
		if err == nil && (len(k) != 32 || EncodeKey(k) != s) {
			t.Fatalf("accepted non-canonical key %q", s)
		}
	})
}

func FuzzChallengeBytes(f *testing.F) {
	f.Add("id", []byte("0123456789abcdef"), "aud", "fp", int64(1), int64(2))
	f.Fuzz(func(t *testing.T, id string, nonce []byte, aud, fp string, iat, exp int64) {
		c := Challenge{ID: id, Nonce: nonce, Audience: aud, Fingerprint: fp, IssuedAt: time.Unix(iat, 0), ExpiresAt: time.Unix(exp, 0)}
		b1, err1 := ChallengeBytes(c)
		b2, err2 := ChallengeBytes(c)
		if (err1 == nil) != (err2 == nil) || !bytes.Equal(b1, b2) {
			t.Fatal("non-deterministic")
		}
	})
}

func FuzzVerifyToken(f *testing.F) {
	pub, priv := newKey(f)
	tok, _ := NewSigner("k", priv).Sign(claims(TypeSession, "a", t0.Add(time.Hour)))
	f.Add(tok)
	f.Add("v1.k..")
	ks := KeySet{"k": pub}
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = ks.Verify(s, TypeSession, "a", t0) // must never panic
	})
}
