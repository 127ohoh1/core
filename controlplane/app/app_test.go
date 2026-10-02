package app

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/127ohoh1/core/internal/config"
	"github.com/127ohoh1/core/internal/observability"
	"github.com/127ohoh1/core/protocol/auth"
)

func baseCfg() config.ControlPlane {
	c := config.DefaultControlPlane()
	c.AppEnv, c.EdgeServiceToken, c.EdgeTunnelAddr = config.EnvTest, strings.Repeat("s", 32), "127.0.0.1:7443"
	return c
}

func newKey(t *testing.T) ed25519.PrivateKey {
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// Key rotation: tokens signed by the retired key keep verifying while it is
// listed as a previous verification key; after removal they stop.
func TestSigningKeyRotationOverlap(t *testing.T) {
	log := observability.NewLogger(io.Discard, "error", "t")
	oldPriv, newPriv := newKey(t), newKey(t)
	oldPub := oldPriv.Public().(ed25519.PublicKey)
	now := time.Now()
	claims := auth.Claims{Type: auth.TypeTunnel, Subject: "pr", Audience: "127ohoh1-edge", ID: "t1", IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix()}
	oldTok, _ := auth.NewSigner(KeyID(oldPub), oldPriv).Sign(claims)

	cfg := baseCfg()
	cfg.PreviousVerifyKeys = KeyID(oldPub) + "=" + auth.EncodeKey(oldPub)
	rotated, err := New(cfg, Options{Log: log, SigningKey: newPriv})
	if err != nil {
		t.Fatal(err)
	}
	if len(rotated.Keys) != 2 {
		t.Fatalf("published keys: %d", len(rotated.Keys))
	}
	if _, err := rotated.Keys.Verify(oldTok, auth.TypeTunnel, "127ohoh1-edge", now); err != nil {
		t.Fatalf("credential signed by the retired key must verify during the overlap: %v", err)
	}
	newTok, _ := rotated.Signer.Sign(claims)
	if _, err := rotated.Keys.Verify(newTok, auth.TypeTunnel, "127ohoh1-edge", now); err != nil {
		t.Fatal(err)
	}
	if rotated.Signer.KeyID() == KeyID(oldPub) {
		t.Fatal("must sign with the new key")
	}
	// Overlap over: the old key is removed and its credentials die.
	done, _ := New(baseCfg(), Options{Log: log, SigningKey: newPriv})
	if _, err := done.Keys.Verify(oldTok, auth.TypeTunnel, "127ohoh1-edge", now); !errors.Is(err, auth.ErrTokenUnknownKey) {
		t.Fatalf("retired key still accepted: %v", err)
	}
}

func TestPreviousKeysValidation(t *testing.T) {
	log := observability.NewLogger(io.Discard, "error", "t")
	cur := newKey(t)
	for name, v := range map[string]string{
		"malformed":      "nokeyvalue",
		"bad key":        "k1=notbase64!!",
		"duplicate kid":  "k1=" + auth.EncodeKey(newKey(t).Public().(ed25519.PublicKey)) + ",k1=" + auth.EncodeKey(newKey(t).Public().(ed25519.PublicKey)),
		"equals current": KeyID(cur.Public().(ed25519.PublicKey)) + "=" + auth.EncodeKey(newKey(t).Public().(ed25519.PublicKey)),
	} {
		cfg := baseCfg()
		cfg.PreviousVerifyKeys = v
		if _, err := New(cfg, Options{Log: log, SigningKey: cur}); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestSigningKeyFileLoadingRules(t *testing.T) {
	dir := t.TempDir()
	cfg := baseCfg()
	cfg.SigningKeyFile = filepath.Join(dir, "missing")
	if _, err := New(cfg, Options{Log: observability.NewLogger(io.Discard, "error", "t")}); err == nil {
		t.Fatal("missing key file accepted")
	}
	os.WriteFile(cfg.SigningKeyFile, []byte("short\n"), 0o600)
	if _, err := New(cfg, Options{Log: observability.NewLogger(io.Discard, "error", "t")}); err == nil {
		t.Fatal("malformed seed accepted")
	}
	// Production without a key file must not fall back to an ephemeral key.
	prod := baseCfg()
	prod.AppEnv = config.EnvProduction
	if _, err := LoadSigningKey(prod, nil); err == nil {
		t.Fatal("production must not generate an ephemeral signing key")
	}
}
