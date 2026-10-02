package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadFileAndEnvOverride(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "c.json")
	os.WriteFile(f, []byte(`{"listen_addr":":1","session_ttl":"5m"}`), 0o600)
	t.Setenv("OHOH_LISTEN_ADDR", ":2")
	t.Setenv("OHOH_DEVELOPMENT_PAYMENTS", "true")
	c := DefaultControlPlane()
	if err := Load(&c, f, "OHOH_"); err != nil {
		t.Fatal(err)
	}
	if c.ListenAddr != ":2" || c.SessionTTL.D() != 5*time.Minute || !c.DevelopmentPayments {
		t.Fatalf("%+v", c)
	}
}

func TestLoadRejectsUnknownField(t *testing.T) {
	f := filepath.Join(t.TempDir(), "c.json")
	os.WriteFile(f, []byte(`{"nope":1}`), 0o600)
	c := DefaultControlPlane()
	if err := Load(&c, f, "OHOH_"); err == nil {
		t.Fatal("expected error")
	}
}

func validCP() ControlPlane {
	c := DefaultControlPlane()
	c.EdgeServiceToken = strings.Repeat("a", 32)
	c.EdgeTunnelAddr = "localhost:7443"
	return c
}

func TestProductionRefusesDevelopmentPayments(t *testing.T) {
	c := validCP()
	c.AppEnv = EnvProduction
	c.SigningKeyFile = "/k"
	c.DevelopmentPayments = true
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "development_payments") {
		t.Fatalf("got %v", err)
	}
	c.DevelopmentPayments = false
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c.SigningKeyFile = ""
	if c.Validate() == nil {
		t.Fatal("production must require a signing key")
	}
}

func TestEdgeValidation(t *testing.T) {
	e := DefaultEdge()
	e.ControlPlaneURL = "http://cp"
	e.EdgeServiceToken = strings.Repeat("x", 16)
	if err := e.Validate(); err != nil {
		t.Fatal(err)
	}
	e.AppEnv = EnvProduction
	if e.Validate() == nil {
		t.Fatal("production without certs must fail")
	}
	e = DefaultEdge()
	e.ControlPlaneURL, e.EdgeServiceToken = "http://cp", strings.Repeat("x", 16)
	e.StreamWindow = 10
	if e.Validate() == nil {
		t.Fatal("bad windows must fail")
	}
}

func TestParseVerifyKeys(t *testing.T) {
	ks, err := ParseVerifyKeys(" k1=AAA , k2=BBB ,, ")
	if err != nil || len(ks) != 2 || ks[0].KID != "k1" || ks[1].PublicKey != "BBB" {
		t.Fatalf("%+v %v", ks, err)
	}
	for _, bad := range []string{"k1", "=x", "k1=", "k1=a,k1=b"} {
		if _, err := ParseVerifyKeys(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if ks, err := ParseVerifyKeys(""); err != nil || len(ks) != 0 {
		t.Fatal("empty must be valid and empty")
	}
}

func FuzzParseVerifyKeys(f *testing.F) {
	f.Add("k1=abc,k2=def")
	f.Add("")
	f.Add("=,==,")
	f.Fuzz(func(t *testing.T, s string) {
		ks, err := ParseVerifyKeys(s)
		if err != nil {
			return
		}
		seen := map[string]bool{}
		for _, k := range ks {
			if k.KID == "" || k.PublicKey == "" || len(k.KID) > 64 || seen[k.KID] {
				t.Fatalf("accepted bad entry %+v from %q", k, s)
			}
			seen[k.KID] = true
		}
	})
}
