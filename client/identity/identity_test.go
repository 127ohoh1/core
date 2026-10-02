package identity

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateLoadRoundTripAndPerms(t *testing.T) {
	p := filepath.Join(t.TempDir(), "cfg", "id_ed25519")
	id, created, err := LoadOrGenerate(p)
	if err != nil || !created {
		t.Fatal(err, created)
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("file mode %o", st.Mode().Perm())
	}
	dst, _ := os.Stat(filepath.Dir(p))
	if dst.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %o", dst.Mode().Perm())
	}
	again, created, err := LoadOrGenerate(p)
	if err != nil || created || again.Fingerprint() != id.Fingerprint() {
		t.Fatal("identity must be stable across runs")
	}
}

func TestLoadRefusesOpenPermissions(t *testing.T) {
	p := filepath.Join(t.TempDir(), "id")
	Generate(p)
	os.Chmod(p, 0o644)
	if _, err := Load(p); !errors.Is(err, ErrPermissions) {
		t.Fatalf("got %v", err)
	}
}

func TestGenerateNeverOverwrites(t *testing.T) {
	p := filepath.Join(t.TempDir(), "id")
	a, _ := Generate(p)
	if _, err := Generate(p); !errors.Is(err, ErrExists) {
		t.Fatalf("got %v", err)
	}
	b, _ := Load(p)
	if a.Fingerprint() != b.Fingerprint() {
		t.Fatal("key was clobbered")
	}
}

func TestImport(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	orig, _ := Generate(src)
	dst := filepath.Join(dir, "cfg", "id")
	got, err := Import(src, dst)
	if err != nil || got.Fingerprint() != orig.Fingerprint() {
		t.Fatal(err)
	}
	if _, err := Import(src, dst); !errors.Is(err, ErrExists) {
		t.Fatalf("import must not overwrite: %v", err)
	}
	bad := filepath.Join(dir, "bad")
	os.WriteFile(bad, []byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"), 0o600)
	if _, err := Import(bad, filepath.Join(dir, "x")); !errors.Is(err, ErrFormat) {
		t.Fatalf("got %v", err)
	}
}

func TestPublicOutputDoesNotContainPrivateKey(t *testing.T) {
	id, _ := Generate(filepath.Join(t.TempDir(), "id"))
	if strings.Contains(id.PublicKeyString(), string(id.Private[:8])) {
		t.Fatal("unexpected")
	}
	if len(id.PublicKeyString()) != 43 {
		t.Fatal("public key encoding length")
	}
}
