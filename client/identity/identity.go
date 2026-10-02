// Package identity manages the client's Ed25519 identity on disk.
//
// The private key is stored as a PKCS#8 PEM under the user's config
// directory with 0600 permissions (directory 0700). It is never printed or
// sent anywhere; only the public key and fingerprint are shown.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/127ohoh1/core/protocol/auth"
)

// Identity is a loaded keypair.
type Identity struct {
	Private ed25519.PrivateKey
	Public  ed25519.PublicKey
}

// Fingerprint returns the documented key fingerprint.
func (i Identity) Fingerprint() string { return auth.Fingerprint(i.Public) }

// PublicKeyString returns the base64url public key used on the wire.
func (i Identity) PublicKeyString() string { return auth.EncodeKey(i.Public) }

// Errors.
var (
	ErrNotFound    = errors.New("identity: no identity found")
	ErrExists      = errors.New("identity: identity already exists")
	ErrPermissions = errors.New("identity: key file permissions are too open")
	ErrFormat      = errors.New("identity: unsupported key format (expected PKCS#8 Ed25519 PEM)")
)

const pemType = "PRIVATE KEY"

// DefaultPath returns $XDG_CONFIG_HOME/127ohoh1/id_ed25519 (or ~/.config/...).
func DefaultPath() (string, error) {
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "127ohoh1", "id_ed25519"), nil
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, ".config", "127ohoh1", "id_ed25519"), nil
}

// Generate creates a new identity at path. It refuses to overwrite.
func Generate(path string) (Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Identity{}, err
	}
	id := Identity{Private: priv, Public: pub}
	return id, save(path, id)
}

func save(path string, id Identity) error {
	der, err := x509.MarshalPKCS8PrivateKey(id.Private)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	// O_EXCL guarantees we never clobber an existing key; 0600 from creation.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return ErrExists
		}
		return err
	}
	if err := pem.Encode(f, &pem.Block{Type: pemType, Bytes: der}); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	return f.Close()
}

// Load reads an identity, refusing files readable by group/other.
func Load(path string) (Identity, error) {
	st, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Identity{}, ErrNotFound
		}
		return Identity{}, err
	}
	if st.Mode().Perm()&0o077 != 0 {
		return Identity{}, fmt.Errorf("%w: %s is %o, want 0600", ErrPermissions, path, st.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return Identity{}, err
	}
	return parse(b)
}

func parse(b []byte) (Identity, error) {
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != pemType {
		return Identity{}, ErrFormat
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return Identity{}, ErrFormat
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return Identity{}, ErrFormat
	}
	return Identity{Private: priv, Public: priv.Public().(ed25519.PublicKey)}, nil
}

// LoadOrGenerate loads the identity, creating one on first run. created
// reports whether a new key was generated.
func LoadOrGenerate(path string) (id Identity, created bool, err error) {
	id, err = Load(path)
	if err == nil {
		return id, false, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return Identity{}, false, err
	}
	id, err = Generate(path)
	return id, err == nil, err
}

// Import validates the PEM file at src and installs it at dst. This is the
// only way to bring an existing key in, and it refuses to overwrite.
func Import(src, dst string) (Identity, error) {
	b, err := os.ReadFile(src)
	if err != nil {
		return Identity{}, err
	}
	id, err := parse(b)
	if err != nil {
		return Identity{}, err
	}
	return id, save(dst, id)
}
