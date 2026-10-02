// Package devtls generates a throwaway local CA and server certificate for
// development and tests. It is NOT for production: the private keys live on
// local disk and the CA is self-issued. Production certificates come from a
// CertificateProvider (see docs/operations.md).
package devtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io/fs"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// Bundle is a CA plus a leaf certificate, PEM encoded.
type Bundle struct {
	CAPEM, CertPEM, KeyPEM []byte
	// CAKeyPEM lets a development setup re-issue leaf certificates under the
	// same CA (certificate rotation tests). Never present in real deployments.
	CAKeyPEM []byte
}

// Generate creates a fresh CA and a leaf valid for names (DNS names, wildcards
// and IP literals).
func Generate(names []string, now time.Time) (Bundle, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Bundle{}, err
	}
	caTmpl := &x509.Certificate{
		SerialNumber: serial(), Subject: pkix.Name{CommonName: "127ohoh1 development CA (NOT FOR PRODUCTION)"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return Bundle{}, err
	}
	caCert, _ := x509.ParseCertificate(caDER)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Bundle{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(), Subject: pkix.Name{CommonName: "127ohoh1 development"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(90 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, n)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return Bundle{}, err
	}
	kder, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return Bundle{}, err
	}
	cakder, err := x509.MarshalPKCS8PrivateKey(caKey)
	if err != nil {
		return Bundle{}, err
	}
	return Bundle{
		CAPEM:    pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		CertPEM:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:   pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}),
		CAKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: cakder}),
	}, nil
}

// Reissue creates a fresh leaf certificate and key for names under the
// existing CA of b, as an ACME renewal would: same trust anchor, new key and
// serial. validFor sets the lifetime (short values exercise renewal paths).
func Reissue(b Bundle, names []string, now time.Time, validFor time.Duration) (Bundle, error) {
	caBlk, _ := pem.Decode(b.CAPEM)
	keyBlk, _ := pem.Decode(b.CAKeyPEM)
	if caBlk == nil || keyBlk == nil {
		return Bundle{}, errors.New("devtls: bundle has no CA key to re-issue with")
	}
	caCert, err := x509.ParseCertificate(caBlk.Bytes)
	if err != nil {
		return Bundle{}, err
	}
	ck, err := x509.ParsePKCS8PrivateKey(keyBlk.Bytes)
	if err != nil {
		return Bundle{}, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Bundle{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(), Subject: pkix.Name{CommonName: "127ohoh1 development"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(validFor),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, n)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, ck)
	if err != nil {
		return Bundle{}, err
	}
	kder, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return Bundle{}, err
	}
	out := b
	out.CertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	out.KeyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder})
	return out, nil
}

// Write stores the leaf certificate and key in dir atomically (rename), the
// way a certificate manager should, so a reader never sees a torn pair.
func (b Bundle) WriteLeaf(dir string) error {
	for name, data := range map[string][]byte{"cert.pem": b.CertPEM, "key.pem": b.KeyPEM} {
		mode := fs.FileMode(0o644)
		if name == "key.pem" {
			mode = 0o600
		}
		tmp := filepath.Join(dir, name+".tmp")
		if err := os.WriteFile(tmp, data, mode); err != nil {
			return err
		}
		if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
			return err
		}
	}
	return nil
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 100))
	return n
}

// LoadOrGenerate persists a bundle under dir (ca.pem, cert.pem, key.pem),
// generating it on first use. The key file is written 0600.
func LoadOrGenerate(dir string, names []string, now time.Time) (Bundle, error) {
	read := func() (Bundle, error) {
		ca, err1 := os.ReadFile(filepath.Join(dir, "ca.pem"))
		c, err2 := os.ReadFile(filepath.Join(dir, "cert.pem"))
		k, err3 := os.ReadFile(filepath.Join(dir, "key.pem"))
		cak, _ := os.ReadFile(filepath.Join(dir, "ca-key.pem")) // optional
		return Bundle{CAPEM: ca, CertPEM: c, KeyPEM: k, CAKeyPEM: cak}, errors.Join(err1, err2, err3)
	}
	if b, err := read(); err == nil {
		if cert, err := b.Certificate(); err == nil && len(cert.Certificate) > 0 {
			if leaf, err := x509.ParseCertificate(cert.Certificate[0]); err == nil && leaf.NotAfter.After(now.Add(24*time.Hour)) {
				return b, nil
			}
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		// unreadable/partial state: regenerate below
	}
	b, err := Generate(names, now)
	if err != nil {
		return Bundle{}, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Bundle{}, err
	}
	for name, data := range map[string][]byte{"ca.pem": b.CAPEM, "cert.pem": b.CertPEM, "key.pem": b.KeyPEM, "ca-key.pem": b.CAKeyPEM} {
		mode := fs.FileMode(0o644)
		if name == "key.pem" || name == "ca-key.pem" {
			mode = 0o600
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, mode); err != nil {
			return Bundle{}, err
		}
	}
	return b, nil
}

// Certificate parses the leaf certificate and key.
func (b Bundle) Certificate() (tls.Certificate, error) { return tls.X509KeyPair(b.CertPEM, b.KeyPEM) }

// CAPool returns a pool trusting the development CA.
func (b Bundle) CAPool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AppendCertsFromPEM(b.CAPEM)
	return p
}
