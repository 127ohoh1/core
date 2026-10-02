// Package cert is the edge's CertificateProvider boundary.
//
// One certificate covers the base domain and its wildcard (ADR 0002). The
// provider hands the *current* certificate to every TLS handshake through
// GetCertificate, so rotation is a pointer swap: established tunnels and
// in-flight requests are untouched, new handshakes see the new certificate.
//
// The public reference ships a file-based provider (development CA, or files
// written by any external ACME client such as one running DNS-01 for
// `127ohoh1.com` and `*.127ohoh1.com`). It deliberately contains no ACME
// implementation, DNS-provider credential handling or private topology.
package cert

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync/atomic"
	"time"

	"github.com/127ohoh1/core/internal/clock"
	"github.com/127ohoh1/core/internal/observability"
)

// CertificateProvider supplies TLS certificates to listeners.
type CertificateProvider interface {
	GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error)
	// NotAfter is the expiry of the certificate currently served.
	NotAfter() time.Time
}

// Metrics observed by File.
type Metrics struct {
	ExpirySeconds *observability.Gauge   // edge_certificate_expiry_seconds
	Reloads       *observability.Counter // edge_certificate_reloads_total{result}
}

// NewMetrics registers provider metrics.
func NewMetrics(r *observability.Registry) Metrics {
	return Metrics{
		ExpirySeconds: r.Gauge("edge_certificate_expiry_seconds", "Seconds until the served certificate expires (alert well before zero)."),
		Reloads:       r.Counter("edge_certificate_reloads_total", "Certificate reload attempts by result.", "result"),
	}
}

type loaded struct {
	cert     *tls.Certificate
	leaf     *x509.Certificate
	certMod  time.Time
	keyMod   time.Time
	serialHx string
}

// File loads a certificate and key from disk and reloads them atomically when
// the files change. A bad replacement (unparsable, expired, wrong names) is
// rejected and the previous certificate keeps being served.
type File struct {
	certFile, keyFile, base string
	clk                     clock.Clock
	log                     *slog.Logger
	m                       Metrics
	cur                     atomic.Pointer[loaded]
}

// NewFile loads the initial certificate; failure is fatal to startup (there is
// no insecure fallback).
func NewFile(certFile, keyFile, baseDomain string, clk clock.Clock, log *slog.Logger, m Metrics) (*File, error) {
	f := &File{certFile: certFile, keyFile: keyFile, base: baseDomain, clk: clk, log: log, m: m}
	l, err := f.load()
	if err != nil {
		return nil, err
	}
	f.cur.Store(l)
	f.m.ExpirySeconds.Set(l.leaf.NotAfter.Sub(clk.Now()).Seconds())
	return f, nil
}

func (f *File) load() (*loaded, error) {
	cst, err1 := os.Stat(f.certFile)
	kst, err2 := os.Stat(f.keyFile)
	if err := errors.Join(err1, err2); err != nil {
		return nil, err
	}
	pair, err := tls.LoadX509KeyPair(f.certFile, f.keyFile)
	if err != nil {
		return nil, fmt.Errorf("load key pair: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, err
	}
	pair.Leaf = leaf
	now := f.clk.Now()
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return nil, fmt.Errorf("certificate is not valid now (valid %s to %s)", leaf.NotBefore.Format(time.RFC3339), leaf.NotAfter.Format(time.RFC3339))
	}
	// It must actually serve tenants: the base domain and any single label under it.
	for _, h := range []string{f.base, "tenant." + f.base} {
		if err := leaf.VerifyHostname(h); err != nil {
			return nil, fmt.Errorf("certificate does not cover %q: %w", h, err)
		}
	}
	return &loaded{cert: &pair, leaf: leaf, certMod: cst.ModTime(), keyMod: kst.ModTime(), serialHx: leaf.SerialNumber.Text(16)}, nil
}

// Reload re-reads the files. The previous certificate stays active on error.
func (f *File) Reload() error {
	l, err := f.load()
	if err != nil {
		f.m.Reloads.Inc("error")
		if f.log != nil {
			f.log.Error("cert.reload_failed", observability.FieldEvent, "cert.reload_failed", "err", err.Error())
		}
		return err
	}
	old := f.cur.Load()
	f.cur.Store(l)
	f.m.ExpirySeconds.Set(l.leaf.NotAfter.Sub(f.clk.Now()).Seconds())
	f.m.Reloads.Inc("ok")
	if f.log != nil && old != nil && old.serialHx != l.serialHx {
		f.log.Info("cert.rotated", observability.FieldEvent, "cert.rotated", "not_after", l.leaf.NotAfter.Format(time.RFC3339))
	}
	return nil
}

func (f *File) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return f.cur.Load().cert, nil
}

func (f *File) NotAfter() time.Time { return f.cur.Load().leaf.NotAfter }

// Serial returns the hex serial of the certificate currently served.
func (f *File) Serial() string { return f.cur.Load().serialHx }

// Changed reports whether the files on disk differ (by mtime) from what is served.
func (f *File) changed() bool {
	l := f.cur.Load()
	cst, err1 := os.Stat(f.certFile)
	kst, err2 := os.Stat(f.keyFile)
	if err1 != nil || err2 != nil {
		return false
	}
	return !cst.ModTime().Equal(l.certMod) || !kst.ModTime().Equal(l.keyMod)
}

// Watch polls for file changes every `every` until stop is closed, reloading
// on change, and keeps the expiry gauge fresh.
func (f *File) Watch(stop <-chan struct{}, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			f.m.ExpirySeconds.Set(f.NotAfter().Sub(f.clk.Now()).Seconds())
			if f.changed() {
				_ = f.Reload()
			}
		}
	}
}
