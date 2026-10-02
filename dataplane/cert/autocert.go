// On-demand HTTP-01 certificates, for domains whose registrar offers no
// automatable DNS-01 API. Instead of one wildcard certificate (ADR 0002's
// preferred shape), each hostname gets its own certificate the first time it
// is dialled, cached to disk and renewed automatically by the underlying
// library well before expiry. See docs/adr/0009-http01-autocert-deviation.md.
package cert

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

// Autocert is a CertificateProvider backed by golang.org/x/crypto/acme/autocert.
type Autocert struct {
	mgr  *autocert.Manager
	leaf atomic.Pointer[x509.Certificate]
}

// NewAutocert builds an on-demand provider and the plain-HTTP handler that
// must be reachable on port 80 for every accepted hostname (directly, or
// forwarded there by a router) to complete ACME HTTP-01 challenges and to
// redirect other plaintext requests to https.
//
// Accepted hostnames: baseDomain, "www."+baseDomain, each of extra verbatim
// (e.g. a fixed tunnel-control hostname), and any single DNS label under
// baseDomain (one tenant subdomain, e.g. "quiet-river-7f2c."+baseDomain, but
// not a deeper name) **that knownTenant confirms has a live tunnel**.
// Without that check, anyone could trigger a real ACME issuance for an
// arbitrary never-used name just by dialling it with that SNI — no
// reservation or payment required — and spraying enough distinct names
// could exhaust Let's Encrypt's per-registered-domain rate limit and deny
// legitimate customers' first certificate (found in the 2026-10-01 security
// review; see docs/adr/0009-http01-autocert-deviation.md). knownTenant
// should be backed by the same routing.TunnelDirectory the ingress handler
// already consults: a cert is only useful once a tunnel exists to proxy to
// anyway, so this never blocks a legitimate first real visit.
//
// cacheDir persists issued certificates and their keys across restarts; it
// must be writable and should not be world-readable.
func NewAutocert(cacheDir, baseDomain, email string, extra []string, knownTenant func(ctx context.Context, label string) bool) (*Autocert, http.Handler) {
	a := &Autocert{}
	a.mgr = &autocert.Manager{
		Prompt: autocert.AcceptTOS,
		Cache:  autocert.DirCache(cacheDir),
		Email:  email,
		HostPolicy: func(ctx context.Context, host string) error {
			label, isTenantCandidate, allowed := classifyAutocertHost(baseDomain, extra, host)
			if !allowed {
				return fmt.Errorf("cert: host %q is not served here", host)
			}
			if isTenantCandidate && (knownTenant == nil || !knownTenant(ctx, label)) {
				return fmt.Errorf("cert: host %q has no live tunnel", host)
			}
			return nil
		},
	}
	// Never redirect (or serve a challenge response) for a host we don't
	// recognize at all -- the library's default handler reflects the Host
	// header verbatim into a redirect Location with no validation, which is
	// an open redirect for any Host an attacker can get to this server
	// (also found in the 2026-10-01 review). The shape check alone (not
	// knownTenant) is enough here: redirecting a syntactically valid tenant
	// hostname to itself over https is harmless even before it has a live
	// tunnel -- it will just 404 at the application layer, same as today.
	handler := a.mgr.HTTPHandler(nil)
	filtered := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !AutocertHostAllowed(baseDomain, extra, hostOnly(r.Host)) {
			http.NotFound(w, r)
			return
		}
		handler.ServeHTTP(w, r)
	})
	return a, filtered
}

func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}

// classifyAutocertHost is AutocertHostAllowed's underlying logic, additionally
// reporting whether host is a tenant-subdomain candidate (and, if so, its
// label) so the caller can apply an extra check before issuing for one.
func classifyAutocertHost(baseDomain string, extra []string, host string) (label string, isTenantCandidate, allowed bool) {
	base := strings.ToLower(baseDomain)
	host = strings.ToLower(host)
	if host == base || host == "www."+base {
		return "", false, true
	}
	for _, h := range extra {
		if host == strings.ToLower(h) {
			return "", false, true
		}
	}
	if l, ok := strings.CutSuffix(host, "."+base); ok && l != "" && !strings.Contains(l, ".") {
		return l, true, true
	}
	return "", false, false
}

// AutocertHostAllowed reports whether host is *shaped* like something this
// deployment serves: baseDomain itself, "www."+baseDomain, any single DNS
// label directly under baseDomain (one tenant subdomain, not a deeper name),
// or one of extra verbatim. All comparisons are case-insensitive. This is
// shape only, used for the HTTP(80) redirect filter above -- it does NOT
// mean a certificate will be issued for it; see NewAutocert's HostPolicy and
// classifyAutocertHost for the additional knownTenant check that applies there.
func AutocertHostAllowed(baseDomain string, extra []string, host string) bool {
	_, _, allowed := classifyAutocertHost(baseDomain, extra, host)
	return allowed
}

// GetCertificate obtains (or returns the cached) certificate for the SNI name
// in hello, issuing a new one via ACME HTTP-01 on first use.
func (a *Autocert) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	c, err := a.mgr.GetCertificate(hello)
	if err != nil {
		return nil, err
	}
	if c.Leaf != nil {
		a.leaf.Store(c.Leaf)
	} else if leaf, err := x509.ParseCertificate(c.Certificate[0]); err == nil {
		a.leaf.Store(leaf)
	}
	return c, nil
}

// NotAfter is the expiry of the last certificate served, or the zero time
// before any handshake has completed. autocert renews well ahead of expiry
// on its own; this only feeds the same expiry gauge File does.
func (a *Autocert) NotAfter() time.Time {
	if l := a.leaf.Load(); l != nil {
		return l.NotAfter
	}
	return time.Time{}
}
