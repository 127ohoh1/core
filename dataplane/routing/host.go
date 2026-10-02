package routing

import (
	"errors"
	"net"
	"strings"
)

// Host errors.
var (
	ErrBadHost      = errors.New("routing: malformed host")
	ErrHostNotOurs  = errors.New("routing: host is not a tenant hostname")
	ErrHostMismatch = errors.New("routing: SNI and Host disagree")
)

// ParseTenantHost extracts the tenant label from a Host header value. It
// accepts exactly one label directly under baseDomain (any port is stripped),
// lowercases it, and rejects everything else: IP literals, multiple labels,
// trailing dots, userinfo, and hosts outside the base domain.
func ParseTenantHost(hostHeader, baseDomain string) (string, error) {
	h := hostHeader
	if h == "" || len(h) > 300 || strings.ContainsAny(h, " \t\r\n/@\\?#") {
		return "", ErrBadHost
	}
	if host, port, err := net.SplitHostPort(h); err == nil {
		if port == "" {
			return "", ErrBadHost
		}
		h = host
	} else if strings.Contains(h, ":") {
		return "", ErrBadHost // stray colon / IPv6 without brackets
	}
	h = strings.ToLower(h)
	if net.ParseIP(h) != nil {
		return "", ErrHostNotOurs
	}
	base := strings.ToLower(baseDomain)
	suffix := "." + base
	if !strings.HasSuffix(h, suffix) {
		return "", ErrHostNotOurs
	}
	label := strings.TrimSuffix(h, suffix)
	if label == "" || strings.Contains(label, ".") {
		return "", ErrHostNotOurs
	}
	if len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
		return "", ErrBadHost
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return "", ErrBadHost
		}
	}
	return label, nil
}

// CheckSNI verifies that the TLS SNI (if any) names the same tenant as Host.
// A client that connected with SNI for tenant A and asks for tenant B's Host
// is rejected: this is the domain-fronting / cross-tenant guard. An empty SNI
// is accepted only when allowEmpty is set (plain-HTTP development listeners).
func CheckSNI(sni, hostLabel, baseDomain string, allowEmpty bool) error {
	if sni == "" {
		if allowEmpty {
			return nil
		}
		return ErrHostMismatch
	}
	l, err := ParseTenantHost(sni, baseDomain)
	if err != nil || l != hostLabel {
		return ErrHostMismatch
	}
	return nil
}
