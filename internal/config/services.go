package config

import (
	"fmt"
	"strings"
	"time"
)

// ControlPlane configures cmd/control-plane.
type ControlPlane struct {
	AppEnv        string   `json:"app_env" env:"APP_ENV"`
	ListenAddr    string   `json:"listen_addr" env:"LISTEN_ADDR"`
	MetricsAddr   string   `json:"metrics_addr" env:"METRICS_ADDR"` // separate listener for /metrics; empty disables
	BaseDomain    string   `json:"base_domain" env:"BASE_DOMAIN"`
	PublicPort    int      `json:"public_port" env:"PUBLIC_PORT"` // port in public URLs; 443 is omitted
	LogLevel      string   `json:"log_level" env:"LOG_LEVEL"`
	ShutdownGrace Duration `json:"shutdown_grace" env:"SHUTDOWN_GRACE"`

	// Auth. SigningKeyFile holds a base64 Ed25519 seed. Development may leave
	// it empty (ephemeral key, tokens die on restart); production may not.
	SigningKeyFile string `json:"signing_key_file" env:"SIGNING_KEY_FILE"`
	// PreviousVerifyKeys lists retired signing keys that must keep verifying
	// during a rotation overlap: comma-separated "kid=base64url(public key)".
	// They are published at /v1/keys (so edges accept credentials signed by
	// them) and never used to sign.
	PreviousVerifyKeys  string   `json:"previous_verify_keys" env:"PREVIOUS_VERIFY_KEYS"`
	SessionTTL          Duration `json:"session_ttl" env:"SESSION_TTL"`
	ChallengeTTL        Duration `json:"challenge_ttl" env:"CHALLENGE_TTL"`
	TunnelCredentialTTL Duration `json:"tunnel_credential_ttl" env:"TUNNEL_CREDENTIAL_TTL"`
	EdgeAudience        string   `json:"edge_audience" env:"EDGE_AUDIENCE"`
	ControlAudience     string   `json:"control_audience" env:"CONTROL_AUDIENCE"`
	EdgeTunnelAddr      string   `json:"edge_tunnel_addr" env:"EDGE_TUNNEL_ADDR"` // advertised to clients

	// Service credentials for edge -> control plane and operator hooks.
	EdgeServiceToken string `json:"edge_service_token" env:"EDGE_SERVICE_TOKEN"`
	AdminToken       string `json:"admin_token" env:"ADMIN_TOKEN"` // empty disables /v1/admin

	// Policy and lifecycle.
	PolicyTTL                Duration `json:"policy_ttl" env:"POLICY_TTL"`
	FreeInactivity           Duration `json:"free_inactivity" env:"FREE_INACTIVITY"`
	NameTombstone            Duration `json:"name_tombstone" env:"NAME_TOMBSTONE"`
	ReaperInterval           Duration `json:"reaper_interval" env:"REAPER_INTERVAL"`
	MaxEndpointsPerPrincipal int      `json:"max_endpoints_per_principal" env:"MAX_ENDPOINTS_PER_PRINCIPAL"`
	OfferTTL                 Duration `json:"offer_ttl" env:"OFFER_TTL"`
	AbuseReportsPerMinute    int      `json:"abuse_reports_per_minute" env:"ABUSE_REPORTS_PER_MINUTE"` // per client address
	AuthRatePerMinute        int      `json:"auth_rate_per_minute" env:"AUTH_RATE_PER_MINUTE"`         // challenge/session requests per client address
	ExpiredReservedRelease   Duration `json:"expired_reserved_release" env:"EXPIRED_RESERVED_RELEASE"`

	// Explicit development feature gates. All are refused when AppEnv is production.
	DevelopmentPayments bool `json:"development_payments" env:"DEVELOPMENT_PAYMENTS"`

	DatabaseURL string `json:"database_url" env:"DATABASE_URL"`
	RedisURL    string `json:"redis_url" env:"REDIS_URL"`
}

// DefaultControlPlane returns development defaults.
func DefaultControlPlane() ControlPlane {
	return ControlPlane{
		AppEnv: EnvDevelopment, ListenAddr: ":8080", BaseDomain: "127ohoh1.localhost", PublicPort: 8443, LogLevel: "info",
		ShutdownGrace: Duration(15 * time.Second),
		SessionTTL:    Duration(15 * time.Minute), ChallengeTTL: Duration(60 * time.Second),
		TunnelCredentialTTL: Duration(2 * time.Minute),
		EdgeAudience:        "127ohoh1-edge", ControlAudience: "127ohoh1-control",
		PolicyTTL: Duration(5 * time.Minute), FreeInactivity: Duration(24 * time.Hour),
		NameTombstone: Duration(time.Hour), ReaperInterval: Duration(time.Minute),
		MaxEndpointsPerPrincipal: 3, OfferTTL: Duration(30 * time.Minute), ExpiredReservedRelease: Duration(72 * time.Hour), AbuseReportsPerMinute: 6, AuthRatePerMinute: 60,
	}
}

// Validate checks internal consistency.
func (c ControlPlane) Validate() error {
	var p Problems
	switch c.AppEnv {
	case EnvDevelopment, EnvTest, EnvProduction:
	default:
		p.Addf("app_env %q must be development, test or production", c.AppEnv)
	}
	if c.ListenAddr == "" {
		p.Addf("listen_addr is required")
	}
	if c.BaseDomain == "" || strings.ContainsAny(c.BaseDomain, "/: ") {
		p.Addf("base_domain must be a bare DNS name")
	}
	if len(c.EdgeServiceToken) < 16 {
		p.Addf("edge_service_token must be at least 16 characters")
	}
	if c.EdgeTunnelAddr == "" {
		p.Addf("edge_tunnel_addr is required")
	}
	if c.SessionTTL.D() <= 0 || c.ChallengeTTL.D() <= 0 || c.TunnelCredentialTTL.D() <= 0 || c.PolicyTTL.D() <= 0 {
		p.Addf("ttl values must be positive")
	}
	if c.FreeInactivity.D() <= 0 || c.ReaperInterval.D() <= 0 {
		p.Addf("free_inactivity and reaper_interval must be positive")
	}
	if c.MaxEndpointsPerPrincipal < 1 {
		p.Addf("max_endpoints_per_principal must be >= 1")
	}
	if c.AbuseReportsPerMinute < 1 || c.AuthRatePerMinute < 1 {
		p.Addf("abuse_reports_per_minute and auth_rate_per_minute must be >= 1")
	}
	if _, err := ParseVerifyKeys(c.PreviousVerifyKeys); err != nil {
		p.Addf("previous_verify_keys: %v", err)
	}
	if c.AppEnv == EnvProduction {
		if c.DevelopmentPayments {
			p.Addf("development_payments must not be enabled when app_env=production")
		}
		if c.SigningKeyFile == "" {
			p.Addf("signing_key_file is required in production")
		}
		if len(c.EdgeServiceToken) < 32 {
			p.Addf("edge_service_token must be at least 32 characters in production")
		}
	}
	return p.Err()
}

// Edge configures cmd/edge.
type Edge struct {
	AppEnv        string   `json:"app_env" env:"APP_ENV"`
	EdgeID        string   `json:"edge_id" env:"EDGE_ID"`
	IngressAddr   string   `json:"ingress_addr" env:"INGRESS_ADDR"`
	TunnelAddr    string   `json:"tunnel_addr" env:"TUNNEL_ADDR"`
	AdminAddr     string   `json:"admin_addr" env:"ADMIN_ADDR"` // metrics, healthz, readyz
	BaseDomain    string   `json:"base_domain" env:"BASE_DOMAIN"`
	LogLevel      string   `json:"log_level" env:"LOG_LEVEL"`
	ShutdownGrace Duration `json:"shutdown_grace" env:"SHUTDOWN_GRACE"`

	ControlPlaneURL  string `json:"control_plane_url" env:"CONTROL_PLANE_URL"`
	EdgeServiceToken string `json:"edge_service_token" env:"EDGE_SERVICE_TOKEN"`
	EdgeAudience     string `json:"edge_audience" env:"EDGE_AUDIENCE"`

	// IngressPlainHTTP serves the public listener without TLS. Development
	// and tests only: refused when AppEnv is production.
	IngressPlainHTTP bool `json:"ingress_plain_http" env:"INGRESS_PLAIN_HTTP"`

	// TLS. With CertFile/KeyFile unset and AppEnv != production the edge
	// generates a development CA and certificate (DevTLSDir persists them).
	CertFile  string `json:"cert_file" env:"CERT_FILE"`
	KeyFile   string `json:"key_file" env:"KEY_FILE"`
	DevTLSDir string `json:"dev_tls_dir" env:"DEV_TLS_DIR"`
	// CertReloadInterval is how often the certificate files are checked for
	// replacement (SIGHUP forces an immediate reload).
	CertReloadInterval Duration `json:"cert_reload_interval" env:"CERT_RELOAD_INTERVAL"`

	// AutocertCacheDir switches to on-demand HTTP-01 certificates (see
	// dataplane/cert.Autocert) instead of CertFile/KeyFile: used when the
	// base domain's DNS provider offers no automatable DNS-01 API, so a
	// single wildcard certificate (ADR 0002) isn't obtainable unattended.
	// Mutually exclusive with CertFile/KeyFile.
	AutocertCacheDir string `json:"autocert_cache_dir" env:"AUTOCERT_CACHE_DIR"`
	// AutocertHosts are comma-separated exact hostnames to accept in addition
	// to BaseDomain, "www."+BaseDomain and any single tenant label under
	// BaseDomain — e.g. the fixed hostname tunnel clients dial.
	AutocertHosts string `json:"autocert_hosts" env:"AUTOCERT_HOSTS"`
	// AutocertHTTPAddr is where the ACME HTTP-01 responder listens (plain
	// HTTP); a router must forward port 80 for every accepted host here.
	AutocertHTTPAddr string `json:"autocert_http_addr" env:"AUTOCERT_HTTP_ADDR"`
	AutocertEmail    string `json:"autocert_email" env:"AUTOCERT_EMAIL"`

	// Tunnel and proxy limits.
	MaxFramePayload       int      `json:"max_frame_payload" env:"MAX_FRAME_PAYLOAD"`
	StreamWindow          int      `json:"stream_window" env:"STREAM_WINDOW"`
	ConnWindow            int      `json:"conn_window" env:"CONN_WINDOW"`
	MaxStreamsPerSession  int      `json:"max_streams_per_session" env:"MAX_STREAMS_PER_SESSION"`
	MaxSessions           int      `json:"max_sessions" env:"MAX_SESSIONS"`
	PingInterval          Duration `json:"ping_interval" env:"PING_INTERVAL"`
	PingTimeout           Duration `json:"ping_timeout" env:"PING_TIMEOUT"`
	DrainTimeout          Duration `json:"drain_timeout" env:"DRAIN_TIMEOUT"`
	RequestHeaderTimeout  Duration `json:"request_header_timeout" env:"REQUEST_HEADER_TIMEOUT"`
	RequestIdleTimeout    Duration `json:"request_idle_timeout" env:"REQUEST_IDLE_TIMEOUT"`
	RequestMaxDuration    Duration `json:"request_max_duration" env:"REQUEST_MAX_DURATION"`
	ResponseHeaderTimeout Duration `json:"response_header_timeout" env:"RESPONSE_HEADER_TIMEOUT"`

	// Policy cache and usage.
	PolicyRefresh    Duration `json:"policy_refresh" env:"POLICY_REFRESH"`
	PolicyStaleGrace Duration `json:"policy_stale_grace" env:"POLICY_STALE_GRACE"`
	UsageFlush       Duration `json:"usage_flush" env:"USAGE_FLUSH"`

	RedisURL          string   `json:"redis_url" env:"REDIS_URL"`
	LeaseTTL          Duration `json:"lease_ttl" env:"LEASE_TTL"`         // tunnel directory lease; heartbeats run at a third of it
	InternalAddr      string   `json:"internal_addr" env:"INTERNAL_ADDR"` // inter-edge listener (multi-edge profile)
	AdvertiseInternal string   `json:"advertise_internal" env:"ADVERTISE_INTERNAL"`
}

// DefaultEdge returns development defaults.
func DefaultEdge() Edge {
	return Edge{
		AppEnv: EnvDevelopment, EdgeID: "edge-1", IngressAddr: ":8443", TunnelAddr: ":7443", AdminAddr: ":9100",
		BaseDomain: "127ohoh1.localhost", LogLevel: "info", ShutdownGrace: Duration(20 * time.Second),
		EdgeAudience: "127ohoh1-edge", DevTLSDir: "./.devtls", CertReloadInterval: Duration(30 * time.Second), LeaseTTL: Duration(30 * time.Second),
		MaxFramePayload: 64 * 1024, StreamWindow: 256 * 1024, ConnWindow: 4 * 1024 * 1024,
		MaxStreamsPerSession: 128, MaxSessions: 10000,
		PingInterval: Duration(15 * time.Second), PingTimeout: Duration(10 * time.Second),
		DrainTimeout:         Duration(10 * time.Second),
		RequestHeaderTimeout: Duration(10 * time.Second), RequestIdleTimeout: Duration(60 * time.Second),
		RequestMaxDuration: Duration(10 * time.Minute), ResponseHeaderTimeout: Duration(60 * time.Second),
		PolicyRefresh: Duration(30 * time.Second), PolicyStaleGrace: Duration(5 * time.Minute),
		UsageFlush: Duration(time.Second),
	}
}

// Validate checks internal consistency.
func (c Edge) Validate() error {
	var p Problems
	switch c.AppEnv {
	case EnvDevelopment, EnvTest, EnvProduction:
	default:
		p.Addf("app_env %q must be development, test or production", c.AppEnv)
	}
	if c.EdgeID == "" {
		p.Addf("edge_id is required")
	}
	if c.BaseDomain == "" || strings.ContainsAny(c.BaseDomain, "/: ") {
		p.Addf("base_domain must be a bare DNS name")
	}
	if c.ControlPlaneURL == "" {
		p.Addf("control_plane_url is required")
	}
	if len(c.EdgeServiceToken) < 16 {
		p.Addf("edge_service_token must be at least 16 characters")
	}
	if (c.CertFile == "") != (c.KeyFile == "") {
		p.Addf("cert_file and key_file must be set together")
	}
	if c.AutocertCacheDir != "" && (c.CertFile != "" || c.KeyFile != "") {
		p.Addf("autocert_cache_dir is mutually exclusive with cert_file/key_file")
	}
	if c.AutocertCacheDir != "" && c.AutocertHTTPAddr == "" {
		p.Addf("autocert_http_addr is required when autocert_cache_dir is set")
	}
	if c.MaxFramePayload < 1024 || c.MaxFramePayload > 1<<20 {
		p.Addf("max_frame_payload must be within 1 KiB..1 MiB")
	}
	if c.StreamWindow < c.MaxFramePayload || c.ConnWindow < c.StreamWindow {
		p.Addf("windows must satisfy max_frame_payload <= stream_window <= conn_window")
	}
	if c.MaxStreamsPerSession < 1 || c.MaxSessions < 1 {
		p.Addf("max_streams_per_session and max_sessions must be >= 1")
	}
	if c.PolicyRefresh.D() <= 0 || c.PolicyStaleGrace.D() < 0 || c.UsageFlush.D() <= 0 {
		p.Addf("policy_refresh/usage_flush must be positive and policy_stale_grace non-negative")
	}
	if c.AppEnv == EnvProduction {
		if c.CertFile == "" && c.AutocertCacheDir == "" {
			p.Addf("cert_file/key_file or autocert_cache_dir are required in production (no development TLS)")
		}
		if c.IngressPlainHTTP {
			p.Addf("ingress_plain_http must not be enabled when app_env=production")
		}
		if !strings.HasPrefix(c.ControlPlaneURL, "https://") {
			p.Addf("control_plane_url must be https in production")
		}
	}
	return p.Err()
}

// VerifyKey is a retired public key kept for verification during rotation.
type VerifyKey struct {
	KID       string
	PublicKey string // base64url, validated by the consumer
}

// ParseVerifyKeys parses "kid=base64url,kid2=base64url".
func ParseVerifyKeys(s string) ([]VerifyKey, error) {
	var out []VerifyKey
	seen := map[string]bool{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kid, key, ok := strings.Cut(part, "=")
		if !ok || kid == "" || key == "" || len(kid) > 64 || seen[kid] {
			return nil, fmt.Errorf("malformed or duplicate entry %q (want kid=base64url-public-key)", kid)
		}
		seen[kid] = true
		out = append(out, VerifyKey{KID: kid, PublicKey: key})
	}
	return out, nil
}
