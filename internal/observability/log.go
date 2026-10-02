// Package observability provides structured logging with secret redaction,
// a small Prometheus-compatible metrics registry, and W3C trace context.
package observability

import (
	"io"
	"log/slog"
	"strings"
)

// Stable correlation field names used in logs.
const (
	FieldRequestID  = "request_id"
	FieldTraceID    = "trace_id"
	FieldPrincipal  = "principal_id"
	FieldEndpoint   = "endpoint_id"
	FieldEdge       = "edge_id"
	FieldSession    = "tunnel_session_id"
	FieldStream     = "stream_id"
	FieldPolicyVer  = "policy_version"
	FieldErrorCode  = "error_code"
	FieldDurationMS = "duration_ms"
	FieldBytesIn    = "bytes_in"
	FieldBytesOut   = "bytes_out"
	FieldEvent      = "event"
)

var sensitive = []string{
	"authorization", "token", "secret", "password", "private_key", "signature",
	"cookie", "proof", "payment_request", "nonce", "query",
}

// isSensitive reports whether an attribute key must never be logged.
func isSensitive(key string) bool {
	k := strings.ToLower(key)
	for _, s := range sensitive {
		if strings.Contains(k, s) {
			return true
		}
	}
	return false
}

// NewLogger returns a JSON logger for a service. Attributes whose key looks
// sensitive are replaced with "[REDACTED]".
func NewLogger(w io.Writer, level, service string) *slog.Logger {
	var lv slog.LevelVar
	if err := lv.UnmarshalText([]byte(level)); err != nil {
		lv.Set(slog.LevelInfo)
	}
	h := slog.NewJSONHandler(w, &slog.HandlerOptions{
		Level: &lv,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key != slog.MessageKey && a.Key != slog.TimeKey && a.Key != slog.LevelKey && isSensitive(a.Key) {
				return slog.String(a.Key, "[REDACTED]")
			}
			return a
		},
	})
	return slog.New(h).With("service", service)
}
