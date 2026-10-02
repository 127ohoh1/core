package observability

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
)

// TraceContext is a W3C traceparent (version 00). Only the traceparent header
// crosses the tunnel; tracestate and baggage are deliberately dropped so an
// untrusted caller cannot inject arbitrary metadata into the tunnel.
type TraceContext struct {
	TraceID string // 32 lowercase hex, not all zero
	SpanID  string // 16 lowercase hex, not all zero
	Sampled bool
	// External is true when the trace id came from an untrusted caller. Only
	// the trace id is honoured; the span id is always freshly generated.
	External bool
}

func isHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	zero := true
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9':
			if c != '0' {
				zero = false
			}
		case c >= 'a' && c <= 'f':
			zero = false
		default:
			return false
		}
	}
	return !zero
}

// ParseTraceparent parses a traceparent header value.
func ParseTraceparent(v string) (TraceContext, bool) {
	p := strings.Split(strings.TrimSpace(v), "-")
	if len(p) < 4 || p[0] != "00" || len(p[3]) != 2 {
		return TraceContext{}, false
	}
	if !isHex(p[1], 32) || !isHex(p[2], 16) {
		return TraceContext{}, false
	}
	flags, err := hex.DecodeString(p[3])
	if err != nil {
		return TraceContext{}, false
	}
	return TraceContext{TraceID: p[1], SpanID: p[2], Sampled: flags[0]&1 == 1}, true
}

// String renders the header value.
func (t TraceContext) String() string {
	f := "00"
	if t.Sampled {
		f = "01"
	}
	return "00-" + t.TraceID + "-" + t.SpanID + "-" + f
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// NewTrace starts a new trace.
func NewTrace() TraceContext {
	return TraceContext{TraceID: randHex(16), SpanID: randHex(8), Sampled: true}
}

// Child returns a new span in the same trace.
func (t TraceContext) Child() TraceContext {
	t.SpanID = randHex(8)
	return t
}

// FromExternal derives the edge's root span from a caller-supplied
// traceparent: the caller's trace id is kept for correlation, but the edge
// always mints its own span id and marks the parentage as external.
func FromExternal(header string) TraceContext {
	if in, ok := ParseTraceparent(header); ok {
		return TraceContext{TraceID: in.TraceID, SpanID: randHex(8), Sampled: in.Sampled, External: true}
	}
	return NewTrace()
}
