package observability

import (
	"bytes"
	"strings"
	"testing"
)

func TestLoggerRedactsSensitiveKeys(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf, "info", "test")
	l.Info("hello", "request_id", "req_1", "authorization", "Bearer abc", "signature", "zzz", "tunnel_token", "t0k")
	out := buf.String()
	for _, leak := range []string{"Bearer abc", "zzz", "t0k"} {
		if strings.Contains(out, leak) {
			t.Fatalf("leaked %q in %s", leak, out)
		}
	}
	if !strings.Contains(out, "req_1") || !strings.Contains(out, "[REDACTED]") {
		t.Fatalf("unexpected: %s", out)
	}
}

func TestMetricsExposition(t *testing.T) {
	r := NewRegistry()
	c := r.Counter("reqs_total", "Requests.", "class")
	c.Inc("2xx")
	c.Add(2, "2xx")
	g := r.Gauge("active", "Active.")
	g.Set(4)
	h := r.Histogram("lat_seconds", "Latency.", []float64{0.1, 1})
	h.Observe(0.05)
	h.Observe(0.5)
	h.Observe(5)
	var buf bytes.Buffer
	r.WriteText(&buf)
	out := buf.String()
	for _, want := range []string{
		`reqs_total{class="2xx"} 3`, `active 4`,
		`lat_seconds_bucket{le="0.1"} 1`, `lat_seconds_bucket{le="1"} 2`, `lat_seconds_bucket{le="+Inf"} 3`,
		`lat_seconds_count 3`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	if c2 := r.Counter("reqs_total", "x", "class"); c2.Value("2xx") != 3 {
		t.Fatal("registration must be idempotent")
	}
}

func TestTraceparent(t *testing.T) {
	in := "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	tc, ok := ParseTraceparent(in)
	if !ok || tc.String() != in {
		t.Fatalf("roundtrip failed: %v %v", tc, ok)
	}
	for _, bad := range []string{"", "01-" + in[3:], "00-00000000000000000000000000000000-00f067aa0ba902b7-01", "00-xyz", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-1"} {
		if _, ok := ParseTraceparent(bad); ok {
			t.Errorf("accepted %q", bad)
		}
	}
	ext := FromExternal(in)
	if ext.TraceID != tc.TraceID || ext.SpanID == tc.SpanID || !ext.External {
		t.Fatalf("external handling wrong: %+v", ext)
	}
	if FromExternal("garbage").External {
		t.Fatal("garbage must start a fresh internal trace")
	}
}
