package proxy

import (
	"net/http"
	"testing"
)

func TestStripHopByHopIncludingConnectionListed(t *testing.T) {
	h := http.Header{}
	h.Set("Connection", "keep-alive, X-Secret-Hop")
	h.Set("X-Secret-Hop", "1")
	h.Set("Keep-Alive", "timeout=5")
	h.Set("Transfer-Encoding", "chunked")
	h.Set("Upgrade", "websocket")
	h.Set("Te", "trailers")
	h.Set("Accept", "*/*")
	StripHopByHop(h)
	if len(h) != 1 || h.Get("Accept") == "" {
		t.Fatalf("left: %v", h)
	}
}

func TestRequestHeadersDropsSpoofableForwarding(t *testing.T) {
	h := http.Header{}
	for _, k := range []string{"X-Forwarded-For", "Forwarded", "X-Real-Ip", "X-Forwarded-Proto", "X-Forwarded-Host", "Traceparent", "Via", "Host"} {
		h.Set(k, "attacker")
	}
	h.Set("User-Agent", "curl")
	out := RequestHeaders(h)
	if len(out) != 1 || out.Get("User-Agent") != "curl" {
		t.Fatalf("got %v", out)
	}
	if h.Get("X-Forwarded-For") == "" {
		t.Fatal("input must not be mutated")
	}
}

func TestResponseHeadersStripsPlatformNamespace(t *testing.T) {
	h := http.Header{}
	h.Set("X-127ohoh1-Error", "quota_exhausted") // origin pretending to be the platform
	h.Set("x-127ohoh1-anything", "x")
	h.Set("Content-Type", "text/plain")
	h.Set("Connection", "close")
	out := ResponseHeaders(h)
	if len(out) != 1 || out.Get("Content-Type") == "" {
		t.Fatalf("got %v", out)
	}
}

func TestIsUpgrade(t *testing.T) {
	yes := []http.Header{{"Upgrade": {"websocket"}}, {"Connection": {"Upgrade"}}, {"Connection": {"keep-alive, upgrade"}}}
	for _, h := range yes {
		if !IsUpgrade(h) {
			t.Errorf("%v", h)
		}
	}
	if IsUpgrade(http.Header{"Connection": {"keep-alive"}}) {
		t.Error("false positive")
	}
}
