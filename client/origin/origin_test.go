package origin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	proto "github.com/127ohoh1/core/protocol/tunnel"
)

func TestParseTarget(t *testing.T) {
	ok := []string{"http://127.0.0.1:3000", "http://localhost:8080", "http://localhost", "http://[::1]:9000", "http://127.0.0.1:3000/"}
	for _, s := range ok {
		if _, err := ParseTarget(s, false); err != nil {
			t.Errorf("%s: %v", s, err)
		}
	}
	bad := map[string]string{
		"https://localhost:3000":        "scheme",
		"ftp://localhost":               "scheme",
		"file:///etc/passwd":            "scheme",
		"localhost:3000":                "scheme", // parses as scheme "localhost"
		"http://example.com":            "loopback",
		"http://192.168.1.10:80":        "loopback",
		"http://10.0.0.1":               "loopback",
		"http://169.254.169.254":        "loopback", // cloud metadata
		"http://user:pw@localhost:3000": "credentials",
		"http://localhost:3000/api":     "path",
		"http://localhost:3000?x=1":     "path",
		"http://":                       "host",
		"":                              "scheme",
	}
	for s, why := range bad {
		if _, err := ParseTarget(s, false); err == nil {
			t.Errorf("accepted %q (should fail: %s)", s, why)
		}
	}
	if _, err := ParseTarget("http://192.168.1.10:80", true); err != nil {
		t.Errorf("explicit unsafe opt-in must allow non-loopback: %v", err)
	}
	if _, err := ParseTarget("gopher://192.168.1.10", true); err == nil {
		t.Error("the opt-in must never allow other schemes")
	}
}

// Even if a hostname were to resolve to a non-loopback address, the dialer
// must refuse the connection (DNS-rebinding defence).
func TestDialerRefusesNonLoopbackAtConnectTime(t *testing.T) {
	u, err := ParseTarget("http://192.0.2.1:80", true) // TEST-NET-1, would be routable
	if err != nil {
		t.Fatal(err)
	}
	h := New(u, Options{AllowNonLoopback: false})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", "http://192.0.2.1:80/", nil)
	_, err = h.client.Do(req)
	if err == nil || !strings.Contains(err.Error(), "non-loopback") {
		t.Fatalf("got %v", err)
	}
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data", http.StatusFound)
	}))
	defer srv.Close()
	u, _ := ParseTarget(srv.URL, false)
	h := New(u, Options{})
	resp, err := h.client.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 302 {
		t.Fatalf("redirect was followed: %d", resp.StatusCode)
	}
}

func TestHopByHopStrippedOnResponse(t *testing.T) {
	h := http.Header{"Connection": {"close, X-Hop"}, "X-Hop": {"1"}, "Keep-Alive": {"x"}, "Content-Type": {"a"}}
	stripHopByHop(h)
	if len(h) != 1 {
		t.Fatalf("%v", h)
	}
	_ = proto.Version
}
