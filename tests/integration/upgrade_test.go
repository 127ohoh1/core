package integration

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/127ohoh1/core/internal/testenv"
)

// wsEcho is a minimal raw echo "server" good enough to prove the edge and
// client proxy a protocol upgrade transparently: no real WebSocket framing is
// needed to test that bytes and headers cross the tunnel untouched after a
// 101, since neither net/http nor this proxy understand WebSocket framing
// itself (correctly so — that's the origin/browser's job).
func wsEcho(w http.ResponseWriter, r *http.Request) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		http.Error(w, "expected an upgrade", http.StatusBadRequest)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "no hijack support", http.StatusInternalServerError)
		return
	}
	conn, buf, err := hj.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	fmt.Fprint(buf, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: test-accept-token\r\n\r\n")
	buf.Flush()
	tmp := make([]byte, 4096)
	for {
		n, rerr := buf.Reader.Read(tmp)
		if n > 0 {
			if _, werr := buf.Writer.Write(tmp[:n]); werr != nil {
				return
			}
			if werr := buf.Writer.Flush(); werr != nil {
				return
			}
		}
		if rerr != nil {
			return
		}
	}
}

// A protocol-upgrade request (WebSocket's handshake shape) must be proxied
// transparently end to end: the 101 response, its Upgrade/Connection and
// handshake headers, and raw bytes in both directions after the switch.
func TestUpgradeIsProxiedTransparently(t *testing.T) {
	env := testenv.New(t, testenv.Options{})
	origin := env.Origin(http.HandlerFunc(wsEcho))
	x := env.Expose(env.NewIdentity(), origin.URL, "")

	req, err := http.NewRequest("GET", "http://"+env.Edge.Addrs().Ingress+"/ws", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = x.Endpoint.Hostname + "." + testenv.BaseDomain
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("got %d, want 101 (body: %s)", resp.StatusCode, b)
	}
	if !strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") || !strings.EqualFold(resp.Header.Get("Connection"), "Upgrade") {
		t.Fatalf("missing Upgrade/Connection in response: %v", resp.Header)
	}
	if got := resp.Header.Get("Sec-WebSocket-Accept"); got != "test-accept-token" {
		t.Fatalf("handshake header not forwarded: got %q", got)
	}

	rwc, ok := resp.Body.(io.ReadWriteCloser)
	if !ok {
		t.Fatalf("resp.Body is %T, not a ReadWriteCloser after 101", resp.Body)
	}
	defer rwc.Close()

	for _, msg := range []string{"hello tunnel", "second frame", strings.Repeat("x", 70000)} {
		if _, err := rwc.Write([]byte(msg)); err != nil {
			t.Fatalf("write: %v", err)
		}
		got := make([]byte, len(msg))
		if _, err := io.ReadFull(rwc, got); err != nil {
			t.Fatalf("read echo of %q: %v", msg[:min(len(msg), 20)], err)
		}
		if string(got) != msg {
			t.Fatalf("echo mismatch: got %d bytes, want %d", len(got), len(msg))
		}
	}
}

// An upgrade request the origin declines (any non-101 answer) must proxy like
// a normal response instead of being treated specially.
func TestUpgradeDeclinedByOriginProxiesNormally(t *testing.T) {
	env := testenv.New(t, testenv.Options{})
	origin := env.Origin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusBadRequest)
	}))
	x := env.Expose(env.NewIdentity(), origin.URL, "")

	req, err := http.NewRequest("GET", "http://"+env.Edge.Addrs().Ingress+"/ws", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = x.Endpoint.Hostname + "." + testenv.BaseDomain
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusBadRequest || !bytes.Contains(body, []byte("nope")) {
		t.Fatalf("got %d %q, want 400 containing %q", resp.StatusCode, body, "nope")
	}
}
