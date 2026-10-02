package integration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/127ohoh1/core/client/api"
	"github.com/127ohoh1/core/client/cli"
	"github.com/127ohoh1/core/client/session"
	"github.com/127ohoh1/core/internal/testenv"
	"github.com/127ohoh1/core/protocol/auth"
	proto "github.com/127ohoh1/core/protocol/tunnel"
)

var bg = context.Background()

// Scenario 1: identity -> random endpoint -> tunnel -> fetch a local HTTP
// response through the edge.
func TestEndToEndRandomEndpoint(t *testing.T) {
	env := testenv.New(t, testenv.Options{})
	var seen http.Header
	var seenHost, seenURI string
	origin := env.Origin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen, seenHost, seenURI = r.Header.Clone(), r.Host, r.RequestURI
		w.Header().Set("X-Origin", "yes")
		w.Header().Set("X-127ohoh1-Error", "quota_exhausted") // an origin must not impersonate the platform
		fmt.Fprint(w, "hello from origin")
	}))
	x := env.Expose(env.NewIdentity(), origin.URL, "")

	resp, body := env.Get(x.Endpoint.Hostname, "/some/path?q=1&r=%2F")
	if resp.StatusCode != 200 || body != "hello from origin" {
		t.Fatalf("%d %q", resp.StatusCode, body)
	}
	if resp.Header.Get("X-Origin") != "yes" || resp.Header.Get("X-127ohoh1-Error") != "" {
		t.Fatalf("headers: %v", resp.Header)
	}
	if !strings.HasPrefix(resp.Header.Get("X-Request-Id"), "req_") {
		t.Fatal("missing request id")
	}
	if seenURI != "/some/path?q=1&r=%2F" {
		t.Fatalf("path/query not preserved: %q", seenURI)
	}
	if seenHost != x.Endpoint.Hostname+"."+testenv.BaseDomain {
		t.Fatalf("host: %q", seenHost)
	}
	if seen.Get("X-Forwarded-Proto") != "http" || seen.Get("X-Forwarded-For") != "127.0.0.1" {
		t.Fatalf("forwarded headers: %v", seen)
	}
	if !strings.HasPrefix(seen.Get("Traceparent"), "00-") {
		t.Fatalf("trace context not propagated: %q", seen.Get("Traceparent"))
	}
}

func TestClientSuppliedForwardingHeadersAreNotTrusted(t *testing.T) {
	env := testenv.New(t, testenv.Options{})
	var seen http.Header
	origin := env.Origin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen = r.Header.Clone() }))
	x := env.Expose(env.NewIdentity(), origin.URL, "")
	resp, err := env.Request(x.Endpoint.Hostname, "GET", "/", nil, map[string]string{
		"X-Forwarded-For": "6.6.6.6", "X-Real-Ip": "6.6.6.6", "Forwarded": "for=6.6.6.6", "X-Forwarded-Host": "evil.example",
		"Traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if seen.Get("X-Forwarded-For") != "127.0.0.1" || seen.Get("X-Real-Ip") != "" || seen.Get("Forwarded") != "" {
		t.Fatalf("spoofed forwarding headers reached the origin: %v", seen)
	}
	if seen.Get("X-Forwarded-Host") == "evil.example" {
		t.Fatal("X-Forwarded-Host spoofed")
	}
	tp := seen.Get("Traceparent")
	if !strings.Contains(tp, "4bf92f3577b34da6a3ce929d0e0e4736") || strings.Contains(tp, "00f067aa0ba902b7") {
		t.Fatalf("external trace id must be kept but its span id replaced: %q", tp)
	}
}

// Scenario 2: restart the client and recover the same endpoint.
func TestClientRestartRecoversSameEndpoint(t *testing.T) {
	env := testenv.New(t, testenv.Options{})
	origin := env.Origin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "v2") }))
	id := env.NewIdentity()
	x1 := env.Expose(id, origin.URL, "")
	x1.Conn.Session.Close() // client process dies
	<-x1.Done
	waitGone(t, env, x1.Endpoint.Hostname)

	x2 := env.Expose(id, origin.URL, x1.Endpoint.ID)
	if x2.Endpoint.Hostname != x1.Endpoint.Hostname {
		t.Fatal("endpoint name changed across restart")
	}
	if _, body := env.Get(x2.Endpoint.Hostname, "/"); body != "v2" {
		t.Fatalf("%q", body)
	}
}

func waitGone(t *testing.T, env *testenv.Env, host string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := env.Edge.Registry.ByHostname(host); !ok {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("%s still registered", host)
}

// Scenario 3: a credential is useless without the matching private key.
func TestTunnelRejectsWrongKey(t *testing.T) {
	env := testenv.New(t, testenv.Options{})
	owner, thief := env.NewIdentity(), env.NewIdentity()
	ep, err := env.API(owner).CreateEndpoint(bg, "")
	if err != nil {
		t.Fatal(err)
	}
	cred, _ := env.API(owner).TunnelCredentials(bg, ep.ID)
	_, err = session.Connect(bg, env.Edge.Addrs().Tunnel, env.TLSConfig(), cred, thief, 5*time.Second)
	var ae *proto.AuthError
	if !errors.As(err, &ae) || ae.Code != "invalid_credential" || ae.Retryable {
		t.Fatalf("stolen credential accepted or wrong error: %v", err)
	}
	if _, ok := env.Edge.Registry.ByHostname(ep.Hostname); ok {
		t.Fatal("registered despite failed proof")
	}
	if v := authFailures(env, "bad_proof"); v != 1 {
		t.Fatalf("bad_proof metric = %v", v)
	}
}

func authFailures(env *testenv.Env, reason string) float64 {
	var buf bytes.Buffer
	env.Edge.Metrics.WriteText(&buf)
	for _, l := range strings.Split(buf.String(), "\n") {
		if strings.HasPrefix(l, `edge_tunnel_auth_failures_total{reason="`+reason+`"}`) {
			var v float64
			fmt.Sscanf(l[strings.LastIndex(l, " ")+1:], "%g", &v)
			return v
		}
	}
	return 0
}

// A captured AUTH message replayed on a fresh connection must fail: the proof
// is bound to that connection's TLS exporter and the edge's per-connection nonce.
func TestTunnelAuthReplayRejected(t *testing.T) {
	env := testenv.New(t, testenv.Options{})
	id := env.NewIdentity()
	ep, _ := env.API(id).CreateEndpoint(bg, "")
	cred, _ := env.API(id).TunnelCredentials(bg, ep.ID)
	claims, _ := auth.PeekClaims(cred.Token)

	dial := func() (*tls.Conn, []byte, []byte) {
		c, err := tls.Dial("tcp", env.Edge.Addrs().Tunnel, env.TLSConfig())
		if err != nil {
			t.Fatal(err)
		}
		proto.WriteHandshake(c, proto.TypeHello, proto.Hello{Versions: []int{1}}, 3*time.Second)
		var h proto.Hello
		if err := proto.ReadHandshake(c, proto.TypeHello, &h, 3*time.Second); err != nil {
			t.Fatal(err)
		}
		nonce, _ := auth.NonceDecode(h.Nonce)
		cs := c.ConnectionState()
		exp, _ := cs.ExportKeyingMaterial(proto.ExporterLabel, nil, 32)
		return c, nonce, exp
	}
	// Legitimate handshake, capturing the AUTH message.
	c1, nonce1, exp1 := dial()
	proof := auth.EncodeSig(ed25519.Sign(id.Private, auth.TunnelProofBytes(exp1, nonce1, claims.ID, claims.Endpoint)))
	captured := proto.Auth{Token: cred.Token, JTI: claims.ID, Proof: proof}
	proto.WriteHandshake(c1, proto.TypeAuth, captured, 3*time.Second)
	var ok proto.AuthOK
	if err := proto.ReadHandshake(c1, proto.TypeAuthOK, &ok, 3*time.Second); err != nil {
		t.Fatalf("legitimate auth failed: %v", err)
	}
	c1.Close()
	// Replay on a new connection.
	c2, _, _ := dial()
	defer c2.Close()
	proto.WriteHandshake(c2, proto.TypeAuth, captured, 3*time.Second)
	err := proto.ReadHandshake(c2, proto.TypeAuthOK, &ok, 3*time.Second)
	var ae *proto.AuthError
	if !errors.As(err, &ae) {
		t.Fatalf("replayed AUTH accepted: %v", err)
	}
}

func TestTunnelRejectsExpiredAndForeignCredentials(t *testing.T) {
	env := testenv.New(t, testenv.Options{})
	id := env.NewIdentity()
	ep, _ := env.API(id).CreateEndpoint(bg, "")
	cp := env.CP
	now := time.Now()
	mk := func(mut func(*auth.Claims)) api.TunnelCredential {
		c := auth.Claims{Type: auth.TypeTunnel, Subject: "pr_x", Audience: "127ohoh1-edge", Endpoint: ep.ID, Hostname: ep.Hostname,
			PublicKey: id.PublicKeyString(), ID: "tok_test", IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix()}
		mut(&c)
		tok, _ := cp.Signer.Sign(c)
		return api.TunnelCredential{Token: tok}
	}
	cases := []struct {
		name      string
		cred      api.TunnelCredential
		retryable bool
	}{
		{"expired", mk(func(c *auth.Claims) {
			c.IssuedAt, c.ExpiresAt = now.Add(-time.Hour).Unix(), now.Add(-time.Minute).Unix()
		}), true},
		{"wrong audience", mk(func(c *auth.Claims) { c.Audience = "other-edge" }), false},
		{"session token used as tunnel token", mk(func(c *auth.Claims) { c.Type = auth.TypeSession }), false},
	}
	for _, c := range cases {
		_, err := session.Connect(bg, env.Edge.Addrs().Tunnel, env.TLSConfig(), c.cred, id, 5*time.Second)
		var ae *proto.AuthError
		if !errors.As(err, &ae) || ae.Retryable != c.retryable {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	// A token signed by an unknown key.
	forged := auth.NewSigner(env.CP.Signer.KeyID(), mustKey(t))
	tok, _ := forged.Sign(auth.Claims{Type: auth.TypeTunnel, Subject: "pr_x", Audience: "127ohoh1-edge", Endpoint: ep.ID, Hostname: ep.Hostname,
		PublicKey: id.PublicKeyString(), ID: "tok_f", IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix()})
	if _, err := session.Connect(bg, env.Edge.Addrs().Tunnel, env.TLSConfig(), api.TunnelCredential{Token: tok}, id, 5*time.Second); err == nil {
		t.Fatal("forged credential accepted")
	}
}

func mustKey(t *testing.T) ed25519.PrivateKey {
	_, k, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestTunnelRefusesPlainTCPAndGarbage(t *testing.T) {
	env := testenv.New(t, testenv.Options{})
	for _, payload := range []string{"GET / HTTP/1.1\r\nHost: x\r\n\r\n", strings.Repeat("\xff", 4096), ""} {
		c, err := net.Dial("tcp", env.Edge.Addrs().Tunnel)
		if err != nil {
			t.Fatal(err)
		}
		c.Write([]byte(payload))
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		io.Copy(io.Discard, c) // server must close, not hang
		c.Close()
	}
	// The edge is still healthy afterwards.
	origin := env.Origin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }))
	x := env.Expose(env.NewIdentity(), origin.URL, "")
	if _, body := env.Get(x.Endpoint.Hostname, "/"); body != "ok" {
		t.Fatal("edge unhealthy after garbage connections")
	}
}

// Scenario 5: many concurrent streaming requests over one session, no mix-ups.
func TestConcurrentRequestsOverOneSession(t *testing.T) {
	env := testenv.New(t, testenv.Options{})
	origin := env.Origin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Path", r.URL.Path)
		f := w.(http.Flusher)
		// Stream the reply back in pieces.
		for i := 0; i < 4; i++ {
			w.Write(body[i*len(body)/4 : (i+1)*len(body)/4])
			f.Flush()
		}
	}))
	x := env.Expose(env.NewIdentity(), origin.URL, "")
	const N = 60
	var wg sync.WaitGroup
	errs := make(chan error, N)
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			payload := bytes.Repeat([]byte(fmt.Sprintf("<req-%03d>", i)), 400+i*50)
			resp, err := env.Request(x.Endpoint.Hostname, "POST", fmt.Sprintf("/r/%d", i), bytes.NewReader(payload), nil)
			if err != nil {
				errs <- err
				return
			}
			defer resp.Body.Close()
			got, err := io.ReadAll(resp.Body)
			if err != nil || !bytes.Equal(got, payload) || resp.Header.Get("X-Path") != fmt.Sprintf("/r/%d", i) {
				head := got
				if len(head) > 200 {
					head = head[:200]
				}
				errs <- fmt.Errorf("request %d mixed up or failed: status=%d err=%v len=%d/%d path=%q body=%q", i, resp.StatusCode, err, len(got), len(payload), resp.Header.Get("X-Path"), head)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if x.Conn.Session.Err() != nil {
		t.Fatalf("session failed: %v", x.Conn.Session.Err())
	}
}

func TestLargeBodiesBothDirections(t *testing.T) {
	env := testenv.New(t, testenv.Options{})
	// Go's HTTP/1 origin is not full duplex: read the whole request before replying.
	origin := env.Origin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { b, _ := io.ReadAll(r.Body); w.Write(b) }))
	x := env.Expose(env.NewIdentity(), origin.URL, "")
	payload := make([]byte, 6<<20)
	for i := range payload {
		payload[i] = byte(i * 31)
	}
	resp, err := env.Request(x.Endpoint.Hostname, "POST", "/echo", bytes.NewReader(payload), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	got, err := io.ReadAll(resp.Body)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("echo mismatch: %d bytes err=%v", len(got), err)
	}
}

func TestPlatformErrorsAreDistinguishable(t *testing.T) {
	env := testenv.New(t, testenv.Options{})
	dead := "http://" + testenv.LoopbackAddr(t) // nothing listens
	x := env.Expose(env.NewIdentity(), dead, "")

	check := func(name, host, method, path string, status int, code string, hdr map[string]string) {
		t.Helper()
		resp, err := env.Request(host, method, path, nil, hdr)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != status || resp.Header.Get("X-127ohoh1-Error") != code {
			t.Errorf("%s: got %d %q (%s), want %d %q", name, resp.StatusCode, resp.Header.Get("X-127ohoh1-Error"), b, status, code)
		}
		if !strings.Contains(string(b), `"request_id":"req_`) {
			t.Errorf("%s: body lacks request id: %s", name, b)
		}
	}
	check("origin down", x.Endpoint.Hostname, "GET", "/", 502, "origin_unreachable", nil)
	check("unknown tenant", "no-such-name-0000", "GET", "/", 404, "endpoint_not_found", nil)
	// Protocol upgrades are proxied like any other request now (see
	// upgrade_test.go for the success path): against a dead origin, an
	// upgrade request fails exactly like a plain one.
	check("websocket upgrade, origin down", x.Endpoint.Hostname, "GET", "/", 502, "origin_unreachable", map[string]string{"Connection": "Upgrade", "Upgrade": "websocket"})

	// A browser gets a readable page instead of the JSON envelope: same status
	// and platform header, no scripts allowed, and nothing from the request
	// (Host) reflected into it.
	browser := map[string]string{"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}
	for _, tc := range []struct {
		name, host    string
		status        int
		code, heading string
	}{
		{"origin down", x.Endpoint.Hostname, 502, "origin_unreachable", "This site is offline"},
		{"unknown tenant", "no-such-name-0000", 404, "endpoint_not_found", "This site isn&#39;t online"},
	} {
		resp, err := env.Request(tc.host, "GET", "/", nil, browser)
		if err != nil {
			t.Fatalf("%s (browser): %v", tc.name, err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		page := string(b)
		if resp.StatusCode != tc.status || resp.Header.Get("X-127ohoh1-Error") != tc.code {
			t.Errorf("%s (browser): got %d %q, want %d %q", tc.name, resp.StatusCode, resp.Header.Get("X-127ohoh1-Error"), tc.status, tc.code)
		}
		if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
			t.Errorf("%s (browser): content-type %q", tc.name, ct)
		}
		if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") || strings.Contains(csp, "script-src") {
			t.Errorf("%s (browser): csp %q", tc.name, csp)
		}
		if !strings.Contains(page, "<h1>"+tc.heading+"</h1>") || !strings.Contains(page, "req_") || strings.Contains(page, `"error"`) {
			t.Errorf("%s (browser): unexpected page: %s", tc.name, page)
		}
		if strings.Contains(page, tc.host) {
			t.Errorf("%s (browser): request host reflected into the page", tc.name)
		}
	}

	// Host outside the platform domain.
	req, _ := http.NewRequest("GET", "http://"+env.Edge.Addrs().Ingress+"/", nil)
	req.Host = "evil.example.com"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 404 || resp.Header.Get("X-127ohoh1-Error") != "unknown_host" {
		t.Errorf("foreign host: %d %s", resp.StatusCode, resp.Header.Get("X-127ohoh1-Error"))
	}
	// Multi-label host cannot address another tenant.
	req.Host = "x." + x.Endpoint.Hostname + "." + testenv.BaseDomain
	resp, _ = http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Errorf("nested host: %d", resp.StatusCode)
	}
	// CONNECT is refused.
	c, _ := net.Dial("tcp", env.Edge.Addrs().Ingress)
	defer c.Close()
	fmt.Fprintf(c, "CONNECT example.com:443 HTTP/1.1\r\nHost: %s.%s\r\n\r\n", x.Endpoint.Hostname, testenv.BaseDomain)
	line, _ := io.ReadAll(io.LimitReader(c, 64))
	if !strings.Contains(string(line), "405") && !strings.Contains(string(line), "400") {
		t.Errorf("CONNECT not refused: %q", line)
	}
}

// Scenario 14: a duplicate session supersedes the old one.
func TestDuplicateSessionSupersedesOld(t *testing.T) {
	env := testenv.New(t, testenv.Options{})
	var which string
	mkOrigin := func(name string) *http.Handler {
		h := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, name) }))
		return &h
	}
	_ = which
	o1 := env.Origin(*mkOrigin("first"))
	o2 := env.Origin(*mkOrigin("second"))
	id := env.NewIdentity()
	x1 := env.Expose(id, o1.URL, "")
	if _, body := env.Get(x1.Endpoint.Hostname, "/"); body != "first" {
		t.Fatal(body)
	}
	x2 := env.Expose(id, o2.URL, x1.Endpoint.ID)
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, body := env.Get(x1.Endpoint.Hostname, "/"); body == "second" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("new session never took over")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// The old session was told to drain (GOAWAY) and ends once it is idle.
	select {
	case <-x1.Done:
	case <-time.After(10 * time.Second):
		t.Fatal("superseded session was not closed")
	}
	if !x1.Conn.Session.Draining() {
		t.Fatal("old session did not receive GOAWAY")
	}
	if x2.Conn.Session.Err() != nil {
		t.Fatal("new session must stay up")
	}
	if got := env.Edge.Registry.Count(); got != 1 {
		t.Fatalf("registry count %d", got)
	}
}

// The request target from the public caller can never redirect the client's
// request to another host (SSRF / open proxy).
func TestRequestTargetCannotChangeOriginHost(t *testing.T) {
	env := testenv.New(t, testenv.Options{})
	var gotURI, gotHost string
	origin := env.Origin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { gotURI, gotHost = r.RequestURI, r.Host }))
	x := env.Expose(env.NewIdentity(), origin.URL, "")
	for _, target := range []string{"//evil.example/steal", "/http://169.254.169.254/latest", "/%2e%2e/%2e%2e/etc/passwd"} {
		c, err := net.Dial("tcp", env.Edge.Addrs().Ingress)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: %s.%s\r\nConnection: close\r\n\r\n", target, x.Endpoint.Hostname, testenv.BaseDomain)
		io.Copy(io.Discard, c)
		c.Close()
		if gotURI != target {
			t.Errorf("origin saw %q for target %q", gotURI, target)
		}
		if gotHost == "evil.example" || gotHost == "169.254.169.254" {
			t.Errorf("host header taken from request target: %q", gotHost)
		}
	}
	// Absolute-form targets (as sent to proxies) are not honoured either.
	c, _ := net.Dial("tcp", env.Edge.Addrs().Ingress)
	fmt.Fprintf(c, "GET http://evil.example/x HTTP/1.1\r\nHost: %s.%s\r\nConnection: close\r\n\r\n", x.Endpoint.Hostname, testenv.BaseDomain)
	io.Copy(io.Discard, c)
	c.Close()
	if gotHost == "evil.example" {
		t.Error("absolute-form request target changed the origin host")
	}
}

// The primary CLI path: `127ohoh1 expose URL` end to end, including reuse of
// the same name after a restart.
func TestCLIExposeEndToEnd(t *testing.T) {
	env := testenv.New(t, testenv.Options{})
	origin := env.Origin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "via cli") }))
	dir := t.TempDir()
	ca := dir + "/ca.pem"
	os.WriteFile(ca, env.Edge.TLS.CAPEM, 0o600)
	idp := dir + "/id"

	run := func() (string, context.CancelFunc, chan int) {
		var out safeBuf
		ctx, cancel := context.WithCancel(bg)
		done := make(chan int, 1)
		go func() {
			done <- cli.Run(ctx, []string{"expose", origin.URL, "--api", env.CPServer.URL, "--identity", idp, "--edge", env.Edge.Addrs().Tunnel, "--ca", ca, "--json"},
				cli.Env{Stdout: &out, Stderr: io.Discard, Stdin: strings.NewReader(""), Getenv: func(string) string { return "" }})
		}()
		var info struct{ Hostname, URL, Plan string }
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			if s := out.String(); strings.Contains(s, "}") {
				json.Unmarshal([]byte(s[strings.Index(s, "{"):]), &info)
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if info.Hostname == "" {
			t.Fatalf("expose printed nothing useful: %q", out.String())
		}
		return info.Hostname, cancel, done
	}
	host1, cancel1, done1 := run()
	env.WaitRegistered(host1)
	if _, body := env.Get(host1, "/"); body != "via cli" {
		t.Fatalf("%q", body)
	}
	cancel1()
	if code := <-done1; code != cli.ExitOK {
		t.Fatalf("exit %d", code)
	}
	host2, cancel2, done2 := run()
	defer func() { cancel2(); <-done2 }()
	if host2 != host1 {
		t.Fatalf("name changed across restarts: %s -> %s", host1, host2)
	}
}

type safeBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *safeBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *safeBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }
