package api_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/127ohoh1/core/client/api"
	cid "github.com/127ohoh1/core/client/identity"
	"github.com/127ohoh1/core/controlplane/app"
	"github.com/127ohoh1/core/internal/config"
	"github.com/127ohoh1/core/internal/observability"
	"github.com/127ohoh1/core/protocol/auth"
)

func testConfig() config.ControlPlane {
	c := config.DefaultControlPlane()
	c.AppEnv = config.EnvTest
	c.EdgeServiceToken = strings.Repeat("s", 32)
	c.EdgeTunnelAddr = "127.0.0.1:7443"
	c.PublicPort = 8443
	return c
}

func newApp(t *testing.T, mutate func(*config.ControlPlane)) (*app.App, *httptest.Server) {
	t.Helper()
	cfg := testConfig()
	if mutate != nil {
		mutate(&cfg)
	}
	a, err := app.New(cfg, app.Options{Log: observability.NewLogger(io.Discard, "error", "test")})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(a.Handler())
	t.Cleanup(ts.Close)
	return a, ts
}

func newClient(t *testing.T, ts *httptest.Server) *api.Client {
	t.Helper()
	id, err := cid.Generate(filepath.Join(t.TempDir(), "id"))
	if err != nil {
		t.Fatal(err)
	}
	return api.New(ts.URL, id, nil)
}

func raw(t *testing.T, method, url, token string, body any, hdr map[string]string) (*http.Response, []byte) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, url, rd)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

func TestRegisterEndpointAndTunnelCredential(t *testing.T) {
	a, ts := newApp(t, nil)
	c := newClient(t, ts)
	ctx := context.Background()

	e, err := c.CreateEndpoint(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if e.State != "ACTIVE" || e.Kind != "random" || e.Plan != "free" || !strings.HasPrefix(e.URL, "https://"+e.Hostname+".127ohoh1.localhost:8443") {
		t.Fatalf("%+v", e)
	}
	got, err := c.GetEndpoint(ctx, e.ID)
	if err != nil || got.ID != e.ID {
		t.Fatal(err)
	}
	list, _ := c.ListEndpoints(ctx)
	if len(list) != 1 {
		t.Fatalf("list: %v", list)
	}

	cred, err := c.TunnelCredentials(ctx, e.ID)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := a.Keys.Verify(cred.Token, auth.TypeTunnel, "127ohoh1-edge", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if claims.Endpoint != e.ID || claims.Hostname != e.Hostname || claims.PublicKey != c.Identity.PublicKeyString() {
		t.Fatalf("claims not scoped: %+v", claims)
	}
	if cred.Edge.Addr != "127.0.0.1:7443" {
		t.Fatalf("edge addr %q", cred.Edge.Addr)
	}

	// Delete is idempotent; the name is released and credentials are refused.
	for i := 0; i < 2; i++ {
		d, err := c.DeleteEndpoint(ctx, e.ID)
		if err != nil || d.State != "RELEASED" {
			t.Fatalf("delete #%d: %v %+v", i, err, d)
		}
	}
	if _, err := c.TunnelCredentials(ctx, e.ID); !api.IsCode(err, "gone") {
		t.Fatalf("credentials for released endpoint: %v", err)
	}
	if list, _ := c.ListEndpoints(ctx); len(list) != 0 {
		t.Fatal("released endpoint still listed")
	}
}

func TestRestartRecoversSameEndpoint(t *testing.T) {
	_, ts := newApp(t, nil)
	path := filepath.Join(t.TempDir(), "id")
	id, _ := cid.Generate(path)
	ctx := context.Background()
	e1, err := api.New(ts.URL, id, nil).CreateEndpoint(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	// "Client restart": reload identity from disk, new client, new session.
	id2, err := cid.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	list, err := api.New(ts.URL, id2, nil).ListEndpoints(ctx)
	if err != nil || len(list) != 1 || list[0].ID != e1.ID {
		t.Fatalf("did not recover endpoint: %v %v", list, err)
	}
}

func challenge(t *testing.T, ts *httptest.Server, pub ed25519.PublicKey) (id, nonce string, c auth.Challenge) {
	t.Helper()
	resp, b := raw(t, "POST", ts.URL+"/v1/auth/challenges", "", map[string]string{"public_key": auth.EncodeKey(pub)}, nil)
	if resp.StatusCode != 201 {
		t.Fatalf("challenge: %d %s", resp.StatusCode, b)
	}
	var ch struct {
		ID, Nonce, Audience string
		IssuedAt, ExpiresAt string
	}
	var m map[string]any
	json.Unmarshal(b, &m)
	ch.ID, ch.Nonce, ch.Audience = m["challenge_id"].(string), m["nonce"].(string), m["audience"].(string)
	ch.IssuedAt, ch.ExpiresAt = m["issued_at"].(string), m["expires_at"].(string)
	n, _ := auth.NonceDecode(ch.Nonce)
	iat, _ := time.Parse(time.RFC3339, ch.IssuedAt)
	exp, _ := time.Parse(time.RFC3339, ch.ExpiresAt)
	return ch.ID, ch.Nonce, auth.Challenge{ID: ch.ID, Nonce: n, Audience: ch.Audience, Fingerprint: auth.Fingerprint(pub), IssuedAt: iat, ExpiresAt: exp}
}

func TestWrongKeySignatureRejected(t *testing.T) {
	_, ts := newApp(t, nil)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, evil, _ := ed25519.GenerateKey(rand.Reader)
	id, nonce, c := challenge(t, ts, pub)
	sig, _ := auth.SignChallenge(evil, c)
	resp, b := raw(t, "POST", ts.URL+"/v1/auth/sessions", "", map[string]string{"challenge_id": id, "nonce": nonce, "signature": auth.EncodeSig(sig)}, nil)
	if resp.StatusCode != 401 || !strings.Contains(string(b), `"code":"unauthorized"`) {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
}

func TestReplayedChallengeRejected(t *testing.T) {
	_, ts := newApp(t, nil)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	id, nonce, c := challenge(t, ts, pub)
	sig, _ := auth.SignChallenge(priv, c)
	body := map[string]string{"challenge_id": id, "nonce": nonce, "signature": auth.EncodeSig(sig)}
	if resp, b := raw(t, "POST", ts.URL+"/v1/auth/sessions", "", body, nil); resp.StatusCode != 201 {
		t.Fatalf("first: %d %s", resp.StatusCode, b)
	}
	if resp, _ := raw(t, "POST", ts.URL+"/v1/auth/sessions", "", body, nil); resp.StatusCode != 401 {
		t.Fatalf("replay accepted: %d", resp.StatusCode)
	}
}

func TestIdempotentEndpointCreation(t *testing.T) {
	_, ts := newApp(t, nil)
	c := newClient(t, ts)
	ctx := context.Background()
	e1, err := c.CreateEndpoint(ctx, "idem-key-0001")
	if err != nil {
		t.Fatal(err)
	}
	e2, err := c.CreateEndpoint(ctx, "idem-key-0001")
	if err != nil || e2.ID != e1.ID || e2.Hostname != e1.Hostname {
		t.Fatalf("replay must return the original resource: %v %+v", err, e2)
	}
	if list, _ := c.ListEndpoints(ctx); len(list) != 1 {
		t.Fatalf("idempotent retry created %d endpoints", len(list))
	}
	e3, _ := c.CreateEndpoint(ctx, "idem-key-0002")
	if e3.ID == e1.ID {
		t.Fatal("different key must create a new endpoint")
	}

	// Same key, different request => conflict.
	tok, _, _ := c.Login(ctx)
	resp, b := raw(t, "POST", ts.URL+"/v1/endpoints", tok, map[string]string{}, map[string]string{"Idempotency-Key": "idem-key-0001"})
	if resp.StatusCode != 409 || !strings.Contains(string(b), "idempotency_key_reused") {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	// Keys are scoped per principal.
	c2 := newClient(t, ts)
	e4, err := c2.CreateEndpoint(ctx, "idem-key-0001")
	if err != nil || e4.ID == e1.ID {
		t.Fatalf("idempotency keys must not leak across principals: %v", err)
	}
}

func TestEndpointCapPerPrincipal(t *testing.T) {
	_, ts := newApp(t, func(c *config.ControlPlane) { c.MaxEndpointsPerPrincipal = 2 })
	c := newClient(t, ts)
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if _, err := c.CreateEndpoint(ctx, ""); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.CreateEndpoint(ctx, ""); !api.IsCode(err, "rate_limited") {
		t.Fatalf("got %v", err)
	}
}

func TestCrossTenantIsolation(t *testing.T) {
	_, ts := newApp(t, nil)
	a, b := newClient(t, ts), newClient(t, ts)
	ctx := context.Background()
	e, _ := a.CreateEndpoint(ctx, "")
	if _, err := b.GetEndpoint(ctx, e.ID); !api.IsCode(err, "not_found") {
		t.Fatalf("get: %v", err)
	}
	if _, err := b.DeleteEndpoint(ctx, e.ID); !api.IsCode(err, "not_found") {
		t.Fatalf("delete: %v", err)
	}
	if _, err := b.TunnelCredentials(ctx, e.ID); !api.IsCode(err, "not_found") {
		t.Fatalf("credentials: %v", err)
	}
	if list, _ := b.ListEndpoints(ctx); len(list) != 0 {
		t.Fatal("list leaked")
	}
}

func TestUnauthenticatedAndMalformed(t *testing.T) {
	_, ts := newApp(t, nil)
	resp, b := raw(t, "GET", ts.URL+"/v1/endpoints", "", nil, nil)
	if resp.StatusCode != 401 || resp.Header.Get("WWW-Authenticate") == "" {
		t.Fatalf("%d", resp.StatusCode)
	}
	var env struct {
		Error struct {
			Code      string `json:"code"`
			RequestID string `json:"request_id"`
		} `json:"error"`
	}
	json.Unmarshal(b, &env)
	if env.Error.Code != "unauthorized" || !strings.HasPrefix(env.Error.RequestID, "req_") || resp.Header.Get("X-Request-Id") != env.Error.RequestID {
		t.Fatalf("envelope: %s", b)
	}
	if resp, _ := raw(t, "GET", ts.URL+"/v1/endpoints", "garbage.token", nil, nil); resp.StatusCode != 401 {
		t.Fatalf("garbage token: %d", resp.StatusCode)
	}
	for _, body := range []string{`{"public_key":1}`, `{"public_key":"x","extra":1}`, `not json`, `{"public_key":"x"} {}`} {
		req, _ := http.NewRequest("POST", ts.URL+"/v1/auth/challenges", strings.NewReader(body))
		r, _ := http.DefaultClient.Do(req)
		r.Body.Close()
		if r.StatusCode != 400 {
			t.Errorf("%q: %d", body, r.StatusCode)
		}
	}
	big := strings.Repeat("a", 70<<10)
	req, _ := http.NewRequest("POST", ts.URL+"/v1/auth/challenges", strings.NewReader(`{"public_key":"`+big+`"}`))
	r, _ := http.DefaultClient.Do(req)
	r.Body.Close()
	if r.StatusCode != 413 {
		t.Errorf("oversize body: %d", r.StatusCode)
	}
}

func TestChallengeRateLimit(t *testing.T) {
	_, ts := newApp(t, nil)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	limited := false
	for i := 0; i < 40; i++ {
		resp, _ := raw(t, "POST", ts.URL+"/v1/auth/challenges", "", map[string]string{"public_key": auth.EncodeKey(pub)}, nil)
		if resp.StatusCode == 429 {
			limited = true
			if resp.Header.Get("Retry-After") == "" {
				t.Error("missing Retry-After")
			}
			break
		}
	}
	if !limited {
		t.Fatal("registration spam not rate limited")
	}
}

func TestKeysAndHealth(t *testing.T) {
	a, ts := newApp(t, nil)
	if resp, _ := raw(t, "GET", ts.URL+"/healthz", "", nil, nil); resp.StatusCode != 200 {
		t.Fatal("healthz")
	}
	if resp, _ := raw(t, "GET", ts.URL+"/readyz", "", nil, nil); resp.StatusCode != 200 {
		t.Fatal("readyz")
	}
	_, b := raw(t, "GET", ts.URL+"/v1/keys", "", nil, nil)
	if !strings.Contains(string(b), auth.EncodeKey(a.Signer.PublicKey())) {
		t.Fatalf("keys: %s", b)
	}
}
