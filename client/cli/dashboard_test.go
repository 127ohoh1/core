package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cid "github.com/127ohoh1/core/client/identity"
)

// stubAuth answers the challenge-response login, accepting any signature.
func stubAuth(w http.ResponseWriter, r *http.Request) bool {
	w.Header().Set("Content-Type", "application/json")
	exp := time.Now().Add(5 * time.Minute).UTC().Format(time.RFC3339)
	switch r.URL.Path {
	case "/v1/auth/challenges":
		_ = json.NewEncoder(w).Encode(map[string]string{"challenge_id": "ch_1", "nonce": base64.RawURLEncoding.EncodeToString(make([]byte, 32)), "audience": "x",
			"issued_at": time.Now().UTC().Format(time.RFC3339), "expires_at": exp})
		return true
	case "/v1/auth/sessions":
		_ = json.NewEncoder(w).Encode(map[string]string{"session_token": "tok", "expires_at": exp})
		return true
	}
	return false
}

// stubAPI accepts any challenge signature (the hosted service checks it; here
// only the CLI side is under test) and answers the two account endpoints.
func stubAPI(t *testing.T, linked bool) (*httptest.Server, *int) {
	t.Helper()
	calls := 0
	exp := time.Now().Add(5 * time.Minute).UTC().Format(time.RFC3339)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if stubAuth(w, r) {
			return
		}
		switch r.URL.Path {
		case "/v1/dashboard-links":
			calls++
			if r.Header.Get("Authorization") == "" {
				w.WriteHeader(401)
				return
			}
			w.WriteHeader(201)
			_ = json.NewEncoder(w).Encode(map[string]string{"url": "https://127ohoh1.example/app/#k=secret", "expires_at": exp})
		case "/v1/device-links":
			calls++
			if linked {
				w.WriteHeader(409)
				_, _ = w.Write([]byte(`{"error":{"code":"conflict","message":"The request conflicts with current state."}}`))
				return
			}
			w.WriteHeader(201)
			_ = json.NewEncoder(w).Encode(map[string]string{"code": "ABCD-EFGH", "expires_at": exp})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(ts.Close)
	return ts, &calls
}

func TestDashboardPrintsAndOpensTheLink(t *testing.T) {
	path := filepath.Join(t.TempDir(), "id")
	ts, calls := stubAPI(t, false)
	args := []string{"dashboard", "--api", ts.URL, "--identity", path}

	// No identity: nothing is generated and nothing is asked for.
	if code, _, errb := run(t, args...); code != ExitAuth || !strings.Contains(errb, "no identity") || *calls != 0 {
		t.Fatalf("without an identity: %d %q calls=%d", code, errb, *calls)
	}
	if _, _, err := cid.LoadOrGenerate(path); err != nil {
		t.Fatal(err)
	}

	var out, errb bytes.Buffer
	opened := ""
	env := Env{Stdout: &out, Stderr: &errb, Getenv: func(string) string { return "" }, Interactive: true, OpenURL: func(u string) error { opened = u; return nil }}
	if code := Run(context.Background(), args, env); code != ExitOK {
		t.Fatalf("dashboard: %d %s", code, errb.String())
	}
	if !strings.Contains(out.String(), "https://127ohoh1.example/app/#k=secret") || opened != "https://127ohoh1.example/app/#k=secret" {
		t.Fatalf("out %q opened %q", out.String(), opened)
	}
	if !strings.Contains(out.String(), "don't share it") {
		t.Fatal("no warning that the link is a credential")
	}

	opened = ""
	if code := Run(context.Background(), append(args, "--no-open"), env); code != ExitOK || opened != "" {
		t.Fatalf("--no-open: %d opened %q", code, opened)
	}
	code, o, _ := run(t, append(args, "--json")...)
	var l struct{ URL string }
	if code != ExitOK || json.Unmarshal([]byte(o), &l) != nil || l.URL == "" {
		t.Fatalf("--json: %d %q", code, o)
	}
}

func TestLinkPrintsACodeOrPointsToTheDashboard(t *testing.T) {
	path := filepath.Join(t.TempDir(), "id")
	if _, _, err := cid.LoadOrGenerate(path); err != nil {
		t.Fatal(err)
	}
	ts, _ := stubAPI(t, false)
	if code, out, _ := run(t, "link", "--api", ts.URL, "--identity", path); code != ExitOK || !strings.Contains(out, "ABCD-EFGH") {
		t.Fatalf("link: %d %q", code, out)
	}
	ts, _ = stubAPI(t, true)
	if code, _, errb := run(t, "link", "--api", ts.URL, "--identity", path); code != ExitFailure || !strings.Contains(errb, "127ohoh1 dashboard") {
		t.Fatalf("already linked: %d %q", code, errb)
	}
}
