package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/127ohoh1/core/controlplane/app"
	"github.com/127ohoh1/core/internal/config"
	"github.com/127ohoh1/core/internal/observability"
)

func run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := Run(context.Background(), args, Env{Stdout: &out, Stderr: &errb, Stdin: strings.NewReader(""), Getenv: func(string) string { return "" }})
	return code, out.String(), errb.String()
}

func testServer(t *testing.T) *httptest.Server {
	t.Helper()
	c := config.DefaultControlPlane()
	c.AppEnv, c.EdgeServiceToken, c.EdgeTunnelAddr = config.EnvTest, strings.Repeat("s", 32), "127.0.0.1:7443"
	a, err := app.New(c, app.Options{Log: observability.NewLogger(io.Discard, "error", "t")})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(a.Handler())
	t.Cleanup(ts.Close)
	return ts
}

func TestVersionAndUsage(t *testing.T) {
	if code, out, _ := run(t, "version"); code != ExitOK || !strings.Contains(out, "127ohoh1") {
		t.Fatal(code, out)
	}
	if code, _, _ := run(t); code != ExitUsage {
		t.Fatalf("no args: %d", code)
	}
	if code, _, _ := run(t, "bogus"); code != ExitUsage {
		t.Fatalf("bogus: %d", code)
	}
	if code, _, _ := run(t, "endpoints", "inspect"); code != ExitUsage && code != ExitNetwork {
		t.Fatalf("inspect without id: %d", code)
	}
}

func TestIdentityShowNeverPrintsPrivateKey(t *testing.T) {
	ts := testServer(t)
	idp := filepath.Join(t.TempDir(), "id")
	if code, _, e := run(t, "endpoints", "create", "--api", ts.URL, "--identity", idp); code != ExitOK {
		t.Fatalf("%d %s", code, e)
	}
	code, out, _ := run(t, "identity", "show", "--identity", idp, "--json")
	if code != ExitOK {
		t.Fatal(code)
	}
	raw, _ := os.ReadFile(idp)
	body := strings.Split(string(raw), "\n")[1]
	if strings.Contains(out, body) || strings.Contains(out, "PRIVATE") {
		t.Fatal("private key material leaked")
	}
	var m map[string]string
	json.Unmarshal([]byte(out), &m)
	if len(m["fingerprint"]) != 43 {
		t.Fatalf("%v", m)
	}
}

func TestEndpointsLifecycleAndExitCodes(t *testing.T) {
	ts := testServer(t)
	idp := filepath.Join(t.TempDir(), "id")
	common := []string{"--api", ts.URL, "--identity", idp}
	code, out, _ := run(t, append([]string{"endpoints", "create", "--json"}, common...)...)
	if code != ExitOK {
		t.Fatal(code)
	}
	var e struct {
		ID, State string
	}
	json.Unmarshal([]byte(out), &e)
	if e.ID == "" {
		t.Fatalf("no id in %s", out)
	}
	if code, out, _ := run(t, append([]string{"endpoints", "list"}, common...)...); code != ExitOK || !strings.Contains(out, e.ID) {
		t.Fatalf("list: %d %s", code, out)
	}
	if code, _, _ := run(t, append([]string{"endpoints", "delete", e.ID}, common...)...); code != ExitOK {
		t.Fatalf("delete: %d", code)
	}
	if code, _, _ := run(t, append([]string{"endpoints", "inspect", "ep_missing"}, common...)...); code != ExitFailure {
		t.Fatalf("not found should be a generic failure: %d", code)
	}
	// Unreachable API => network exit code.
	if code, _, _ := run(t, "endpoints", "list", "--api", "http://127.0.0.1:1", "--identity", idp); code != ExitNetwork {
		t.Fatalf("network: %d", code)
	}
}

func TestBadIdentityPermissionsExitAuth(t *testing.T) {
	idp := filepath.Join(t.TempDir(), "id")
	run(t, "endpoints", "list", "--api", "http://127.0.0.1:1", "--identity", idp) // generates the key
	os.Chmod(idp, 0o644)
	if code, _, _ := run(t, "identity", "show", "--identity", idp); code != ExitAuth {
		t.Fatalf("got %d", code)
	}
}
