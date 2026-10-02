package cert

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAutocertHostAllowed(t *testing.T) {
	extra := []string{"connect.127ohoh1.com"}
	cases := []struct {
		host string
		want bool
	}{
		{"127ohoh1.com", true},
		{"127OHOH1.com", true}, // case-insensitive
		{"www.127ohoh1.com", true},
		{"connect.127ohoh1.com", true},
		{"quiet-river-7f2c.127ohoh1.com", true},
		{"a.127ohoh1.com", true},
		{"evil.other.com", false},
		{"nested.tenant.127ohoh1.com", false}, // two labels under base: reject
		{"127ohoh1.com.evil.com", false},
		{"", false},
		{"127ohoh1.com.", false},
	}
	for _, c := range cases {
		if got := AutocertHostAllowed("127ohoh1.com", extra, c.host); got != c.want {
			t.Errorf("AutocertHostAllowed(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

func TestClassifyAutocertHostTenantCandidate(t *testing.T) {
	extra := []string{"tunnel.127ohoh1.com"}
	cases := []struct {
		host           string
		wantLabel      string
		wantTenantCand bool
		wantAllowed    bool
	}{
		{"127ohoh1.com", "", false, true},
		{"www.127ohoh1.com", "", false, true},
		{"tunnel.127ohoh1.com", "", false, true}, // extra: not a tenant candidate, never needs a directory check
		{"quiet-river-7f2c.127ohoh1.com", "quiet-river-7f2c", true, true},
		{"evil.other.com", "", false, false},
	}
	for _, c := range cases {
		label, isCand, allowed := classifyAutocertHost("127ohoh1.com", extra, c.host)
		if label != c.wantLabel || isCand != c.wantTenantCand || allowed != c.wantAllowed {
			t.Errorf("classifyAutocertHost(%q) = (%q,%v,%v), want (%q,%v,%v)", c.host, label, isCand, allowed, c.wantLabel, c.wantTenantCand, c.wantAllowed)
		}
	}
}

// TestNewAutocertRefusesUnknownTenant is the regression test for the
// 2026-10-01 finding: a tenant-shaped hostname with no live tunnel must not
// reach ACME issuance, so spraying invented names can't exhaust Let's
// Encrypt's rate limit. It drives HostPolicy directly (through the Manager
// autocert.Manager wraps internally isn't exported), which is the function
// that decides whether an issuance is even attempted.
func TestNewAutocertRefusesUnknownTenant(t *testing.T) {
	dir := t.TempDir()
	var queried string
	known := func(_ context.Context, label string) bool { queried = label; return label == "quiet-river-7f2c" }
	a, _ := NewAutocert(dir, "127ohoh1.com", "", []string{"tunnel.127ohoh1.com"}, known)

	cases := []struct {
		host    string
		wantErr bool
	}{
		{"quiet-river-7f2c.127ohoh1.com", false}, // known tenant: HostPolicy accepts
		{"never-reserved-xyz.127ohoh1.com", true},
		{"tunnel.127ohoh1.com", false}, // extra: no directory lookup needed
		{"evil.other.com", true},
	}
	for _, c := range cases {
		err := a.mgr.HostPolicy(context.Background(), c.host)
		if (err != nil) != c.wantErr {
			t.Errorf("HostPolicy(%q) error = %v, wantErr %v", c.host, err, c.wantErr)
		}
	}
	if queried != "never-reserved-xyz" {
		t.Errorf("knownTenant was last queried with %q, want the invented label (confirms it's actually consulted)", queried)
	}
}

// TestAutocertHTTPHandlerRejectsUnknownHost is the regression test for the
// Host-header open redirect: a request for a hostname this deployment
// doesn't serve at all must get a plain 404, never a redirect built from
// that same attacker-controlled Host.
func TestAutocertHTTPHandlerRejectsUnknownHost(t *testing.T) {
	dir := t.TempDir()
	_, handler := NewAutocert(dir, "127ohoh1.com", "", nil, func(context.Context, string) bool { return true })

	req := httptest.NewRequest("GET", "http://127ohoh1.com/some/path", nil)
	req.Host = "evil.example.com"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Fatalf("must not redirect for an unrecognized host, got Location: %s", loc)
	}

	req2 := httptest.NewRequest("GET", "http://127ohoh1.com/some/path", nil)
	req2.Host = "quiet-river-7f2c.127ohoh1.com"
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	if rec2.Code == http.StatusNotFound {
		t.Fatalf("a recognized tenant-shaped host must reach autocert's own handler, not be rejected by the filter")
	}
}
