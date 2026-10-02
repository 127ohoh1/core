package api_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/127ohoh1/core/internal/config"
)

func TestAbuseReportIntakeContract(t *testing.T) {
	const adminTok = "admin-token-for-tests-0123456789"
	a, ts := newApp(t, func(c *config.ControlPlane) { c.AdminToken = adminTok; c.AbuseReportsPerMinute = 600 })
	c := newClient(t, ts)
	ep, _ := c.CreateEndpoint(context.Background(), "")

	// No account needed: a victim can report.
	resp, b := raw(t, "POST", ts.URL+"/v1/abuse-reports", "", map[string]string{
		"hostname": strings.ToUpper(ep.Hostname) + ".127ohoh1.com", "category": "phishing",
		"description": "Looks like a bank login page.\x1b[31m", "url": "https://" + ep.Hostname + ".127ohoh1.com/login", "contact": "reporter@example.org"}, nil)
	if resp.StatusCode != 202 {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	if !strings.Contains(string(b), "no automatic action") {
		t.Fatalf("intake must state that nothing is auto-enforced: %s", b)
	}
	// Nothing is enforced automatically.
	if e, _ := a.Endpoints.GetByID(context.Background(), ep.ID); string(e.State) != "ACTIVE" {
		t.Fatal("a report must never change endpoint state by itself")
	}

	for name, body := range map[string]map[string]string{
		"bad category": {"hostname": "x1", "category": "nope"},
		"no hostname":  {"category": "spam"},
		"long desc":    {"hostname": "x1", "category": "spam", "description": strings.Repeat("a", 2001)},
		"long contact": {"hostname": "x1", "category": "spam", "contact": strings.Repeat("a", 201)},
	} {
		if resp, _ := raw(t, "POST", ts.URL+"/v1/abuse-reports", "", body, nil); resp.StatusCode != 400 {
			t.Errorf("%s: %d", name, resp.StatusCode)
		}
	}
	if resp, _ := raw(t, "POST", ts.URL+"/v1/abuse-reports", "", map[string]any{"hostname": "x1", "category": "spam", "unexpected": 1}, nil); resp.StatusCode != 400 {
		t.Errorf("unknown field accepted: %d", resp.StatusCode)
	}
	big := strings.Repeat("a", 20<<10)
	if resp, _ := raw(t, "POST", ts.URL+"/v1/abuse-reports", "", map[string]string{"hostname": "x1", "category": "spam", "description": big}, nil); resp.StatusCode != 413 {
		t.Errorf("oversize body: %d", resp.StatusCode)
	}

	// Operator review links to the manual suspension hook via endpoint_id; the ESC character was stripped.
	resp, b = raw(t, "GET", ts.URL+"/v1/admin/abuse-reports?hostname="+ep.Hostname, adminTok, nil, nil)
	var out struct {
		Reports []struct {
			ID, Hostname, Category, Description, Status string
			EndpointID                                  string `json:"endpoint_id"`
		}
	}
	json.Unmarshal(b, &out)
	if resp.StatusCode != 200 || len(out.Reports) != 1 || out.Reports[0].EndpointID != ep.ID || out.Reports[0].Hostname != ep.Hostname ||
		out.Reports[0].Status != "REPORTED" || strings.Contains(out.Reports[0].Description, "\x1b") {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	if resp, _ := raw(t, "GET", ts.URL+"/v1/admin/abuse-reports", "wrong", nil, nil); resp.StatusCode != 401 {
		t.Fatalf("listing needs the admin token: %d", resp.StatusCode)
	}
	if resp, _ := raw(t, "POST", ts.URL+"/v1/admin/endpoints/"+ep.ID+"/suspend", adminTok, map[string]string{"reason": "abuse report " + out.Reports[0].ID}, nil); resp.StatusCode != 200 {
		t.Fatalf("manual enforcement hook: %d", resp.StatusCode)
	}
}

func TestAbuseIntakeIsRateLimited(t *testing.T) {
	_, ts := newApp(t, nil)
	limited := false
	for i := 0; i < 20; i++ {
		resp, _ := raw(t, "POST", ts.URL+"/v1/abuse-reports", "", map[string]string{"hostname": "spam-target", "category": "spam"}, nil)
		if resp.StatusCode == 429 {
			limited = true
			if resp.Header.Get("Retry-After") == "" {
				t.Error("missing Retry-After")
			}
			break
		}
	}
	if !limited {
		t.Fatal("the public abuse endpoint must defend itself against spam")
	}
}
