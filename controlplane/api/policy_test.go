package api_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/127ohoh1/core/internal/config"
	pp "github.com/127ohoh1/core/protocol/policy"
)

func TestPlansEndpointExactValues(t *testing.T) {
	_, ts := newApp(t, nil)
	resp, b := raw(t, "GET", ts.URL+"/v1/plans", "", nil, nil)
	if resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode)
	}
	var out struct {
		Plans []struct {
			ID    string `json:"id"`
			Price struct {
				Amount, Asset, Interval, Unit string
			} `json:"price"`
			BW      int64 `json:"bandwidth_bytes_per_second"`
			Burst   int64 `json:"burst_bytes"`
			Monthly int64 `json:"monthly_transfer_bytes"`
		} `json:"plans"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	want := []struct {
		id, amt       string
		bw, burst, mo int64
	}{
		{"free", "0", 100_000, 200_000, 500_000_000},
		{"tier_1", "1", 1_000_000, 2_000_000, 10_000_000_000},
		{"tier_2", "2", 3_000_000, 6_000_000, 100_000_000_000},
		{"tier_3", "4", 5_000_000, 10_000_000, 500_000_000_000},
	}
	if len(out.Plans) != 4 {
		t.Fatalf("%s", b)
	}
	for i, w := range want {
		g := out.Plans[i]
		if g.ID != w.id || g.Price.Amount != w.amt || g.Price.Asset != "USDC" || g.Price.Interval != "month" || g.Price.Unit != "name" ||
			g.BW != w.bw || g.Burst != w.burst || g.Monthly != w.mo {
			t.Errorf("plan %d: %+v", i, g)
		}
	}
}

func TestPolicyEndpointAuthorization(t *testing.T) {
	_, ts := newApp(t, nil)
	owner, other := newClient(t, ts), newClient(t, ts)
	ctx := context.Background()
	e, _ := owner.CreateEndpoint(ctx, "")
	url := ts.URL + "/v1/endpoints/" + e.ID + "/policy"

	otok, _, _ := owner.Login(ctx)
	xtok, _, _ := other.Login(ctx)
	svc := testConfig().EdgeServiceToken

	for name, tc := range map[string]struct {
		token string
		want  int
	}{"owner": {otok, 200}, "edge service": {svc, 200}, "other tenant": {xtok, 404}, "anonymous": {"", 401}, "junk": {"junk", 401}} {
		resp, b := raw(t, "GET", url, tc.token, nil, nil)
		if resp.StatusCode != tc.want {
			t.Errorf("%s: %d %s", name, resp.StatusCode, b)
		}
	}
	_, b := raw(t, "GET", url, svc, nil, nil)
	p, err := pp.Decode(b)
	if err != nil || p.State != pp.StateActive || p.Limits.BandwidthBytesPerSecond != 100_000 || p.PolicyVersion < 1 {
		t.Fatalf("%+v %v", p, err)
	}
	if resp, _ := raw(t, "GET", ts.URL+"/v1/endpoints/ep_nope/policy", svc, nil, nil); resp.StatusCode != 404 {
		t.Fatalf("unknown endpoint: %d", resp.StatusCode)
	}
}

func TestPolicyChangesRequiresServiceToken(t *testing.T) {
	_, ts := newApp(t, nil)
	c := newClient(t, ts)
	tok, _, _ := c.Login(context.Background())
	if resp, _ := raw(t, "GET", ts.URL+"/v1/policies/changes?since=0&wait=0", tok, nil, nil); resp.StatusCode != 401 {
		t.Fatalf("a customer session must not read the global change feed: %d", resp.StatusCode)
	}
	svc := testConfig().EdgeServiceToken
	for _, q := range []string{"?since=x", "?since=-1", "?since=0&wait=999", ""} {
		if resp, _ := raw(t, "GET", ts.URL+"/v1/policies/changes"+q, svc, nil, nil); resp.StatusCode != 400 {
			t.Errorf("%q: %d", q, resp.StatusCode)
		}
	}
	resp, b := raw(t, "GET", ts.URL+"/v1/policies/changes?since=0&wait=0", svc, nil, nil)
	if resp.StatusCode != 200 || !strings.Contains(string(b), `"seq"`) {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
}

func TestAdminHooksDisabledByDefaultAndAuditedWhenEnabled(t *testing.T) {
	_, ts := newApp(t, nil)
	if resp, _ := raw(t, "POST", ts.URL+"/v1/admin/emergency", "anything", map[string]any{"enabled": true}, nil); resp.StatusCode != 404 {
		t.Fatalf("admin API must not exist without a configured token: %d", resp.StatusCode)
	}

	const adminTok = "admin-token-for-tests-0123456789"
	a, ts2 := newApp(t, func(c *config.ControlPlane) { c.AdminToken = adminTok })
	svc := testConfig().EdgeServiceToken
	c := newClient(t, ts2)
	ctx := context.Background()
	e, _ := c.CreateEndpoint(ctx, "")
	polURL := ts2.URL + "/v1/endpoints/" + e.ID + "/policy"
	get := func() pp.EndpointPolicy {
		_, b := raw(t, "GET", polURL, svc, nil, nil)
		p, _ := pp.Decode(b)
		return p
	}
	v0 := get().PolicyVersion

	// Wrong tokens (including the edge service token) are refused.
	for _, tok := range []string{"", "wrong", svc} {
		if resp, _ := raw(t, "POST", ts2.URL+"/v1/admin/endpoints/"+e.ID+"/suspend", tok, nil, nil); resp.StatusCode != 401 {
			t.Errorf("token %q: %d", tok, resp.StatusCode)
		}
	}
	if get().State != pp.StateActive {
		t.Fatal("unauthenticated call changed state")
	}
	resp, b := raw(t, "POST", ts2.URL+"/v1/admin/endpoints/"+e.ID+"/suspend", adminTok, map[string]any{"reason": "abuse case 42"}, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	if p := get(); p.State != pp.StateSuspended || p.PolicyVersion <= v0 {
		t.Fatalf("suspension not published: %+v", p)
	}
	// Suspended endpoints cannot obtain tunnel credentials.
	if _, err := c.TunnelCredentials(ctx, e.ID); err == nil {
		t.Fatal("credentials issued for a suspended endpoint")
	}
	raw(t, "POST", ts2.URL+"/v1/admin/endpoints/"+e.ID+"/suspend", adminTok, nil, nil) // idempotent
	raw(t, "POST", ts2.URL+"/v1/admin/endpoints/"+e.ID+"/unsuspend", adminTok, nil, nil)
	if get().State != pp.StateActive {
		t.Fatal("unsuspend")
	}

	// Principal suspension propagates to every endpoint and blocks sessions.
	tokBefore, _, _ := c.Login(ctx)
	ep, _ := a.Endpoints.GetByID(ctx, e.ID)
	pr := struct{ PrincipalID string }{ep.PrincipalID}
	if resp, _ := raw(t, "POST", ts2.URL+"/v1/admin/principals/"+pr.PrincipalID+"/suspend", adminTok, nil, nil); resp.StatusCode != 200 {
		t.Fatalf("suspend principal: %d", resp.StatusCode)
	}
	if get().State != pp.StateSuspended {
		t.Fatal("principal suspension did not reach the endpoint policy")
	}
	if resp, _ := raw(t, "GET", ts2.URL+"/v1/endpoints", tokBefore, nil, nil); resp.StatusCode != 403 {
		t.Fatalf("existing session of a suspended principal: %d", resp.StatusCode)
	}
	raw(t, "POST", ts2.URL+"/v1/admin/principals/"+pr.PrincipalID+"/unsuspend", adminTok, nil, nil)
	if get().State != pp.StateActive {
		t.Fatal("restore")
	}

	// Emergency override.
	raw(t, "POST", ts2.URL+"/v1/admin/emergency", adminTok, map[string]any{"enabled": true}, nil)
	if get().State != pp.StateSuspended {
		t.Fatal("emergency override")
	}
	raw(t, "POST", ts2.URL+"/v1/admin/emergency", adminTok, map[string]any{"enabled": false}, nil)
	if get().State != pp.StateActive {
		t.Fatal("emergency clear")
	}
	if resp, _ := raw(t, "POST", ts2.URL+"/v1/admin/emergency", adminTok, map[string]any{}, nil); resp.StatusCode != 400 {
		t.Fatal("emergency without 'enabled' must be a 400")
	}

	// Audit: every admin call is recorded, denials included, and the reason is kept.
	var denied, ok int
	var sawReason bool
	for _, ev := range a.Audit.Events() {
		if !strings.Contains(ev.Action, "suspend") && !strings.Contains(ev.Action, "emergency") {
			continue
		}
		if ev.Result == "denied" {
			denied++
		} else {
			ok++
		}
		if ev.Metadata["reason"] == "abuse case 42" {
			sawReason = true
		}
	}
	if denied != 3 || ok < 6 || !sawReason {
		t.Fatalf("audit trail incomplete: denied=%d ok=%d reason=%v", denied, ok, sawReason)
	}
}
