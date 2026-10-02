package api_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/127ohoh1/core/controlplane/app"
	"github.com/127ohoh1/core/internal/config"
	pp "github.com/127ohoh1/core/protocol/policy"
)

func devPayments(c *config.ControlPlane) { c.DevelopmentPayments = true }

type offerDoc struct {
	ID     string `json:"id"`
	Plan   string `json:"plan"`
	Status string `json:"status"`
	Scope  struct {
		Type string `json:"type"`
		Name string `json:"name"`
	} `json:"scope"`
	Price struct {
		Amount, Asset, Interval, Unit string
	} `json:"price"`
	Limits struct {
		BW int64 `json:"bandwidth_bytes_per_second"`
		MO int64 `json:"monthly_transfer_bytes"`
	} `json:"limits"`
	Methods []struct {
		Type, Network, Asset string
		PaymentRequest       string `json:"payment_request"`
		Simulated            bool   `json:"simulated"`
	} `json:"payment_methods"`
	PaymentID string `json:"payment_id"`
	ExpiresAt string `json:"expires_at"`
	StatusURL string `json:"status_url"`
}

func mkOffer(t *testing.T, base, tok, name, plan string, hdr map[string]string) (int, offerDoc, []byte) {
	t.Helper()
	resp, b := raw(t, "POST", base+"/v1/offers", tok, map[string]string{"name": name, "plan": plan}, hdr)
	var d offerDoc
	json.Unmarshal(b, &d)
	return resp.StatusCode, d, b
}

func TestOffersCarryExactTierTerms(t *testing.T) {
	_, ts := newApp(t, devPayments)
	c := newClient(t, ts)
	tok, _, _ := c.Login(context.Background())
	want := map[string]struct {
		amount string
		bw, mo int64
	}{"tier_1": {"1", 1_000_000, 10_000_000_000}, "tier_2": {"2", 3_000_000, 100_000_000_000}, "tier_3": {"4", 5_000_000, 500_000_000_000}}
	i := 0
	for plan, w := range want {
		i++
		code, d, b := mkOffer(t, ts.URL, tok, "tier-name-"+string(rune('a'+i)), plan, nil)
		if code != 201 {
			t.Fatalf("%s: %d %s", plan, code, b)
		}
		if d.Plan != plan || d.Price.Amount != w.amount || d.Price.Asset != "USDC" || d.Price.Interval != "month" || d.Price.Unit != "name" ||
			d.Limits.BW != w.bw || d.Limits.MO != w.mo || d.Scope.Type != "hostname" || d.Status != "open" {
			t.Errorf("%s: %+v", plan, d)
		}
		if len(d.Methods) != 1 || d.Methods[0].Type != "development_crypto" || d.Methods[0].Network != "development" || !d.Methods[0].Simulated ||
			!strings.HasPrefix(d.Methods[0].PaymentRequest, "devpay:pay_") || d.Methods[0].Asset != "USDC" {
			t.Errorf("%s methods: %+v", plan, d.Methods)
		}
		exp, err := time.Parse(time.RFC3339, d.ExpiresAt)
		if err != nil || time.Until(exp) < 25*time.Minute || time.Until(exp) > 31*time.Minute {
			t.Errorf("%s expiry %v %v", plan, d.ExpiresAt, err)
		}
		if d.StatusURL != "/v1/offers/"+d.ID {
			t.Errorf("status_url %q", d.StatusURL)
		}
	}
}

func TestOfferValidationAndAuth(t *testing.T) {
	_, ts := newApp(t, devPayments)
	c := newClient(t, ts)
	tok, _, _ := c.Login(context.Background())
	for _, tc := range []struct{ name, plan string }{{"myname", "free"}, {"myname", "tier_9"}, {"www", "tier_1"}, {"a", "tier_1"}, {"bad_name", "tier_1"}, {"", "tier_1"}} {
		if code, _, b := mkOffer(t, ts.URL, tok, tc.name, tc.plan, nil); code != 400 {
			t.Errorf("%+v: %d %s", tc, code, b)
		}
	}
	if code, _, _ := mkOffer(t, ts.URL, "", "myname", "tier_1", nil); code != 401 {
		t.Fatalf("anonymous: %d", code)
	}
	resp, _ := raw(t, "POST", ts.URL+"/v1/offers", tok, map[string]any{"name": "myname", "plan": "tier_1", "price": "0"}, nil)
	if resp.StatusCode != 400 {
		t.Fatalf("client-supplied price must be rejected as an unknown field: %d", resp.StatusCode)
	}
}

func TestOfferCreationIdempotent(t *testing.T) {
	_, ts := newApp(t, devPayments)
	c := newClient(t, ts)
	tok, _, _ := c.Login(context.Background())
	_, a, _ := mkOffer(t, ts.URL, tok, "myname", "tier_2", map[string]string{"Idempotency-Key": "offer-key-0001"})
	code, b, _ := mkOffer(t, ts.URL, tok, "myname", "tier_2", map[string]string{"Idempotency-Key": "offer-key-0001"})
	if code != 201 || a.ID != b.ID || a.PaymentID != b.PaymentID {
		t.Fatalf("replay must return the same offer: %+v vs %+v", a, b)
	}
	// Same key, different request => conflict.
	if code, _, body := mkOffer(t, ts.URL, tok, "othername", "tier_2", map[string]string{"Idempotency-Key": "offer-key-0001"}); code != 409 || !strings.Contains(string(body), "idempotency_key_reused") {
		t.Fatalf("%d %s", code, body)
	}
	// Without a key an identical open offer is still reused.
	_, c1, _ := mkOffer(t, ts.URL, tok, "third-name", "tier_1", nil)
	_, c2, _ := mkOffer(t, ts.URL, tok, "Third-Name", "tier_1", nil)
	if c1.ID != c2.ID {
		t.Fatal("open offers for the same scope must not multiply")
	}
}

func TestOfferAndPaymentOwnership(t *testing.T) {
	_, ts := newApp(t, devPayments)
	owner, other := newClient(t, ts), newClient(t, ts)
	otok, _, _ := owner.Login(context.Background())
	xtok, _, _ := other.Login(context.Background())
	_, d, _ := mkOffer(t, ts.URL, otok, "myname", "tier_1", nil)
	for _, path := range []string{"/v1/offers/" + d.ID, "/v1/payments/" + d.PaymentID} {
		if resp, _ := raw(t, "GET", ts.URL+path, otok, nil, nil); resp.StatusCode != 200 {
			t.Errorf("owner %s: %d", path, resp.StatusCode)
		}
		if resp, _ := raw(t, "GET", ts.URL+path, xtok, nil, nil); resp.StatusCode != 404 {
			t.Errorf("other tenant %s: %d", path, resp.StatusCode)
		}
	}
	if resp, _ := raw(t, "POST", ts.URL+"/v1/payments/"+d.PaymentID+"/simulate-settlement", xtok, nil, nil); resp.StatusCode != 404 {
		t.Errorf("another tenant must not settle my payment: %d", resp.StatusCode)
	}
}

func TestSimulationFailsClosedWhenNotEnabled(t *testing.T) {
	a, ts := newApp(t, nil) // DevelopmentPayments = false
	c := newClient(t, ts)
	tok, _, _ := c.Login(context.Background())
	_, d, _ := mkOffer(t, ts.URL, tok, "myname", "tier_1", nil)
	resp, b := raw(t, "POST", ts.URL+"/v1/payments/"+d.PaymentID+"/simulate-settlement", tok, nil, nil)
	if resp.StatusCode != 404 {
		t.Fatalf("simulation reachable without the development gate: %d %s", resp.StatusCode, b)
	}
	_, pb := raw(t, "GET", ts.URL+"/v1/payments/"+d.PaymentID, tok, nil, nil)
	if !strings.Contains(string(pb), `"state":"AWAITING_PAYMENT"`) {
		t.Fatalf("state changed: %s", pb)
	}
	p, _ := a.Identity.Authenticate(context.Background(), tok)
	if es, _ := a.Entitlements.ListActive(context.Background(), p.ID, time.Now()); len(es) != 0 {
		t.Fatal("entitlement granted without settlement")
	}
}

func TestProductionCannotEnableSimulation(t *testing.T) {
	cfg := testConfig()
	cfg.AppEnv, cfg.DevelopmentPayments, cfg.SigningKeyFile = config.EnvProduction, true, "/nonexistent"
	cfg.EdgeServiceToken = strings.Repeat("s", 40)
	if _, err := app.New(cfg, app.Options{}); err == nil || !strings.Contains(err.Error(), "development_payments") {
		t.Fatalf("production + development payments must fail at startup: %v", err)
	}
}

func TestSimulatedSettlementGrantsOneEntitlementIdempotently(t *testing.T) {
	a, ts := newApp(t, devPayments)
	c := newClient(t, ts)
	ctx := context.Background()
	tok, _, _ := c.Login(ctx)
	p, _ := a.Identity.Authenticate(ctx, tok)
	_, d, _ := mkOffer(t, ts.URL, tok, "myproject", "tier_2", nil)

	var last string
	for i := 0; i < 4; i++ { // repeated delivery of the same settlement
		resp, b := raw(t, "POST", ts.URL+"/v1/payments/"+d.PaymentID+"/simulate-settlement", tok, nil, nil)
		if resp.StatusCode != 200 {
			t.Fatalf("#%d: %d %s", i, resp.StatusCode, b)
		}
		last = string(b)
	}
	var pv struct {
		State, Amount, Asset, Network, Provider string
		Simulated                               bool
	}
	json.Unmarshal([]byte(last), &pv)
	if pv.State != "ENTITLEMENT_GRANTED" || pv.Amount != "2" || pv.Asset != "USDC" || pv.Network != "development" || pv.Provider != "development" || !pv.Simulated {
		t.Fatalf("%s", last)
	}
	es, _ := a.Entitlements.ListActive(ctx, p.ID, time.Now())
	if len(es) != 1 || es[0].ScopeName != "myproject" || es[0].PlanID != "tier_2" {
		t.Fatalf("%+v", es)
	}
	_, ob := raw(t, "GET", ts.URL+"/v1/offers/"+d.ID, tok, nil, nil)
	if !strings.Contains(string(ob), `"status":"paid"`) {
		t.Fatalf("offer not paid: %s", ob)
	}
	// Audit trail records the settlement.
	found := false
	for _, ev := range a.Audit.Events() {
		if ev.Action == "payment.settle" && ev.Result == "ok" {
			found = true
		}
	}
	if !found {
		t.Fatal("settlement not audited")
	}
}

// The policy for a reserved name follows its entitlement exactly, and the edge
// sees limits only.
func TestReservedNamePolicyFollowsEntitlement(t *testing.T) {
	a, ts := newApp(t, devPayments)
	c := newClient(t, ts)
	ctx := context.Background()
	tok, _, _ := c.Login(ctx)
	p, _ := a.Identity.Authenticate(ctx, tok)
	svc := testConfig().EdgeServiceToken

	ep, err := a.Endpoints.CreateReserved(ctx, p.ID, "myproject") // as the reserve workflow would after payment
	if err != nil {
		t.Fatal(err)
	}
	get := func() pp.EndpointPolicy {
		_, b := raw(t, "GET", ts.URL+"/v1/endpoints/"+ep.ID+"/policy", svc, nil, nil)
		pol, err := pp.Decode(b)
		if err != nil {
			t.Fatalf("%v %s", err, b)
		}
		return pol
	}
	if got := get(); got.State != pp.StateExpired {
		t.Fatalf("a reserved name without an entitlement must resolve to expired, got %s", got.State)
	}
	_, d, _ := mkOffer(t, ts.URL, tok, "myproject", "tier_3", nil)
	before := get().PolicyVersion
	raw(t, "POST", ts.URL+"/v1/payments/"+d.PaymentID+"/simulate-settlement", tok, nil, nil)
	got := get()
	if got.State != pp.StateActive || got.Limits.BandwidthBytesPerSecond != 5_000_000 || got.Limits.BurstBytes != 10_000_000 ||
		got.Limits.MonthlyTransferBytes != 500_000_000_000 || got.PolicyVersion <= before {
		t.Fatalf("tier_3 policy: %+v", got)
	}
	if got.Hostname.Kind != "reserved" || got.Hostname.InactiveExpirySecond != nil {
		t.Fatalf("hostname: %+v", got.Hostname)
	}
}

// ADR 0011: an edge may issue a certificate for a reserved name as soon as it
// is paid (active), never for an unpaid reservation or a random name without
// a tunnel, and only the edge service may ask.
func TestHostnameStatusAllowsIssuanceOnlyForPaidReservedNames(t *testing.T) {
	a, ts := newApp(t, devPayments)
	c := newClient(t, ts)
	ctx := context.Background()
	tok, _, _ := c.Login(ctx)
	p, _ := a.Identity.Authenticate(ctx, tok)
	svc := testConfig().EdgeServiceToken
	status := func(label, token string) (int, pp.HostnameStatus) {
		resp, b := raw(t, "GET", ts.URL+"/v1/hostnames/"+label, token, nil, nil)
		var h pp.HostnameStatus
		_ = json.Unmarshal(b, &h)
		return resp.StatusCode, h
	}

	if _, err := a.Endpoints.CreateReserved(ctx, p.ID, "paidsoon"); err != nil {
		t.Fatal(err)
	}
	if code, h := status("paidsoon", svc); code != 200 || h.Kind != "reserved" || h.CertificateIssuable() {
		t.Fatalf("unpaid reservation: %d %+v", code, h)
	}
	_, d, _ := mkOffer(t, ts.URL, tok, "paidsoon", "tier_1", nil)
	raw(t, "POST", ts.URL+"/v1/payments/"+d.PaymentID+"/simulate-settlement", tok, nil, nil)
	if code, h := status("paidsoon", svc); code != 200 || !h.CertificateIssuable() || h.EndpointID == "" {
		t.Fatalf("paid reservation: %d %+v", code, h)
	}

	rnd, _ := c.CreateEndpoint(ctx, "")
	if code, h := status(rnd.Hostname, svc); code != 200 || h.Kind != "random" || h.CertificateIssuable() {
		t.Fatalf("random name: %d %+v", code, h)
	}
	if code, _ := status("nobody-has-this", svc); code != 404 {
		t.Fatalf("unknown label: %d", code)
	}
	for name, token := range map[string]string{"anonymous": "", "principal": tok, "junk": "junk"} {
		if code, _ := status("paidsoon", token); code != 401 {
			t.Errorf("%s: %d", name, code)
		}
	}
}
