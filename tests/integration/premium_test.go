package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/127ohoh1/core/client/api"
	"github.com/127ohoh1/core/client/cli"
	cid "github.com/127ohoh1/core/client/identity"
	"github.com/127ohoh1/core/controlplane/endpoint"
	"github.com/127ohoh1/core/internal/clock"
	"github.com/127ohoh1/core/internal/config"
	"github.com/127ohoh1/core/internal/testenv"
	pp "github.com/127ohoh1/core/protocol/policy"
)

func withDevPayments(c *config.ControlPlane) { c.DevelopmentPayments = true }

// Scenario 8: 402 for a reserved name, simulate settlement, entitlement grant,
// idempotent retry, success.
func TestReservedNameFlow402ToSuccess(t *testing.T) {
	env := testenv.New(t, testenv.Options{CP: withDevPayments})
	id := env.NewIdentity()
	c := env.API(id)

	// Raw request: check the documented 402 wire contract.
	tok, _, _ := c.Login(bg)
	post := func() (*http.Response, []byte) {
		req, _ := http.NewRequest("POST", env.CPURL()+"/v1/endpoints/reserve", strings.NewReader(`{"name":"myproject","plan":"tier_2"}`))
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Idempotency-Key", "reserve-key-0001")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, b
	}
	resp, body := post()
	if resp.StatusCode != 402 || resp.Header.Get("Cache-Control") != "no-store" || !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
		t.Fatalf("%d %v %s", resp.StatusCode, resp.Header, body)
	}
	var doc struct {
		Error struct {
			Code      string `json:"code"`
			Message   string `json:"message"`
			RequestID string `json:"request_id"`
		} `json:"error"`
		Resource struct{ Type, Name string } `json:"resource"`
		Offers   []api.Offer                 `json:"offers"`
	}
	if err := json.Unmarshal(body, &doc); err != nil || doc.Error.Code != "payment_required" || !strings.HasPrefix(doc.Error.RequestID, "req_") || doc.Error.Message == "" || doc.Resource.Type != "hostname" || doc.Resource.Name != "myproject" || len(doc.Offers) != 1 {
		t.Fatalf("%v %s", err, body)
	}
	o := doc.Offers[0]
	if o.Plan != "tier_2" || o.Price.Amount != "2" || o.Price.Asset != "USDC" || o.PaymentMethods[0].Type != "development_crypto" || !strings.HasPrefix(o.PaymentMethods[0].PaymentRequest, "devpay:") {
		t.Fatalf("%+v", o)
	}
	// Retrying while unpaid returns the *same* offer, not a new one.
	_, body2 := post()
	var doc2 struct{ Offers []api.Offer }
	json.Unmarshal(body2, &doc2)
	if doc2.Offers[0].ID != o.ID || doc2.Offers[0].PaymentID != o.PaymentID {
		t.Fatal("unpaid retry must return the same offer")
	}
	if es, _ := c.ListEndpoints(bg); len(es) != 0 {
		t.Fatal("an endpoint exists before payment")
	}

	// Simulated settlement, delivered several times.
	for i := 0; i < 3; i++ {
		p, err := c.SimulateSettlement(bg, o.PaymentID)
		if err != nil || p.State != "ENTITLEMENT_GRANTED" || !p.Simulated {
			t.Fatalf("#%d: %+v %v", i, p, err)
		}
	}
	// The original request, same idempotency key, now yields the resource.
	resp, body = post()
	if resp.StatusCode != 201 {
		t.Fatalf("retry after settlement: %d %s", resp.StatusCode, body)
	}
	var ep api.Endpoint
	json.Unmarshal(body, &ep)
	if ep.Hostname != "myproject" || ep.Kind != "reserved" || ep.State != "ACTIVE" || ep.Plan != "tier_2" {
		t.Fatalf("%+v", ep)
	}
	// And once more: idempotent replay, no second endpoint.
	resp, _ = post()
	if resp.StatusCode != 201 || resp.Header.Get("Idempotent-Replayed") != "true" {
		t.Fatalf("replay: %d %v", resp.StatusCode, resp.Header)
	}
	if es, _ := c.ListEndpoints(bg); len(es) != 1 {
		t.Fatalf("%d endpoints", len(es))
	}
	// Exactly one entitlement was granted for three settlement deliveries.
	pr, _ := env.CP.Identity.Authenticate(bg, tok)
	if es, _ := env.CP.Entitlements.ListActive(bg, pr.ID, time.Now()); len(es) != 1 {
		t.Fatalf("%d entitlements", len(es))
	}
}

// Scenario 9: each tier resolves to exactly the specified limits, all the way
// to the edge's policy cache (which holds no commercial data).
func TestTiersResolveExactLimitsAtTheEdge(t *testing.T) {
	want := map[string][3]int64{
		"tier_1": {1_000_000, 2_000_000, 10_000_000_000},
		"tier_2": {3_000_000, 6_000_000, 100_000_000_000},
		"tier_3": {5_000_000, 10_000_000, 500_000_000_000},
	}
	// The default test catalog is scaled up; exactness needs the canonical one.
	env2 := testenv.New(t, testenv.Options{CP: withDevPayments, Catalog: testenv.Canonical()})
	id := env2.NewIdentity()
	c := env2.API(id)
	origin := env2.Origin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "premium") }))
	for plan, w := range want {
		name := "name-" + strings.ReplaceAll(plan, "_", "-")
		_, pr, err := c.Reserve(bg, name, plan, "")
		if err != nil || pr == nil {
			t.Fatalf("%s: %v %v", plan, err, pr)
		}
		if _, err := c.SimulateSettlement(bg, pr.Offers[0].PaymentID); err != nil {
			t.Fatal(err)
		}
		ep, pr2, err := c.Reserve(bg, name, plan, "")
		if err != nil || pr2 != nil {
			t.Fatalf("%s: %v", plan, err)
		}
		x := env2.Expose(id, origin.URL, ep.ID)
		if _, body := env2.Get(x.Endpoint.Hostname, "/"); body != "premium" {
			t.Fatalf("%s: %q", plan, body)
		}
		ent, err := env2.Edge.PolicyCache.Get(bg, ep.ID)
		if err != nil {
			t.Fatal(err)
		}
		l := ent.Policy.Limits
		if ent.Policy.State != pp.StateActive || l.BandwidthBytesPerSecond != w[0] || l.BurstBytes != w[1] || l.MonthlyTransferBytes != w[2] {
			t.Errorf("%s: edge holds %+v", plan, l)
		}
		raw, _ := json.Marshal(ent.Policy)
		for _, bad := range []string{"tier", "usdc", "price", "payment", "plan"} {
			if strings.Contains(strings.ToLower(string(raw)), bad) {
				t.Errorf("%s: edge policy leaks %q: %s", plan, bad, raw)
			}
		}
		x.Conn.Session.Close()
	}
}

func TestSecondPrincipalCannotBuyOrReserveAnEntitledName(t *testing.T) {
	env := testenv.New(t, testenv.Options{CP: withDevPayments})
	a, b := env.API(env.NewIdentity()), env.API(env.NewIdentity())
	_, pr, _ := a.Reserve(bg, "contested", "tier_1", "")
	a.SimulateSettlement(bg, pr.Offers[0].PaymentID)
	if _, _, err := a.Reserve(bg, "contested", "tier_1", ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.Reserve(bg, "contested", "tier_1", ""); !api.IsCode(err, "conflict") {
		t.Fatalf("second principal must get 409, not an offer: %v", err)
	}
	// An upgrade of an already-entitled name is a product feature, not part of the reference.
	if _, _, err := a.Reserve(bg, "contested", "tier_3", ""); !api.IsCode(err, "conflict") {
		t.Fatalf("upgrade attempt: %v", err)
	}
}

// Entitlement expiry drives the lifecycle: policy -> expired, endpoint EXPIRED,
// later RELEASED; the name then becomes purchasable again after the tombstone.
func TestEntitlementExpiryAndRelease(t *testing.T) {
	clk := clock.NewFake(time.Now())
	env := testenv.New(t, testenv.Options{Clock: clk, NoEdge: true, CP: func(c *config.ControlPlane) {
		c.DevelopmentPayments = true
		c.ReaperInterval = config.Duration(time.Minute)
		c.ExpiredReservedRelease = config.Duration(72 * time.Hour)
		c.NameTombstone = config.Duration(time.Hour)
	}})
	id := env.NewIdentity()
	c := env.API(id)
	_, pr, _ := c.Reserve(bg, "myproject", "tier_1", "")
	c.SimulateSettlement(bg, pr.Offers[0].PaymentID)
	ep, _, err := c.Reserve(bg, "myproject", "tier_1", "")
	if err != nil {
		t.Fatal(err)
	}
	state := func() (endpoint.State, pp.State) {
		e, _ := env.CP.Endpoints.GetByID(bg, ep.ID)
		p, _ := env.CP.Publisher.Current(bg, ep.ID)
		return e.State, p.State
	}
	waitState := func(es endpoint.State, ps pp.State) {
		t.Helper()
		eventuallyCtx(t, fmt.Sprintf("endpoint %s / policy %s", es, ps), func() bool {
			e, p := state()
			return e == es && p == ps
		})
	}
	waitState(endpoint.StateActive, pp.StateActive)

	// One tick before the end of the term: still active.
	clk.Advance(time.Until(clk.Now().AddDate(0, 1, 0)) - 2*time.Minute)
	time.Sleep(50 * time.Millisecond)
	if e, p := state(); e != endpoint.StateActive || p != pp.StateActive {
		t.Fatalf("expired early: %s %s", e, p)
	}
	clk.Advance(3 * time.Minute) // past valid_until
	waitState(endpoint.StateExpired, pp.StateExpired)
	if _, err := env.API(id).TunnelCredentials(bg, ep.ID); err == nil {
		t.Fatal("credential issued for an expired reserved name")
	}
	// The name is still held during the recovery window: nobody else can take it.
	other := env.API(env.NewIdentity())
	if _, _, err := other.Reserve(bg, "myproject", "tier_1", ""); err == nil {
		t.Fatal("expired-but-unreleased name was offered to someone else")
	}

	clk.Advance(73 * time.Hour)
	waitState(endpoint.StateReleased, pp.StateReleased)
	// Tombstone: no offer may be issued to another principal right after release
	// (they could pay and then be unable to obtain the name).
	if _, pr, err := other.Reserve(bg, "myproject", "tier_1", ""); err == nil || pr != nil {
		t.Fatalf("an offer was issued for a tombstoned name: %v %v", err, pr)
	}
	clk.Advance(2 * time.Hour)
	if _, pr, err := env.API(env.NewIdentity()).Reserve(bg, "myproject", "tier_1", ""); err != nil || pr == nil {
		t.Fatalf("after the tombstone the name is purchasable again: %v", err)
	}
}

// CLI: consent is never implicit.
func TestCLIPremiumFlowRequiresExplicitConsent(t *testing.T) {
	env := testenv.New(t, testenv.Options{CP: withDevPayments, Catalog: testenv.Canonical()})
	origin := env.Origin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "paid content") }))
	dir := t.TempDir()
	ca := dir + "/ca.pem"
	os.WriteFile(ca, env.Edge.TLS.CAPEM, 0o600)
	idp := dir + "/id"
	base := []string{"expose", origin.URL, "--name", "myproject", "--plan", "tier_2", "--api", env.CPURL(), "--identity", idp, "--edge", env.Edge.Addrs().Tunnel, "--ca", ca}

	run := func(ctx context.Context, interactive bool, stdin string, extra ...string) (int, string, string) {
		var out, errb safeBuf
		code := cli.Run(ctx, append(append([]string{}, base...), extra...), cli.Env{Stdout: &out, Stderr: &errb, Stdin: strings.NewReader(stdin),
			Getenv: func(string) string { return "" }, Interactive: interactive})
		return code, out.String(), errb.String()
	}

	// 1. Non-interactive without --yes: prints the offer, exits 4, pays nothing.
	code, out, _ := run(bg, false, "")
	if code != cli.ExitPayment {
		t.Fatalf("exit %d\n%s", code, out)
	}
	for _, want := range []string{"Premium feature: reserved hostname", "Price: 2 USDC/month/name", "Bandwidth: 3 MB/s/name", "Monthly transfer: 100 GB/name", "Payment required: devpay:", "SIMULATED"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	// 2. Interactive decline.
	if code, _, _ := run(bg, true, "n\n"); code != cli.ExitPayment {
		t.Fatalf("declined prompt: exit %d", code)
	}
	if es, _ := env.API(mustLoad(t, idp)).ListEndpoints(bg); len(es) != 0 {
		t.Fatal("an endpoint was created without consent")
	}
	// 3. --yes without --simulate-settlement and nobody paying: times out with the payment code.
	if code, _, e := run(bg, false, "", "--yes", "--wait", "1500ms"); code != cli.ExitPayment {
		t.Fatalf("unpaid wait: exit %d %s", code, e)
	}
	// 4. --yes --simulate-settlement: full flow, then the tunnel serves traffic.
	ctx, cancel := context.WithCancel(bg)
	var out4, err4 safeBuf
	done := make(chan int, 1)
	go func() {
		done <- cli.Run(ctx, append(append([]string{}, base...), "--yes", "--simulate-settlement", "--json"),
			cli.Env{Stdout: &out4, Stderr: &err4, Stdin: strings.NewReader(""), Getenv: func(string) string { return "" }})
	}()
	eventuallyCtx(t, "premium expose", func() bool { return strings.Contains(out4.String(), `"hostname"`) })
	if s := out4.String(); !strings.Contains(s, "Payment confirmed.") || !strings.Contains(s, "simulated settlement") {
		t.Fatalf("flow output:\n%s", s)
	}
	env.WaitRegistered("myproject")
	if resp, body := env.Get("myproject", "/"); resp.StatusCode != 200 || body != "paid content" {
		t.Fatalf("%d %q", resp.StatusCode, body)
	}
	cancel()
	if code := <-done; code != cli.ExitOK {
		t.Fatalf("exit %d", code)
	}
	// 5. Running it again reuses the entitlement: no second payment, no prompt.
	ctx2, cancel2 := context.WithCancel(bg)
	var out5 safeBuf
	done2 := make(chan int, 1)
	go func() {
		done2 <- cli.Run(ctx2, append(append([]string{}, base...), "--json"), cli.Env{Stdout: &out5, Stderr: io.Discard, Stdin: strings.NewReader(""), Getenv: func(string) string { return "" }})
	}()
	eventuallyCtx(t, "second run", func() bool { return strings.Contains(out5.String(), `"hostname"`) })
	if strings.Contains(out5.String(), "Payment required") {
		t.Fatal("asked to pay twice for the same term")
	}
	cancel2()
	<-done2
}

func TestPlansListCommandShowsExactTable(t *testing.T) {
	env := testenv.New(t, testenv.Options{NoEdge: true, Catalog: testenv.Canonical()})
	var out bytes.Buffer
	code := cli.Run(bg, []string{"plans", "list", "--api", env.CPURL(), "--identity", t.TempDir() + "/id"},
		cli.Env{Stdout: &out, Stderr: io.Discard, Stdin: strings.NewReader(""), Getenv: func(string) string { return "" }})
	if code != 0 {
		t.Fatal(code)
	}
	for _, want := range []string{"free", "Free", "100 kB/s", "500 MB", "tier_1", "1 USDC/month/name", "1 MB/s", "10 GB", "tier_2", "2 USDC/month/name", "3 MB/s", "100 GB", "tier_3", "4 USDC/month/name", "5 MB/s", "500 GB"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in\n%s", want, out.String())
		}
	}
}

func mustLoad(t *testing.T, path string) cid.Identity {
	t.Helper()
	id, err := cid.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
