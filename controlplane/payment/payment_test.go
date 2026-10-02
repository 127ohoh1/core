package payment_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/127ohoh1/core/controlplane/endpoint"
	"github.com/127ohoh1/core/controlplane/entitlement"
	"github.com/127ohoh1/core/controlplane/offer"
	"github.com/127ohoh1/core/controlplane/payment"
	"github.com/127ohoh1/core/controlplane/policy"
	"github.com/127ohoh1/core/internal/apperr"
	"github.com/127ohoh1/core/internal/clock"
	"github.com/127ohoh1/core/internal/config"
	"github.com/127ohoh1/core/internal/ids"
)

var bg = context.Background()

func TestAmountParseFormat(t *testing.T) {
	ok := map[string]int64{"0": 0, "1": 1_000_000, "2": 2_000_000, "4": 4_000_000, "0.5": 500_000, "1.25": 1_250_000, "0.000001": 1, "10": 10_000_000}
	for s, want := range ok {
		got, err := payment.ParseAmount(s, 6)
		if err != nil || got != want {
			t.Errorf("%q: %d %v", s, got, err)
		}
		if back := payment.FormatAmount(want, 6); back != s {
			t.Errorf("format %d = %q want %q", want, back, s)
		}
	}
	// Overflow must be an error, never a negative or wrapped amount (regression: fuzz-found).
	for _, s := range []string{"9270000000000", "9223372036854", "9223372036855", "99999999999999999", "18446744073709551616"} {
		n, err := payment.ParseAmount(s, 6)
		if err == nil && n < 0 {
			t.Errorf("%q parsed to a negative amount %d", s, n)
		}
	}
	if n, err := payment.ParseAmount("9223372036854", 6); err != nil || n != 9223372036854000000 {
		t.Errorf("the largest whole value that fits must parse exactly: %d %v", n, err)
	}
	for _, s := range []string{"", ".5", "1.", "-1", "+1", "1e3", "1,5", " 1", "1 ", "0.0000001", "abc", "1.2.3", "99999999999999999999999"} {
		if _, err := payment.ParseAmount(s, 6); err == nil {
			t.Errorf("accepted %q", s)
		}
	}
}

func FuzzAmountRoundTrip(f *testing.F) {
	for _, s := range []string{"1", "0.5", "", "1.2.3", "9999999999"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		n, err := payment.ParseAmount(s, 6)
		if err != nil {
			return
		}
		if n < 0 {
			t.Fatalf("negative %d from %q", n, s)
		}
		back, err := payment.ParseAmount(payment.FormatAmount(n, 6), 6)
		if err != nil || back != n {
			t.Fatalf("round trip %q -> %d -> %d (%v)", s, n, back, err)
		}
	})
}

func TestStateMachineComplete(t *testing.T) {
	S := []payment.State{payment.StateCreated, payment.StateAwaitingPayment, payment.StateSeen, payment.StateConfirming, payment.StateSettled,
		payment.StateEntitlementGranted, payment.StateExpired, payment.StateFailed}
	valid := map[[2]payment.State]bool{
		{payment.StateCreated, payment.StateAwaitingPayment}: true, {payment.StateCreated, payment.StateExpired}: true, {payment.StateCreated, payment.StateFailed}: true,
		{payment.StateAwaitingPayment, payment.StateSeen}: true, {payment.StateAwaitingPayment, payment.StateExpired}: true, {payment.StateAwaitingPayment, payment.StateFailed}: true,
		{payment.StateSeen, payment.StateConfirming}: true, {payment.StateSeen, payment.StateExpired}: true, {payment.StateSeen, payment.StateFailed}: true,
		{payment.StateConfirming, payment.StateSettled}: true, {payment.StateConfirming, payment.StateFailed}: true,
		{payment.StateSettled, payment.StateEntitlementGranted}: true,
	}
	for _, a := range S {
		for _, b := range S {
			if got := payment.CanTransition(a, b); got != valid[[2]payment.State{a, b}] {
				t.Errorf("%s -> %s: %v", a, b, got)
			}
		}
	}
	for _, s := range []payment.State{payment.StateEntitlementGranted, payment.StateExpired, payment.StateFailed} {
		if !s.Terminal() {
			t.Errorf("%s must be terminal", s)
		}
	}
}

func TestMockVerifier(t *testing.T) {
	if _, err := payment.NewMockVerifier(config.EnvProduction); !errors.Is(err, payment.ErrMockInProduction) {
		t.Fatalf("the mock verifier must not exist in production: %v", err)
	}
	v, err := payment.NewMockVerifier(config.EnvDevelopment)
	if err != nil {
		t.Fatal(err)
	}
	res, err := v.Verify(bg, payment.PaymentProof{Provider: payment.DevProvider, Raw: payment.MockProof("pay_1", 2_000_000, "USDC")})
	if err != nil || !res.Settled || res.PaymentID != "pay_1" || res.Amount.Atomic != 2_000_000 || res.Network != "development" {
		t.Fatalf("%+v %v", res, err)
	}
	for _, raw := range []string{"", "0xdeadbeef", "devpay-proof:v0-NOT-FOR-PRODUCTION:", "devpay-proof:v0-NOT-FOR-PRODUCTION:a:b", "devpay-proof:v0-NOT-FOR-PRODUCTION:p:-5:USDC", "devpay-proof:v1:p:5:USDC"} {
		if _, err := v.Verify(bg, payment.PaymentProof{Provider: payment.DevProvider, Raw: raw}); err == nil {
			t.Errorf("accepted %q", raw)
		}
	}
	if _, err := v.Verify(bg, payment.PaymentProof{Provider: "stripe", Raw: payment.MockProof("p", 1, "USDC")}); err == nil {
		t.Error("wrong provider accepted")
	}
}

type fx struct {
	clk  *clock.Fake
	eps  *endpoint.Service
	cat  *policy.Catalog
	offs *offer.Service
	ents *entitlement.Service
	pay  *payment.Service
	// failGrants makes the first n grants fail (crash simulation)
	mu         sync.Mutex
	failGrants int
}

type flakyGranter struct{ f *fx }

func (g flakyGranter) GrantFromSettlement(ctx context.Context, gr payment.Grant) error {
	g.f.mu.Lock()
	if g.f.failGrants > 0 {
		g.f.failGrants--
		g.f.mu.Unlock()
		return apperr.ErrUnavailable
	}
	g.f.mu.Unlock()
	return entitlement.Granter{S: g.f.ents}.GrantFromSettlement(ctx, gr)
}

func newFx() *fx {
	f := &fx{clk: clock.NewFake(time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)), cat: policy.DefaultCatalog()}
	gen := ids.New(f.clk)
	f.eps = endpoint.NewService(endpoint.Config{MaxRandomPerPrincipal: 3, Tombstone: time.Hour, FreeInactivity: 24 * time.Hour},
		endpoint.NewInMemory(), endpoint.NewRandomAllocator(nil), nil, f.clk, gen)
	f.offs = offer.NewService(offer.NewInMemory(), f.cat, f.eps, f.clk, gen, 30*time.Minute)
	f.ents = entitlement.NewService(f.clk, gen)
	f.pay = payment.NewService(payment.NewInMemory(), f.offs, flakyGranter{f}, f.clk, gen, nil)
	f.offs.Available = func(_ context.Context, pr, name string) error {
		if f.ents.HeldByOther(pr, name, f.clk.Now()) {
			return apperr.ErrConflict.WithDetails(map[string]any{"reason": "hostname_unavailable"})
		}
		return nil
	}
	return f
}

func (f *fx) settlement(p payment.Payment, event string) payment.Settlement {
	return payment.Settlement{EventID: event, PaymentID: p.ID, Amount: p.Amount, Network: p.Network, At: f.clk.Now()}
}

func (f *fx) offerAndPay(t *testing.T, principal, name, plan string) (offer.Offer, payment.Payment) {
	t.Helper()
	o, err := f.offs.CreateOrReuse(bg, principal, name, plan)
	if err != nil {
		t.Fatal(err)
	}
	p, err := f.pay.CreateForOffer(bg, o)
	if err != nil {
		t.Fatal(err)
	}
	return o, p
}

func TestOfferTermsSnapshotIsExactAndImmutable(t *testing.T) {
	f := newFx()
	want := map[string]struct {
		amount string
		bw, mo int64
	}{"tier_1": {"1", 1_000_000, 10_000_000_000}, "tier_2": {"2", 3_000_000, 100_000_000_000}, "tier_3": {"4", 5_000_000, 500_000_000_000}}
	i := 0
	for plan, w := range want {
		i++
		o, err := f.offs.CreateOrReuse(bg, "pr_1", "name-"+string(rune('a'+i)), plan)
		if err != nil {
			t.Fatal(err)
		}
		if o.Terms.Amount != w.amount || o.Terms.Asset != "USDC" || o.Terms.Interval != "month" || o.Terms.Unit != "name" ||
			o.Terms.BandwidthBytesPerSecond != w.bw || o.Terms.MonthlyTransferBytes != w.mo {
			t.Errorf("%s: %+v", plan, o.Terms)
		}
	}
	// The stored offer is a value snapshot: re-reading it always returns the
	// terms it was issued with.
	o, _ := f.offs.CreateOrReuse(bg, "pr_1", "snapshot-name", "tier_1")
	got, _ := f.offs.GetByID(bg, o.ID)
	if got.Terms != o.Terms || got.Terms.Amount != "1" || got.Terms.PlanVersion != 1 {
		t.Fatal("offer terms changed after issue")
	}
}

func TestOfferRules(t *testing.T) {
	f := newFx()
	if _, err := f.offs.CreateOrReuse(bg, "pr_1", "myname", "free"); !errors.Is(err, apperr.ErrInvalidRequest) {
		t.Fatalf("free is not purchasable: %v", err)
	}
	if _, err := f.offs.CreateOrReuse(bg, "pr_1", "myname", "tier_9"); !errors.Is(err, apperr.ErrInvalidRequest) {
		t.Fatalf("unknown plan: %v", err)
	}
	if _, err := f.offs.CreateOrReuse(bg, "pr_1", "www", "tier_1"); !errors.Is(err, apperr.ErrInvalidRequest) {
		t.Fatalf("reserved label: %v", err)
	}
	a, _ := f.offs.CreateOrReuse(bg, "pr_1", "MyName", "tier_1")
	b, _ := f.offs.CreateOrReuse(bg, "pr_1", "myname", "tier_1")
	if a.ID != b.ID || a.ScopeName != "myname" {
		t.Fatal("an open offer for the same scope must be reused (idempotent)")
	}
	c, _ := f.offs.CreateOrReuse(bg, "pr_1", "myname", "tier_2")
	d, _ := f.offs.CreateOrReuse(bg, "pr_2", "myname", "tier_1")
	if c.ID == a.ID || d.ID == a.ID {
		t.Fatal("offers are scoped per plan and principal")
	}
	// Taken by another principal's endpoint: no offer.
	f.eps.CreateReserved(bg, "pr_9", "taken-name")
	if _, err := f.offs.CreateOrReuse(bg, "pr_1", "taken-name", "tier_1"); !errors.Is(err, apperr.ErrConflict) {
		t.Fatalf("unavailable name got an offer: %v", err)
	}
	// Lazily expired.
	f.clk.Advance(31 * time.Minute)
	got, _ := f.offs.GetByID(bg, a.ID)
	if got.State != offer.StateExpired {
		t.Fatalf("state %s", got.State)
	}
	e, _ := f.offs.CreateOrReuse(bg, "pr_1", "myname", "tier_1")
	if e.ID == a.ID {
		t.Fatal("an expired offer must not be reused")
	}
}

func TestSettlementGrantsExactlyOneScopedEntitlement(t *testing.T) {
	f := newFx()
	o, p := f.offerAndPay(t, "pr_1", "myproject", "tier_2")
	if p.State != payment.StateAwaitingPayment || p.Amount.Atomic != 2_000_000 || p.Amount.Asset != "USDC" || p.Network != "development" {
		t.Fatalf("%+v", p)
	}
	got, err := f.pay.ProcessSettlement(bg, f.settlement(p, "evt-1"))
	if err != nil || got.State != payment.StateEntitlementGranted {
		t.Fatalf("%+v %v", got, err)
	}
	es, _ := f.ents.ListActive(bg, "pr_1", f.clk.Now())
	if len(es) != 1 {
		t.Fatalf("%d entitlements", len(es))
	}
	e := es[0]
	if e.ScopeName != "myproject" || e.PlanID != "tier_2" || e.PrincipalID != "pr_1" || e.SettlementID != p.ID ||
		!e.ValidUntil.Equal(f.clk.Now().AddDate(0, 1, 0)) || e.Terms != o.Terms {
		t.Fatalf("%+v", e)
	}
	if id, ok, _ := f.ents.ActivePlan(bg, "pr_2", "myproject", f.clk.Now()); ok {
		t.Fatalf("entitlement leaked to another principal (%s)", id)
	}
	if _, ok, _ := f.ents.ActivePlan(bg, "pr_1", "other-name", f.clk.Now()); ok {
		t.Fatal("entitlement leaked to another name")
	}
	if got, _ := f.offs.GetByID(bg, o.ID); got.State != offer.StatePaid {
		t.Fatal("offer not marked paid")
	}
}

func TestDuplicateSettlementDeliveryGrantsOnce(t *testing.T) {
	f := newFx()
	_, p := f.offerAndPay(t, "pr_1", "myproject", "tier_1")
	for i, ev := range []string{"evt-1", "evt-1", "evt-2", "evt-1"} { // same event and a different event id for the same payment
		got, err := f.pay.ProcessSettlement(bg, f.settlement(p, ev))
		if err != nil || got.State != payment.StateEntitlementGranted {
			t.Fatalf("delivery %d: %+v %v", i, got, err)
		}
	}
	es, _ := f.ents.ListActive(bg, "pr_1", f.clk.Now())
	if len(es) != 1 {
		t.Fatalf("%d entitlements after duplicate deliveries", len(es))
	}
}

func TestConcurrentDuplicateSettlementsGrantOnce(t *testing.T) {
	f := newFx()
	_, p := f.offerAndPay(t, "pr_1", "myproject", "tier_1")
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); f.pay.ProcessSettlement(bg, f.settlement(p, "evt-1")) }()
	}
	wg.Wait()
	es, _ := f.ents.ListActive(bg, "pr_1", f.clk.Now())
	if len(es) != 1 {
		t.Fatalf("%d entitlements", len(es))
	}
}

// A failure between SETTLED and the grant must be completed by redelivery,
// never lost and never doubled.
func TestRedeliveryCompletesPartialSettlement(t *testing.T) {
	f := newFx()
	f.failGrants = 1
	_, p := f.offerAndPay(t, "pr_1", "myproject", "tier_1")
	if _, err := f.pay.ProcessSettlement(bg, f.settlement(p, "evt-1")); err == nil {
		t.Fatal("expected the injected failure")
	}
	if es, _ := f.ents.ListActive(bg, "pr_1", f.clk.Now()); len(es) != 0 {
		t.Fatal("entitlement granted despite failure")
	}
	stored, _ := f.pay.Get(bg, "pr_1", p.ID)
	if stored.State != payment.StateSettled {
		t.Fatalf("money was received: state must remain SETTLED, got %s", stored.State)
	}
	got, err := f.pay.ProcessSettlement(bg, f.settlement(p, "evt-1"))
	if err != nil || got.State != payment.StateEntitlementGranted {
		t.Fatalf("%+v %v", got, err)
	}
	if es, _ := f.ents.ListActive(bg, "pr_1", f.clk.Now()); len(es) != 1 {
		t.Fatalf("%d entitlements", len(es))
	}
}

func TestSettlementWithWrongTermsNeverSettles(t *testing.T) {
	cases := map[string]func(*payment.Settlement){
		"underpaid":     func(s *payment.Settlement) { s.Amount.Atomic-- },
		"overpaid":      func(s *payment.Settlement) { s.Amount.Atomic++ },
		"wrong asset":   func(s *payment.Settlement) { s.Amount.Asset = "USDT" },
		"wrong network": func(s *payment.Settlement) { s.Network = "mainnet" },
	}
	for name, mut := range cases {
		f := newFx()
		_, p := f.offerAndPay(t, "pr_1", "myproject", "tier_1")
		st := f.settlement(p, "evt-1")
		mut(&st)
		if _, err := f.pay.ProcessSettlement(bg, st); !errors.Is(err, apperr.ErrConflict) {
			t.Errorf("%s: %v", name, err)
		}
		if es, _ := f.ents.ListActive(bg, "pr_1", f.clk.Now()); len(es) != 0 {
			t.Errorf("%s: entitlement granted", name)
		}
		got, _ := f.pay.Get(bg, "pr_1", p.ID)
		if got.State != payment.StateFailed || got.FailureReason != "settlement_mismatch" {
			t.Errorf("%s: %+v", name, got)
		}
		// A FAILED payment can never be resurrected by a later, correct event.
		if _, err := f.pay.ProcessSettlement(bg, f.settlement(p, "evt-2")); err == nil {
			t.Errorf("%s: failed payment settled later", name)
		}
	}
}

func TestSettlementAfterOfferExpiryDoesNotGrant(t *testing.T) {
	f := newFx()
	_, p := f.offerAndPay(t, "pr_1", "myproject", "tier_1")
	f.clk.Advance(31 * time.Minute)
	if _, err := f.pay.ProcessSettlement(bg, f.settlement(p, "evt-1")); !errors.Is(err, apperr.ErrConflict) {
		t.Fatalf("%v", err)
	}
	got, _ := f.pay.Get(bg, "pr_1", p.ID)
	if got.State != payment.StateExpired || got.FailureReason != "offer_expired" {
		t.Fatalf("%+v", got)
	}
	if es, _ := f.ents.ListActive(bg, "pr_1", f.clk.Now()); len(es) != 0 {
		t.Fatal("granted after expiry")
	}
}

func TestEventIdCannotBeReusedAcrossPayments(t *testing.T) {
	f := newFx()
	_, p1 := f.offerAndPay(t, "pr_1", "name-one", "tier_1")
	_, p2 := f.offerAndPay(t, "pr_1", "name-two", "tier_1")
	if _, err := f.pay.ProcessSettlement(bg, f.settlement(p1, "evt-shared")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pay.ProcessSettlement(bg, f.settlement(p2, "evt-shared")); !errors.Is(err, apperr.ErrConflict) {
		t.Fatalf("a settlement event id replayed against another payment was accepted: %v", err)
	}
	if es, _ := f.ents.ListActive(bg, "pr_1", f.clk.Now()); len(es) != 1 {
		t.Fatalf("%d entitlements", len(es))
	}
}

func TestPaymentsAreOwnerScoped(t *testing.T) {
	f := newFx()
	_, p := f.offerAndPay(t, "pr_1", "myproject", "tier_1")
	if _, err := f.pay.Get(bg, "pr_2", p.ID); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("%v", err)
	}
	if _, err := f.offs.Get(bg, "pr_2", p.OfferID); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("%v", err)
	}
}

// Two principals cannot end up holding the same name.
func TestSecondPayerForTheSameNameIsAnException(t *testing.T) {
	f := newFx()
	_, p1 := f.offerAndPay(t, "pr_1", "contested", "tier_1")
	_, p2 := f.offerAndPay(t, "pr_2", "contested", "tier_1") // both offers were issued before either paid
	if _, err := f.pay.ProcessSettlement(bg, f.settlement(p1, "evt-1")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pay.ProcessSettlement(bg, f.settlement(p2, "evt-2")); !errors.Is(err, apperr.ErrConflict) {
		t.Fatalf("second payer got the name: %v", err)
	}
	if _, ok, _ := f.ents.ActivePlan(bg, "pr_2", "contested", f.clk.Now()); ok {
		t.Fatal("double entitlement")
	}
	got, _ := f.pay.Get(bg, "pr_2", p2.ID)
	if got.State != payment.StateSettled { // money received, needs manual resolution (private product)
		t.Fatalf("state %s", got.State)
	}
	// After the first holder's term ends, a new offer is possible again.
	f.clk.Advance(32 * 24 * time.Hour)
	f.ents.Sweep(bg, f.clk.Now())
	if _, err := f.offs.CreateOrReuse(bg, "pr_2", "contested", "tier_1"); err != nil {
		t.Fatalf("name should be purchasable after expiry: %v", err)
	}
}

func TestEntitlementExpiryBoundary(t *testing.T) {
	f := newFx()
	_, p := f.offerAndPay(t, "pr_1", "myproject", "tier_3")
	f.pay.ProcessSettlement(bg, f.settlement(p, "evt-1"))
	end := f.clk.Now().AddDate(0, 1, 0)
	f.clk.Advance(end.Sub(f.clk.Now()) - time.Nanosecond)
	if _, ok, _ := f.ents.ActivePlan(bg, "pr_1", "myproject", f.clk.Now()); !ok {
		t.Fatal("expired one tick early")
	}
	f.clk.Advance(time.Nanosecond)
	if _, ok, _ := f.ents.ActivePlan(bg, "pr_1", "myproject", f.clk.Now()); ok {
		t.Fatal("still active at valid_until")
	}
	var swept []string
	f.ents.OnChange = func(_ context.Context, n string) { swept = append(swept, n) }
	if n := f.ents.Sweep(bg, f.clk.Now()); len(n) != 1 || len(swept) != 1 {
		t.Fatalf("%v %v", n, swept)
	}
	if n := f.ents.Sweep(bg, f.clk.Now()); len(n) != 0 {
		t.Fatal("sweep must be idempotent")
	}
}

func TestExpireStaleMovesOnlyUnsettledPayments(t *testing.T) {
	f := newFx()
	_, unpaid := f.offerAndPay(t, "pr_1", "unpaid-name", "tier_1")
	_, paid := f.offerAndPay(t, "pr_1", "paid-name", "tier_1")
	f.pay.ProcessSettlement(bg, f.settlement(paid, "evt-1"))
	f.clk.Advance(time.Hour)
	if n := f.pay.ExpireStale(bg); n != 1 {
		t.Fatalf("expired %d", n)
	}
	if got, _ := f.pay.Get(bg, "pr_1", unpaid.ID); got.State != payment.StateExpired {
		t.Fatal(got.State)
	}
	if got, _ := f.pay.Get(bg, "pr_1", paid.ID); got.State != payment.StateEntitlementGranted {
		t.Fatal(got.State)
	}
}
