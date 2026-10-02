package api

import (
	"net/http"
	"time"

	"github.com/127ohoh1/core/controlplane/audit"
	"github.com/127ohoh1/core/controlplane/endpoint"
	"github.com/127ohoh1/core/controlplane/identity"
	"github.com/127ohoh1/core/controlplane/offer"
	"github.com/127ohoh1/core/controlplane/payment"
	"github.com/127ohoh1/core/internal/apperr"
	"github.com/127ohoh1/core/internal/config"
	"github.com/127ohoh1/core/internal/observability"
)

func (s *Server) paymentRoutes() {
	m := s.mux
	m.HandleFunc("POST /v1/offers", s.principal(s.handleCreateOffer))
	m.HandleFunc("GET /v1/offers/{offer_id}", s.principal(s.handleGetOffer))
	m.HandleFunc("GET /v1/payments/{payment_id}", s.principal(s.handleGetPayment))
	m.HandleFunc("POST /v1/payments/{payment_id}/simulate-settlement", s.principal(s.handleSimulateSettlement))
	m.HandleFunc("POST /v1/endpoints/reserve", s.principal(s.handleReserve))
}

// devPaymentsEnabled is the fail-closed gate for every simulated-payment
// capability. It requires an explicit flag AND a non-production profile AND a
// constructed mock verifier; production configuration is additionally refused
// at startup (config.Validate) and when the verifier is built.
func (s *Server) devPaymentsEnabled() bool {
	return s.d.Cfg.DevelopmentPayments && s.d.Cfg.AppEnv != config.EnvProduction && s.d.Verifier != nil
}

// ---- documents ---------------------------------------------------------------

type priceView struct {
	Amount   string `json:"amount"`
	Asset    string `json:"asset"`
	Interval string `json:"interval"`
	Unit     string `json:"unit"`
}

type methodView struct {
	Type           string `json:"type"`
	Network        string `json:"network"`
	Asset          string `json:"asset"`
	PaymentRequest string `json:"payment_request"`
	Simulated      bool   `json:"simulated"`
}

type offerView struct {
	ID     string `json:"id"`
	Plan   string `json:"plan"`
	Status string `json:"status"`
	Scope  struct {
		Type string `json:"type"`
		Name string `json:"name"`
	} `json:"scope"`
	Price          priceView    `json:"price"`
	Limits         limitsView   `json:"limits"`
	PaymentMethods []methodView `json:"payment_methods"`
	PaymentID      string       `json:"payment_id,omitempty"`
	ExpiresAt      string       `json:"expires_at"`
	StatusURL      string       `json:"status_url"`
}

type limitsView struct {
	BandwidthBytesPerSecond int64 `json:"bandwidth_bytes_per_second"`
	MonthlyTransferBytes    int64 `json:"monthly_transfer_bytes"`
}

func (s *Server) offerView(o offer.Offer, p payment.Payment) offerView {
	v := offerView{ID: o.ID, Plan: o.PlanID, Status: string(o.State), ExpiresAt: o.ExpiresAt.UTC().Format(time.RFC3339), StatusURL: "/v1/offers/" + o.ID,
		Price:     priceView{Amount: o.Terms.Amount, Asset: o.Terms.Asset, Interval: o.Terms.Interval, Unit: o.Terms.Unit},
		Limits:    limitsView{BandwidthBytesPerSecond: o.Terms.BandwidthBytesPerSecond, MonthlyTransferBytes: o.Terms.MonthlyTransferBytes},
		PaymentID: p.ID}
	v.Scope.Type, v.Scope.Name = "hostname", o.ScopeName
	// The method list is network-neutral; this reference build only ever lists a
	// clearly labelled development method.
	v.PaymentMethods = []methodView{{Type: "development_crypto", Network: payment.DevNetwork, Asset: o.Terms.Asset,
		PaymentRequest: "devpay:" + p.ID, Simulated: true}}
	return v
}

type paymentView struct {
	ID        string `json:"id"`
	OfferID   string `json:"offer_id"`
	State     string `json:"state"`
	Amount    string `json:"amount"`
	Asset     string `json:"asset"`
	Network   string `json:"network"`
	Provider  string `json:"provider"`
	Simulated bool   `json:"simulated"`
	Reason    string `json:"failure_reason,omitempty"`
	UpdatedAt string `json:"updated_at"`
}

func paymentViewOf(p payment.Payment) paymentView {
	return paymentView{ID: p.ID, OfferID: p.OfferID, State: string(p.State), Amount: payment.FormatAmount(p.Amount.Atomic, payment.USDCDecimals),
		Asset: p.Amount.Asset, Network: p.Network, Provider: p.Provider, Simulated: p.Provider == payment.DevProvider, Reason: p.FailureReason,
		UpdatedAt: p.UpdatedAt.UTC().Format(time.RFC3339)}
}

// paymentRequiredBody is the machine-readable 402 contract (payment-protocol.md).
func (s *Server) paymentRequiredBody(reqID, name string, ov offerView) map[string]any {
	return map[string]any{
		"error": map[string]any{
			"code": "payment_required", "message": "A paid entitlement is required to reserve this hostname.", "request_id": reqID,
		},
		"resource": map[string]any{"type": "hostname", "name": name},
		"offers":   []offerView{ov},
	}
}

// ---- handlers ----------------------------------------------------------------

func (s *Server) newOffer(r *http.Request, p identity.Principal, name, plan string) (offer.Offer, payment.Payment, error) {
	o, err := s.d.Offers.CreateOrReuse(r.Context(), p.ID, name, plan)
	if err != nil {
		return offer.Offer{}, payment.Payment{}, err
	}
	pay, err := s.d.Payments.CreateForOffer(r.Context(), o)
	if err != nil {
		return offer.Offer{}, payment.Payment{}, err
	}
	return o, pay, nil
}

func (s *Server) handleCreateOffer(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	body, err := readBody(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var in struct {
		Name string `json:"name"`
		Plan string `json:"plan"`
	}
	if err := decode(body, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	s.idempotent(w, r, p, "offer.create", body, func() (int, any, error) {
		o, pay, err := s.newOffer(r, p, in.Name, in.Plan)
		if err != nil {
			return 0, nil, err
		}
		s.d.Audit.Record(r.Context(), audit.Event{ID: s.d.IDs.New("aud"), Actor: p.ID, Action: "offer.create", Target: o.ID, Result: "ok", RequestID: requestID(r), At: s.d.Clock.Now(),
			Metadata: map[string]string{"plan": o.PlanID, "name": o.ScopeName}})
		return http.StatusCreated, s.offerView(o, pay), nil
	})
}

func (s *Server) handleGetOffer(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	o, err := s.d.Offers.Get(r.Context(), p.ID, r.PathValue("offer_id"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	pay, err := s.d.Payments.ByOffer(r.Context(), o.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	v := s.offerView(o, pay)
	// The offer is "paid" only once the entitlement exists (payment ENTITLEMENT_GRANTED).
	if pay.State == payment.StateEntitlementGranted {
		v.Status = string(offer.StatePaid)
	}
	writeJSON(w, 200, map[string]any{"offer": v, "payment": paymentViewOf(pay)})
}

func (s *Server) handleGetPayment(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	pay, err := s.d.Payments.Get(r.Context(), p.ID, r.PathValue("payment_id"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, paymentViewOf(pay))
}

// handleSimulateSettlement drives a settlement through the *same* code path a
// production adapter would use: verifier -> settlement event -> idempotent
// processing -> entitlement. Only reachable in an explicit development mode.
func (s *Server) handleSimulateSettlement(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	if !s.devPaymentsEnabled() {
		s.d.Log.Warn("payments.simulation_refused", observability.FieldEvent, "payments.simulation_refused", observability.FieldPrincipal, p.ID)
		s.fail(w, r, apperr.ErrNotFound) // fail closed, and do not advertise the capability
		return
	}
	pay, err := s.d.Payments.Get(r.Context(), p.ID, r.PathValue("payment_id"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	res, err := s.d.Verifier.Verify(r.Context(), payment.PaymentProof{Provider: payment.DevProvider, Reference: pay.Reference,
		Raw: payment.MockProof(pay.ID, pay.Amount.Atomic, pay.Amount.Asset)})
	if err != nil || !res.Settled {
		s.fail(w, r, apperr.ErrInternal.Wrap(err))
		return
	}
	s.d.Log.Warn("payments.simulated_settlement", observability.FieldEvent, "payments.simulated_settlement", observability.FieldPrincipal, p.ID, "payment_id", pay.ID)
	out, err := s.d.Payments.ProcessSettlement(r.Context(), payment.Settlement{EventID: res.EventID, PaymentID: res.PaymentID, Amount: res.Amount, Network: res.Network, At: s.d.Clock.Now()})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.d.Audit.Record(r.Context(), audit.Event{ID: s.d.IDs.New("aud"), Actor: p.ID, Action: "payment.simulate_settlement", Target: out.ID, Result: "ok", RequestID: requestID(r), At: s.d.Clock.Now()})
	writeJSON(w, 200, paymentViewOf(out))
}

// handleReserve implements POST /v1/endpoints/reserve.
//
//	entitled for the name (plan >= requested) -> 201 endpoint (200 if it already exists)
//	not entitled                              -> 402 with a machine-readable offer
//
// The request is naturally idempotent: an unpaid retry returns the same open
// offer, and a retry after settlement returns the resource it created.
func (s *Server) handleReserve(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	body, err := readBody(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var in struct {
		Name string `json:"name"`
		Plan string `json:"plan"`
	}
	if err := decode(body, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	plan, err := s.d.Offers.PaidPlan(in.Plan)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	name, err := s.d.Endpoints.CheckName(r.Context(), p.ID, in.Name)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.idempotent(w, r, p, "endpoint.reserve", body, func() (int, any, error) {
		now := s.d.Clock.Now()
		ent, entitled := s.d.Entitlements.Active(p.ID, name, now)
		if entitled {
			have, err := s.d.Catalog.Get(ent.PlanID)
			if err != nil || have.Rank < plan.Rank {
				return 0, nil, apperr.ErrConflict.WithDetails(map[string]any{"reason": "upgrade_not_supported",
					"message": "an active entitlement exists at a lower tier; upgrades are a product feature outside this reference"})
			}
			if existing, ok := s.findReserved(r, p.ID, name); ok {
				if existing.State == endpoint.StateExpired { // renewed since it lapsed
					if e2, err := s.d.Endpoints.Reactivate(r.Context(), existing.ID); err == nil {
						existing = e2
					}
				}
				return http.StatusOK, s.view(r, existing), nil
			}
			e, err := s.d.Endpoints.CreateReserved(r.Context(), p.ID, name)
			if err != nil {
				return 0, nil, err
			}
			s.d.Audit.Record(r.Context(), audit.Event{ID: s.d.IDs.New("aud"), Actor: p.ID, Action: "endpoint.reserve", Target: e.ID, Result: "ok", RequestID: requestID(r), At: now,
				Metadata: map[string]string{"name": name, "plan": ent.PlanID}})
			return http.StatusCreated, s.view(r, e), nil
		}
		o, pay, err := s.newOffer(r, p, name, plan.ID)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusPaymentRequired, s.paymentRequiredBody(requestID(r), name, s.offerView(o, pay)), nil
	})
}

func (s *Server) findReserved(r *http.Request, principalID, name string) (endpoint.Endpoint, bool) {
	es, err := s.d.Endpoints.List(r.Context(), principalID)
	if err != nil {
		return endpoint.Endpoint{}, false
	}
	for _, e := range es {
		if e.Kind == endpoint.KindReserved && e.Hostname == name {
			return e, true
		}
	}
	return endpoint.Endpoint{}, false
}
