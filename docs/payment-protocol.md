# Payment protocol (development reference)

> **Scope.** This document describes the *contract* and the *development*
> implementation shipped in this repository. Everything money-related here is
> **simulated**: there is no wallet, no key custody, no blockchain access, no
> confirmation or reorg handling, no renewal, refund or reconciliation. Those
> belong to the private product behind the same interfaces (ADR 0007). Nothing
> in this repository should be read as a production payment design.

## 1. Why HTTP 402 with a machine-readable body

`402 Payment Required` is only a *signal*. Browsers and generic HTTP clients do
not know how to pay, so the application defines an explicit contract: the
response body carries offers and payment methods that an aware client (the CLI,
an agent, a dashboard) can act on. The contract is network-neutral: the payment
method object names a `type` and `network`; the reference build lists exactly one
clearly labelled method, `development_crypto` on the `development` network.

Money is never a binary float. Wire amounts are decimal strings (`"1"`, `"2"`,
`"4"`); the domain stores integer atomic units (1 USDC = 1,000,000).

## 2. The 402 response

Returned by `POST /v1/endpoints/reserve` when the caller has no sufficient
entitlement for the requested name.

```http
HTTP/1.1 402 Payment Required
Content-Type: application/json
Cache-Control: no-store
```

```json
{
  "error": {
    "code": "payment_required",
    "message": "A paid entitlement is required to reserve this hostname.",
    "request_id": "req_01J..."
  },
  "resource": {"type": "hostname", "name": "myproject"},
  "offers": [{
    "id": "offer_01J...",
    "plan": "tier_2",
    "status": "open",
    "scope": {"type": "hostname", "name": "myproject"},
    "price": {"amount": "2", "asset": "USDC", "interval": "month", "unit": "name"},
    "limits": {"bandwidth_bytes_per_second": 3000000, "monthly_transfer_bytes": 100000000000},
    "payment_methods": [{
      "type": "development_crypto",
      "network": "development",
      "asset": "USDC",
      "payment_request": "devpay:pay_01J...",
      "simulated": true
    }],
    "payment_id": "pay_01J...",
    "expires_at": "2026-09-21T21:30:00Z",
    "status_url": "/v1/offers/offer_01J..."
  }]
}
```

A client should: show the price and limits, obtain explicit consent, pay via one
of `payment_methods`, poll `status_url` until `status` is `paid`, then **repeat
the original request** (same `Idempotency-Key`). It now succeeds and returns the
reserved endpoint.

## 3. Offers

An offer is a customer-, name- and plan-scoped **immutable terms snapshot**
with an expiry (default 30 minutes). Terms are copied from the catalog at issue
time and are never recomputed: changing the catalog later does not alter an
issued offer, and the entitlement it produces carries the same snapshot.

- `POST /v1/offers {name, plan}` creates (or reuses) an offer without the
  reserve workflow. Unknown JSON fields, including any client-supplied price,
  are rejected.
- An open, unexpired offer for the same `(principal, name, plan)` is reused, so
  retries never multiply offers. `Idempotency-Key` is supported: replays return
  the original offer; the same key with a different request is
  `409 idempotency_key_reused`.
- The name is validated (lowercase DNS label, 3-63 characters, reserved and
  confusable names rejected) and checked for availability **without holding it**:
  an offer is not a reservation.
- Only paid plans (`tier_1`, `tier_2`, `tier_3`) are purchasable. All prices are
  **per month per name**.
- `GET /v1/offers/{id}` (owner only) returns the offer and its payment; the
  offer reports `paid` only once the entitlement exists.

## 4. Payment states

```text
CREATED -> AWAITING_PAYMENT -> SEEN -> CONFIRMING -> SETTLED -> ENTITLEMENT_GRANTED
              |                 |          |
              +-------------> EXPIRED      +-> FAILED
```

`EXPIRED`, `FAILED` and `ENTITLEMENT_GRANTED` are terminal. Every transition is
validated (`CanTransition`, table-tested exhaustively). The development adapter
walks `SEEN -> CONFIRMING -> SETTLED` in a single step; the model supports a
production adapter moving through them over time.

`SETTLED` means "money is considered received". `ENTITLEMENT_GRANTED` means the
capability exists. They are separate on purpose: if granting fails, the payment
stays `SETTLED` and re-delivery completes it (see 6).

## 5. Payment vs entitlement

```text
PaymentVerifier   proof  ->  PaymentResult          "did money move, exactly?"
PaymentService    settlement event -> state machine  "is this payment settled?"
EntitlementService settled payment + terms -> Entitlement   "what does that buy?"
PolicyResolver    entitlement + lifecycle + usage -> EndpointPolicy   "what may the edge enforce?"
```

The **edge never sees any of this**: it consumes `EndpointPolicy` (limits and
lifecycle state only). `TestPolicyCarriesNoCommercialFields` fails if a price,
asset, wallet, transaction, subscription or plan field ever appears in it.

An entitlement is a time-bounded right for one principal to use one hostname
under one plan's limits. In the reference build the term is one calendar month
from settlement (`valid_until` is exclusive). One live entitlement per name
exists at any time; a second payer for a name that is already entitled is an
**exception** (payment stays `SETTLED`, no entitlement) that requires an
operator, which is private-product territory.

## 6. Idempotency and safety

- `ProcessSettlement` runs under a per-payment lock and is driven by the payment
  state, not by "have I seen this event". Any number of deliveries of the same
  (or different) events for one payment produce **at most one entitlement**
  (`TestDuplicateSettlementDeliveryGrantsOnce`,
  `TestConcurrentDuplicateSettlementsGrantOnce`; the entitlement store also
  enforces one entitlement per settlement id).
- A failure after `SETTLED` and before the grant leaves the payment `SETTLED`;
  re-delivery finishes the remaining steps without granting twice
  (`TestRedeliveryCompletesPartialSettlement`).
- A settlement event id is bound to exactly one payment; replaying it against
  another payment is a conflict.
- The settlement's own claims are never trusted: amount, asset and network are
  compared with the offer's immutable terms. A mismatch marks the payment
  `FAILED` (`settlement_mismatch`) and can never be resurrected by a later event.
- A settlement arriving after the offer expired marks the payment `EXPIRED`
  (`offer_expired`) and grants nothing.
- Payments and offers are readable only by their owner; other principals get
  `404`, never `403`.

## 7. Development-only behaviour

| Capability | Where | Guard |
|---|---|---|
| `POST /v1/payments/{id}/simulate-settlement` | control plane | `development_payments=true` **and** `app_env != production` **and** a mock verifier exists; otherwise `404` (fail closed, not advertised) |
| `MockVerifier` | `controlplane/payment/mock.go` | constructor returns `ErrMockInProduction` when `app_env=production`; proof format `devpay-proof:v0-NOT-FOR-PRODUCTION:...` is never valid for anything else |
| `development_payments` config | `internal/config` | `Validate()` refuses it in production, the process exits non-zero |
| Payment method `development_crypto` / network `development` / `"simulated": true` | every offer and payment document | always present, cannot be omitted |

Enabling simulation logs a loud `DEVELOPMENT PAYMENTS ENABLED` warning at startup
and every simulated settlement is logged and audited. There is no environment
variable that grants premium without going through offer, payment and
entitlement (spec section 18).

## 8. What a production adapter replaces

Implementing these interfaces (and nothing else) is the extension point:

- `PaymentVerifier.Verify` — authoritative observation of a real payment (network,
  asset, destination/invoice, exact amount, confirmations, reorg signals).
- `PaymentService` — durable storage, provider event ingestion, reconciliation.
- `EntitlementService` — renewal, upgrade/downgrade, grace, revocation, repair.
- The offer's `payment_methods` — real payment requests attributable to exactly
  one offer.

The protocol above (402 body, offers, states, idempotency rules) does not change.
