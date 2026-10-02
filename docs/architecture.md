# Architecture

**Public HTTPS. Private origin. Zero inbound ports.**

A client behind NAT or a firewall opens one outbound TLS connection to an edge.
The edge terminates public TLS for `*.127ohoh1.com`, routes by hostname, enforces
a resolved policy and carries HTTP exchanges over the tunnel to the local origin.

```text
                          control plane (decides)                       data plane (enforces)
                    ┌──────────────────────────────┐              ┌───────────────────────────────┐
  client  ──HTTPS──▶│ identity   endpoint   plans  │◀─ policy ───▶│ policy cache  token bucket    │
  (Ed25519 key)     │ offers     payments  entitle │◀─ usage ─────│ metering      tunnel registry │
     │              │ policy publisher  usage ledger│              │ ingress (TLS, Host/SNI)       │
     │              └──────────────────────────────┘              └───────────────────────────────┘
     │   ▲ tunnel credential (signed, scoped, short-lived)                 ▲            │
     │   └─────────────────────────────────────────────────────────────────┘            │
     └──── outbound TLS 1.3 tunnel (multiplexed streams) ──────────────────────────────┘
                                                        public caller ──HTTPS──▶ ingress
```

## Components

| Component | Package(s) | Responsibility |
|---|---|---|
| Client CLI | `client/cli`, `client/session`, `client/origin`, `client/identity`, `client/api` | Identity, control-plane API, reconnecting tunnel, loopback-only origin forwarding |
| Control plane | `controlplane/*`, `cmd/control-plane` | Identity, endpoints, plan catalog, offers, payments, entitlements, policy resolution and publication, usage ledger, audit |
| Edge (data plane) | `dataplane/*`, `cmd/edge` | Tunnel auth, session registry, routing, ingress, bandwidth limiter, metering, policy cache |
| Protocol | `protocol/tunnel`, `protocol/auth`, `protocol/policy` | Frame format, stream multiplexer, credentials, the policy contract |
| Shared | `internal/*` | Clock, ids, config, errors, observability, dev TLS, health |

The control plane and the edge are separate binaries and separately testable
modules; each is a modular monolith. The control plane **never carries tenant
traffic**. The edge **never learns about money**.

## Trust boundaries

1. **Public caller → ingress.** Untrusted. Host is parsed strictly (one label under the
   base domain), SNI must equal Host, forwarded/trace headers from the caller are
   discarded and re-derived, sizes are bounded, `CONNECT` is refused. A protocol
   upgrade (WebSocket included) is proxied transparently rather than refused —
   see `docs/operations.md` §2 for how its (necessarily long-lived) duration is
   bounded by inactivity rather than a flat deadline.
2. **Client → edge tunnel.** The client key proves possession (channel-bound to the
   TLS connection); the credential proves what it may do. The origin behind the
   client is *not* trusted by the edge: response metadata is re-validated and origin
   responses cannot impersonate platform errors.
3. **Edge → origin (via client).** The client fixes the origin host at startup. The
   request target from the tunnel supplies path and query only, so a public caller
   cannot turn the client into an open proxy. Loopback-only by default, checked on
   the resolved address at connect time.
4. **Edge ⇄ control plane.** Service credential (constant-time compared). The edge
   receives only a *resolved policy*: limits and lifecycle state. Never a price,
   asset, wallet, transaction, subscription or plan.
5. **Operator → admin hooks.** Separate token, disabled unless configured, every call
   audited.

## Control plane / data plane split

| Question | Answered by | How the edge learns |
|---|---|---|
| Who owns `quiet-river-7f2c`? | control plane (`endpoint`) | signed tunnel credential scoped to one endpoint |
| What may it do, how fast, how much? | control plane (`policy`) | versioned `EndpointPolicy` snapshot |
| How much has it used? | control plane (`usage`) ledger, edge-local until acknowledged | policy `usage.used_bytes` + own unacknowledged bytes |
| Did someone pay? | control plane (`payment`, `entitlement`) | not at all; only the resulting limits |

Consequences: free and premium behaviour are *data* (limits in a policy), not `if plan
== ...` in the edge; a production commercial layer can replace the payment,
entitlement and persistence adapters without touching the protocol or the edge.

## Request lifecycle

1. Public request arrives over TLS; the edge validates method, upgrade headers, Host and SNI.
2. `Registry` maps the tenant label to the live tunnel session (or the request is refused with `endpoint_not_found`).
3. The **Enforcer** resolves the endpoint's cached policy: state (`suspended`, `expired`, `released` refuse), freshness (past `valid_until` + grace fails closed), quota (exhausted → `429 quota_exhausted`), concurrency. It returns a **Gate**.
4. Headers are filtered and a `traceparent` child is minted; `OPEN` carries the request metadata, then body `DATA` frames follow, throttled and metered through the Gate, concurrently with awaiting the response.
5. The client forwards to the local origin and streams the response back (`OPEN_OK`, `DATA`, `HALF_CLOSE`).
6. The edge writes the response, again throttled and metered. On cancellation, quota exhaustion or origin failure the stream is reset and the public connection is aborted so a truncated body cannot look complete.

## Metering rule (single documented layer)

Metered bytes = HTTP **message body** bytes crossing the tunnel, once per direction:
request body bytes handed to the tunnel plus response body bytes received from it.
Not metered: headers, tunnel framing, `WINDOW_UPDATE`/control frames, platform-generated
error bodies. Retries are separate requests; retransmission below TLS is invisible.
The rule is deterministic and tested (`TestMonthlyQuotaCountsBothDirectionsAndRefusesPromptly`).

## Policy propagation and caching

Policies are immutable, versioned snapshots (ADR 0004). The control plane bumps
`policy_version` when enforcement-relevant state changes (lifecycle state, limits,
period, quota exhaustion) but not for usage growth. Edges obtain policies by initial
fetch on demand, a **change feed** (long-poll, wakes within milliseconds), periodic
refresh, and bounded validity (`valid_until` = min(now + TTL, period end)).

The cache never lets a lower version overwrite a higher one, applies non-active states
immediately, serves stale entries only within a configured grace (counted in
`edge_policy_stale_use_total`), and then **fails closed** for new requests
(`policy_expired`). A suspension therefore reaches an edge in about one feed
round-trip when the control plane is reachable, and within `valid_until` + grace
when it is not (the security/availability trade-off is deliberate and configurable).

## Name lifecycle

```text
PENDING -> ACTIVE -> SUSPENDED -> RELEASED
              |          |
              +-> EXPIRED +      EXPIRED -> ACTIVE (renewed) | RELEASED
```

- **Free (random) names:** released after 24 h without an authenticated tunnel. The edge
  reports presence and heartbeats; `last_active_at` therefore only stops advancing once
  the tunnel is gone (or the edge died). Released names enter a configurable tombstone.
- **Reserved names:** exist while an entitlement is active; on lapse the endpoint becomes
  `EXPIRED` (policy `expired`), and is released after a configurable window.
- Every transition is an explicit table; suspension/expiry/release are idempotent.

## Dependencies and degraded modes

| Failure | Behaviour |
|---|---|
| Control plane down, tunnel established | Requests keep flowing from cached policy until `valid_until` + stale grace, then `503 policy_expired` (fail closed). Tunnels stay connected. Recovery is automatic. |
| Control plane down, new tunnel | Credential must already exist (verified locally against cached keys); admission needs a cached policy, otherwise a retryable `policy_unavailable`. |
| Control plane down, usage flush | Batches queue (bounded, immutable) and retry; nothing is lost while the edge lives. |
| Edge killed | Tunnels drop; clients reconnect with backoff. Un-flushed usage (at most the flush interval) is lost. Directory leases expire. |
| Client link lost | In-flight requests fail with `tunnel_lost`; nothing is replayed. |
| Origin down/slow | `502 origin_unreachable` / `504 origin_timeout`. |
| Certificate replacement invalid | Rejected; previous certificate keeps serving. |

See `failure-model.md` for invariants, bounds and retry safety.

## Package boundaries worth knowing

- `dataplane/*` imports only `protocol/*` and `internal/*` — never `controlplane/*` (checked by `TestDataPlaneDoesNotImportControlPlane`).
- Adapters are named for what they are: `InMemory`, `Mock`, `Development`. None can be constructed as "production" (see ADR 0007, `docs/payment-protocol.md`).
