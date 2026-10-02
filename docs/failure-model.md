# Failure model

For each dependency failure this document states the **invariant that must still hold**,
the **observable behaviour**, the **recovery path**, the **data-loss bound**, and whether
**retries are safe**. Every claim names the test that demonstrates it. Numbers marked
*measured* come from the runs recorded in `benchmarks/results/`; nothing here is a target
or a guess.

## Global invariants

1. **No cross-tenant delivery.** A request is only ever forwarded on the tunnel that owns
   the Host's tenant label, or refused. (Even during supersede, partition or policy staleness.)
2. **Fail closed on unbounded staleness.** Enforcement data past `valid_until` + grace is
   never trusted for new requests.
3. **Suspension wins.** No entitlement, cache state or retry can re-enable a suspended endpoint.
4. **At most one entitlement per settled payment**, however often events are delivered.
5. **At most one application of a usage batch id**, however often it is delivered.
6. **Memory is bounded** per connection, stream, queue and retry list; input is checked
   against limits before allocation.
7. **No silent truncation.** A response that cannot be completed is aborted, never ended cleanly.
8. **Requests are never replayed automatically.** A failed in-flight request stays failed.

## Dependency and process failures

### Control plane unavailable while a tunnel is established
*Invariants:* 1, 2, 3 (as far as it was told). *Behaviour:* the edge serves from cached policy
until `valid_until`; then within `policy_stale_grace` (each use counted in
`edge_policy_stale_use_total`); then **new requests get `503 policy_expired`** while the tunnel
stays connected (`TestEstablishedTunnelSurvivesControlPlaneOutageWithinBounds`). Usage batches
queue and retry. *Recovery:* automatic on the next successful refresh; no reconnect needed.
*Data-loss bound:* none for usage while the edge lives. *A suspension issued during the outage*
reaches the edge only at recovery: worst-case exposure = `valid_until` + grace (default 5 min + 5 min).
*Retry safety:* idempotent GETs; usage batches carry ids. *Detection latency:* a control plane that **refuses**
connections is noticed immediately; one that **hangs** (as with `docker pause`, or a black-holed network) is noticed only
when an in-flight call times out, up to about 30 s (change-feed long poll) — `tests/failure/compose-faults.sh` scenario A waits for
`edge_control_plane_reachable = 0` explicitly rather than assuming a fast failure.

### Control plane unavailable, no cached policy (cold edge / new endpoint)
Tunnel admission answers a **retryable** `policy_unavailable`; requests get
`503 policy_unavailable` (`TestColdEdgeDuringOutageIsUnavailableNotPermissive`). Never permissive.

### Control plane restart (state loss in the reference)
The reference stores state in memory: a restart forgets principals, endpoints, offers,
payments, entitlements and usage. Clients transparently re-login once (`TestStaleSessionTriggersOneRelogin`);
their endpoints are then `not_found` and the CLI stops with a clear error. Edges see 404 for
policies (kept entries expire per the rules above). A Postgres-backed store (schema in
`migrations/`) removes this failure mode; it is **not implemented** in the public reference.

### Redis (tunnel directory) unavailable
*Invariant:* local routing is unaffected. *Behaviour:* established tunnels keep serving; new
tunnels still register locally (degraded: invisible to other edges); requests that would need
a cross-edge hop get `503 directory_unavailable`; `edge_directory_errors_total{op}` rises
(`TestDirectoryOutageDegradesGracefully`). *Recovery:* heartbeats re-establish leases; lease
loss during a partition is repaired by re-claiming when no other live owner exists.
*Loss bound:* none (Redis holds no source-of-truth state).

### Database unavailable
Not applicable to the reference (no database). For a real store: the control plane must fail
readiness and return `503` for mutations; edges are unaffected (they depend on the control
plane, not the database).

### Edge process killed
*Behaviour:* tunnels drop; clients detect via keepalive/EOF and reconnect with jittered
backoff to any edge (`TestEdgeRestartClientReconnects`, `TestTunnelMovesToAnotherEdge`). In-flight
requests fail (no replay). Directory leases expire within `lease_ttl`; free-name inactivity
clocks age from the last heartbeat. *Data-loss bound:* usage metered since the last successful
flush is lost: **≤ `usage_flush` (default 1 s) × the endpoint's rate**, i.e. ≤ 100 kB on the free plan.

### Graceful edge shutdown
Readiness goes false first; in-flight public requests complete (`TestLivenessReadinessSemantics`);
tunnels get GOAWAY and drain (bounded); usage and presence are flushed
(`TestUsageFlushedOnGracefulShutdown`); clients reconnect elsewhere.

### Client connection interrupted / GOAWAY
In-flight streams fail (`tunnel_lost`, `TestSessionLossFailsInFlightRequestsClearly`); the client reauthenticates
and reregisters; after GOAWAY it connects the replacement first while the old session drains.
Non-retryable credential errors (released, suspended, unauthorised) stop the client instead of looping
(`TestRunStopsOnNonRetryableCredentialError`).

### Origin slow, unavailable, or dying mid-response
`504 origin_timeout` / `502 origin_unreachable`; a mid-response failure **aborts** the public
connection (`TestSlowOriginGetsGatewayTimeout`, `TestOriginClosesMidResponseIsNotSilentlyTruncated`). Slot released either way.

### Public caller cancels mid-request
Cancellation propagates to the origin request context and frees the stream slot
(`TestPublicCancelPropagatesToOrigin`).

### Slow public client / stalled stream
Flow control blocks the origin at the window; other streams are unaffected
(`TestSlowPublicClientAppliesBackpressure`, `TestStalledStreamDoesNotBlockOthers`). Buffers per
stream ≤ `stream_window` (256 KiB default).

### Monthly quota reached during a transfer
**One behaviour, documented and tested:** new requests are refused immediately with
`429 quota_exhausted` (+ `Retry-After` to the period end); requests in flight are terminated at their next chunk
boundary and the connection is aborted (`TestQuotaExhaustedMidStreamTerminatesConsistently`). Overshoot per endpoint is
at most one 16 KiB chunk per in-flight stream.

**Multi-edge / handoff overshoot (measured).** A quota is enforced from `confirmed ledger total + locally
unacknowledged bytes`. Two edges can only both serve an endpoint during a handoff. The extra usage is bounded by the usage that
had not reached the ledger when the new owner started:

| Scenario (`TestQuotaOvershootAcrossEdgeHandoffIsBounded`, quota 2,000,000 B) | Ledger total | Overshoot |
|---|---:|---:|
| Worst case: periodic flush off, handoff immediately after the caller read 1.2 MB | 3,216,384 – 3,248,384 | **1,216,384 – 1,248,384** (equal, within a few kB, to what edge-1 had counted but not yet reported: 1,216,000 – 1,232,384 in the instrumented runs) |
| Usage flushed (100 ms) before the handoff | 2,000,384 – 2,008,832 | **384 – 8,832** (< one chunk; nothing unreported at handoff) |

*Unreported* means bytes the old owner had already **counted**, which includes bytes in flight up to the flow-control window,
not just what the caller read; that is why the worst case is a little above 1.2 MB. Ten runs; the test asserts the bound on every run.

Design bound: `overshoot ≤ unreported usage at handoff + (flush interval + propagation) × rate + one chunk per stream`.
At the reference's default 1 s flush, that is about `1 s × plan rate` (100 kB free, 5 MB Tier 3) per handoff. Flush also runs when a
tunnel ends, so the old owner's last usage reaches the ledger promptly.

### Usage delivered twice / lost responses
Batches are immutable and keyed `(edge_id, batch_id)`; the ledger applies each once and reports current totals on replay
(`TestDuplicateUsageBatchNotDoubleApplied`, `TestRetryAfterLostResponseIsIdempotent`,
`TestConcurrentDuplicateDeliveryAppliesOnce`). The retry queue is bounded (64 batches); when full, counters keep
accumulating rather than dropping (`TestPendingQueueIsBounded`). A permanently rejected (poison) batch is dropped so it
cannot wedge the queue.

### Settlement delivered twice / partially
Idempotent by state under a per-payment lock; a crash between `SETTLED` and the grant is completed by redelivery
(`TestDuplicateSettlementDeliveryGrantsOnce`, `TestConcurrentDuplicateSettlementsGrantOnce`, `TestRedeliveryCompletesPartialSettlement`).

### Policy version races
Lower never overwrites higher; equal versions merge volatile fields without shortening validity or lowering usage
(`TestLowerVersionNeverOverwritesHigher`, `TestEqualVersionMergesVolatileFields`).

### Certificate replacement
Validated before use; failure keeps the old certificate; rotation never drops tunnels
(`TestCertificateRotationWithoutDroppingTunnels`).

### Bandwidth limiter under many concurrent streams
One shared bucket per endpoint: 32 concurrent waiters get the aggregate rate, not 32×
(`TestManyConcurrentWaitersShareOneRate`, `TestConcurrencyDoesNotMultiplyBandwidth`); accuracy at
100 kB/s measured at 3.004 s for 500 kB through the Compose stack (spec: 3.0 s).

## Retry-safety summary

| Operation | Safe to retry? | Why |
|---|---|---|
| `POST /v1/endpoints`, `/v1/offers`, `/v1/endpoints/reserve` | yes | `Idempotency-Key`; open offers reused; reserve is naturally idempotent |
| `simulate-settlement` (dev) | yes | state-driven idempotence |
| `POST /v1/usage/batches` | yes | idempotent per `(edge_id, batch_id)` |
| `POST /v1/presence` | yes | latest state per endpoint wins |
| Public HTTP request through the tunnel | **not automatically** | never replayed by the platform; the caller decides (safe for idempotent methods only) |
| Tunnel (re)connect | yes | fresh credential each time; new session supersedes old |

## Reproducing the failure tests

```bash
go test -race ./tests/failure/... ./tests/integration/...
make test-redis                   # directory contract against a real Redis (docker)
tests/failure/compose-faults.sh   # kill/restart real containers under the Compose stack
```
