# Postmortem: monthly quota exceeded by 1.2 MB after an edge handoff

> **SYNTHETIC INCIDENT.** This did not happen in production; nothing here has been
> deployed. It is a rehearsal built from a failure the test suite *reproduces*
> (`TestQuotaOvershootAcrossEdgeHandoffIsBounded`), written the way a real postmortem
> would be, to exercise the process and to record what the system actually does. All
> byte counts below are measured; the narrative wrapper (timeline labels, "operator
> noticed") is illustrative.

| | |
|---|---|
| Severity | SEV-3 (fairness/quota accuracy; no data loss, no availability impact) |
| Duration of exposure | ≈ 1 handoff (seconds) |
| Affected | one free-plan endpoint (500 MB/month quota, scaled to 2 MB in the reproduction) |
| Status | corrected; regression test added |

## Summary

An endpoint's client failed over from edge-1 to edge-2. Edge-1 had moved about 1.2 MB
(1,216,000 B counted, including bytes in flight) that it had not yet reported to the ledger. Edge-2 was admitted from a policy showing `used_bytes = 0`
and let the endpoint transfer a further ~2.0 MB before refusing, so the ledger ended at
**3,216,384 B against a 2,000,000 B quota (overshoot 1,216,384 B)**.

## Impact

Bounded and non-persistent: the endpoint received about 1.2 MB of transfer beyond its monthly
allowance once. No other tenant was affected; no data was lost or misdirected; the next period
starts clean. Cost exposure at the free tier's rate: bounded by `unreported usage at handoff`
(here 1.2 MB), which at the default 1 s flush is about `1 s × 100 kB/s = 100 kB` on the free plan
and `1 s × 5 MB/s = 5 MB` on Tier 3 per handoff.

## Timeline (relative)

| T | Event |
|---|---|
| T-0:00 | Client serving via edge-1; 1.2 MB delivered. Usage flush is set to a very long interval (worst-case configuration used to reproduce the failure). |
| T+0:00 | Client fails over: opens a tunnel to edge-2 with a fresh credential. |
| T+0:00 | Edge-2 admits the tunnel using a policy fetched from the control plane: `used_bytes = 0` (edge-1's 1.2 MB is still unreported). Edge-1 loses its directory lease and stops routing locally; requests follow the directory to edge-2. |
| T+0:01 | Edge-2 serves until its own meter reaches the quota, then refuses with `429 quota_exhausted`. |
| T+0:01 | Edge-1's session ends and its usage is flushed. The ledger total now reads 3.2 MB. |
| Detection | Reconciliation of `ledger total − quota` for exhausted endpoints (`edge_quota_exhausted_total` non-zero while `used_bytes > limit`) flags the overshoot. |

## Root cause and contributing factors

1. **Root cause:** an edge's local view of usage is `last confirmed ledger total + its own unacknowledged bytes`.
   A *new* owner learns other edges' usage only from the policy it fetched and from the totals returned by
   its own batch acknowledgements. Usage that the previous owner had not reported is invisible to it.
2. **Contributing:** (a) usage was only flushed periodically, not when a tunnel ended, so a handoff left the ledger stale;
   (b) a session superseded by *another edge* was told GOAWAY but was not closed, so it never reached the point where
   it would flush; (c) the overshoot bound was undocumented, so nobody could say whether 1.2 MB was expected.
3. **Not a factor:** double counting (usage is idempotent per batch id), the token bucket, or the metering rule.

## What went well

Overshoot was bounded by exactly the quantity the design predicts (unreported bytes at handoff), the platform kept
refusing correctly once it knew, and nothing crossed tenants.

## Corrective actions

| # | Action | Type | State |
|---|---|---|---|
| 1 | Flush usage as soon as any tunnel disconnects, so a handoff's previous owner reports immediately. | prevent | done (`dataplane/app`, `OnDisconnect`) |
| 2 | Superseded sessions on another edge now run the same GOAWAY + bounded drain + close as same-edge takeovers, so they end and flush. | prevent | done (`dataplane/tunnel/server.go`) |
| 3 | Document the bound and measure it: `overshoot ≤ unreported at handoff + (flush + propagation) × rate + one chunk per stream`. | detect/explain | done (`docs/failure-model.md`) |
| 4 | Keep the periodic flush short (default 1 s) and expose `edge_usage_unflushed_bytes` so operators can alert on growth. | detect | done (metric + dashboard panel) |
| 5 | (Product) Reserve the difference: let a new owner ask the ledger for *current* usage at admission after a handoff rather than trusting a cached policy. | prevent | **not done in the public reference**; recorded as a product hardening item |

## Verification

| Claim | Evidence |
|---|---|
| Worst-case overshoot equals the usage the old owner had counted but not reported | `TestQuotaOvershootAcrossEdgeHandoffIsBounded`: overshoot 1,216,384 – 1,248,384 B over ten runs, each within a few kB of the measured unreported amount (1,216,000 – 1,232,384 B) |
| With usage reported before the handoff the overshoot is under one chunk | same test: 384 – 8,832 B, nothing unreported at handoff |
| Duplicate delivery cannot inflate the ledger | `TestDuplicateUsageBatchNotDoubleApplied`, `TestConcurrentDuplicateDeliveryAppliesOnce` |
| Superseded session ends and stops routing | `TestTunnelMovesToAnotherEdge` |

## Lessons

- State the bound of every "eventually consistent" quantity in the failure model, and measure it.
- A handoff is a data-consistency event, not just a routing event.
- Test names should read like the invariant they protect; this one is now the executable definition of the bound.
