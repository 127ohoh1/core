# ADR 0004: Versioned immutable policy snapshots

Status: accepted

## Decision
Per endpoint, the control plane publishes a monotonically increasing `policy_version` whenever enforcement-relevant state changes (state, limits, hostname kind, usage period, quota exhaustion). Each snapshot carries `valid_until`.

The edge caches snapshots with these rules:
- a lower version never overwrites a higher one;
- a suspended/released/expired state is applied immediately on receipt;
- after `valid_until`, a configurable stale grace applies (default 5 min, metric `edge_policy_stale_use_total`); beyond it the edge fails closed for new requests;
- cache entries contain only enforcement data.

## Trade-off
Stale-permissive grace favours availability during control-plane blips at the cost of a bounded window in which a revocation may not be seen. Revocations are pushed via a change feed and take precedence when received.
