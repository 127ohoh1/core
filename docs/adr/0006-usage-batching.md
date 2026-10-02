# ADR 0006: Edge-side usage aggregation with idempotent batches

Status: accepted

## Decision
Bytes are counted at the edge on HTTP body payload (both directions, once) and flushed as batches with unique `batch_id`s. Batches are immutable once cut, retried with the same id, and de-duplicated by the ledger on `(edge_id, batch_id)`. A synchronous write per chunk is never made.

## Bounds
Undercount after an abrupt edge kill <= `usage_flush_interval x rate`. Overshoot of the monthly quota is bounded by `(flush + policy refresh) x rate x edges` in multi-edge deployments and is ~0 for a single edge, which adds its own unacknowledged bytes to the ledger total.
