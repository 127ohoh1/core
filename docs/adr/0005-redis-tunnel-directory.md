# ADR 0005: Tunnel directory behind an interface; Redis for multi-edge development

Status: accepted

## Decision
`hostname -> endpoint -> owning edge -> session` is resolved through the `TunnelDirectory` interface. Single-edge uses an in-memory implementation; the multi-edge development profile uses Redis with short leases refreshed by heartbeats. A newly authenticated session supersedes the previous one (GOAWAY + bounded drain).

## Consequences
- Lease expiry bounds stale ownership after an edge is killed.
- Redis is not a source of truth: it is rebuilt from live sessions; losing it degrades multi-edge routing only.
