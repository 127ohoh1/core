# ADR 0003: Control plane decides, data plane enforces

Status: accepted

## Decision
The control plane owns identity, ownership, offers, payments, entitlements and quotas and never carries tenant traffic. The edge authenticates tunnels, routes, meters and enforces a *resolved policy*. The edge has no notion of price, asset, wallet, transaction or subscription.

## Consequences
- Tier behaviour is data (limits in a policy), not `if plan == ...` in the edge.
- The edge verifies tunnel credentials locally (Ed25519 signature, key set cached) so established and new tunnels survive a short control-plane outage.
- The control plane can be replaced or rewritten commercially without touching the protocol.
