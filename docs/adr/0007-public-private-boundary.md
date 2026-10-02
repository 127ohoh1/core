# ADR 0007: Public reference / private product boundary

Status: accepted

## Decision
This repository contains a complete, runnable core with *Mock/Development/InMemory* adapters for payments, entitlements and persistence. Real settlement, renewal, abuse detection, production pricing rules, DNS credentials and operations live in a private product repository that consumes versioned protocol and API artifacts.

## Consequences
- Adapter names are explicit (`Mock…`, `Development…`, `InMemory…`) and dev capabilities refuse to start with `APP_ENV=production`.
- Compatibility between repositories is governed by protocol/API versions, not by the public `main` branch.
