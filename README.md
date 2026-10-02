# 127ohoh1

**Public HTTPS. Private origin. Zero inbound ports.**

127ohoh1 exposes a local HTTP application behind NAT or a firewall through a public HTTPS URL such as
`https://quiet-river-7f2c.127ohoh1.com`. A small client opens **one outbound TLS 1.3 connection** to an edge; the
edge terminates public TLS, routes by hostname, enforces a resolved policy (bandwidth, monthly transfer, lifecycle)
and carries HTTP exchanges over the tunnel to your loopback origin.

> ### This is a public **reference implementation**, not a production service
> It is a runnable, tested, deliberately bounded reference of the engineering: protocol design, authentication,
> flow control, rate limiting, metering, policy propagation, failure handling, and an HTTP 402 payment contract.
> Payments are **simulated**. Persistence is **in memory**. There has been **no independent security review or
> penetration test**. A private product repository is meant to sit behind the same interfaces (see
> [ADR 0007](docs/adr/0007-public-private-boundary.md)); nothing here should be described as production-ready.

## Five-minute demo

Requires Docker and `curl`. Everything below is what the repository's own tests and scripts exercise.

```bash
make up            # control plane, edge, demo origin + client, postgres, redis, prometheus, grafana
```

Wait until it settles, then read the public URL the demo client printed:

```bash
docker compose -f deploy/docker/compose.yaml logs demo-client
#   Generating identity: /tmp/id_ed25519
#   tunnel connected: early-iris-5125
#   Public URL: https://early-iris-5125.127ohoh1.localhost:8443
#   Plan: Free
#   Bandwidth: 100 kB/s
#   Monthly transfer: 500 MB
```

The stack generates a **local development CA** in `./.devtls`. Use it to verify the connection:

```bash
H=early-iris-5125.127ohoh1.localhost        # use the name printed above
curl --cacert .devtls/ca.pem --resolve "$H:8443:127.0.0.1" "https://$H:8443/hello?x=1"
# {"message":"hello from the demo origin", ... "seen_headers":{"X-Forwarded-For":"172.24.0.1","X-Forwarded-Proto":"https", "Traceparent":"00-..."}}
```

That request travelled: caller → HTTPS/HTTP-2 ingress → tunnel (outbound from the client, no inbound port) → the demo origin
on the client container's **loopback**. Try the free-tier limiter (measured: **3.004 s**, expected 3.0 s):

```bash
curl --cacert .devtls/ca.pem --resolve "$H:8443:127.0.0.1" -o /dev/null -w '%{size_download} bytes in %{time_total}s\n' "https://$H:8443/bytes/500000"
```

### A premium (reserved, paid) name, with simulated payment

From the host (build the CLI once with `make build`). A local origin on `127.0.0.1:3000` is needed; the bundled one works:

```bash
go run ./cmd/demo-origin &
./bin/127ohoh1 expose http://127.0.0.1:3000 --name myproject --plan tier_2 --yes --simulate-settlement \
    --api http://localhost:8080 --edge localhost:7443 --ca .devtls/ca.pem
# Premium feature: reserved hostname
# Price: 2 USDC/month/name
# Bandwidth: 3 MB/s/name
# Monthly transfer: 100 GB/name
#
# Payment required: devpay:pay_01... (SIMULATED: no real money moves)
# Requesting simulated settlement (development mode)...
# Waiting for settlement...
# Payment confirmed.
# Public URL: https://myproject.127ohoh1.localhost:8443
```

Without `--yes` the CLI prints the offer and **exits with code 4 without paying**. Consent is never implicit.
Underneath, `POST /v1/endpoints/reserve` returned a machine-readable `402` ([contract](docs/payment-protocol.md)).

Other useful commands: `make down` (stop), `go test -race ./...` (all tests), `make faults` (kill/pause real containers),
`docker compose -f deploy/docker/compose.yaml --profile multi-edge up -d edge-2` (second edge with Redis-backed routing).
Grafana (anonymous viewer) is at `http://127.0.0.1:13001`, Prometheus at `http://127.0.0.1:19090`.

## CLI

```text
127ohoh1 expose URL [--name NAME --plan tier_1|tier_2|tier_3] [--yes] [--simulate-settlement]
127ohoh1 endpoints list | create | inspect ID | delete ID
127ohoh1 plans list
127ohoh1 identity show | import PATH
127ohoh1 dashboard [--no-open]               # one-time sign-in link to the web dashboard (hosted service)
127ohoh1 link                                # code to link this key to an existing account (hosted service)
127ohoh1 payments simulate PAYMENT_ID        # development servers only
127ohoh1 version
```

Stable exit codes: `0` ok · `1` failure · `2` usage · `3` authentication/identity · `4` payment required/declined · `5` network.
The Ed25519 identity lives in `~/.config/127ohoh1/id_ed25519` (mode `0600`; never printed or transmitted). Origins must be
`http://` on loopback unless you pass `--unsafe-allow-non-loopback-origin`.

## Plans (exact units)

Decimal SI: **1 kB = 1,000 bytes, 1 MB = 1,000,000, 1 GB = 1,000,000,000**. A month is an explicit UTC `[period_start, period_end)`.
Metered bytes = HTTP body bytes in both directions, counted once ([rule](docs/architecture.md#metering-rule-single-documented-layer)).

| Plan | Price | Sustained bandwidth per name | Transfer / month per name | Hostname |
|---|---:|---:|---:|---|
| Free | 0 | 100,000 bytes/s | 500,000,000 bytes | random; released after 24 h without an active tunnel |
| Tier 1 | 1 USDC/month/name | 1,000,000 bytes/s | 10,000,000,000 bytes | reserved while entitled |
| Tier 2 | 2 USDC/month/name | 3,000,000 bytes/s | 100,000,000,000 bytes | reserved while entitled |
| Tier 3 | 4 USDC/month/name | 5,000,000 bytes/s | 500,000,000,000 bytes | reserved while entitled |

Burst is two seconds of the sustained rate. The table is asserted verbatim by tests (`TestCanonicalPlansExact`, `TestPlansEndpointExactValues`).

## Architecture in one screen

```text
 client (Ed25519) ──▶ control plane: identity · endpoints · plans · offers · payments · entitlements · policy · usage ledger
    │  outbound TLS 1.3 tunnel                  ▲ resolved policy (limits + state only)   │ usage batches (idempotent)
    ▼                                           │                                          ▼
 edge (data plane): ingress (TLS, Host/SNI) · tunnel registry · policy cache · token bucket · metering
    ▲
 public caller ── HTTPS ──▶ ingress
```

The control plane decides; the edge enforces and **never learns about money**. Details, trust boundaries and degraded modes:
[docs/architecture.md](docs/architecture.md).

## What is implemented, reference-only, or product-only

| Capability | This repository | Private product (separate) |
|---|---|---|
| Tunnel protocol and client | **Complete**: framing, multiplexing, flow control, keepalive, GOAWAY, reconnect | production hardening, release builds |
| Edge proxy and limiter | **Complete** single and multi-edge (optional Redis) development path | global deployment, capacity policy |
| Identity and endpoint API | **Complete** basic implementation | recovery, risk controls, accounts |
| Plans → policy | **Exact canonical constants** | effective-dated catalog |
| HTTP 402 schema | **Complete and interoperable** | real offers and payment requests |
| Payments | **Simulation only** (`Mock`/`Development`, fails closed) | real adapter, confirmations, reorgs, reconciliation |
| Entitlements | demo grant and expiry | renewal, upgrade/downgrade, grace, repair |
| Usage | correct idempotent reference ledger | durable aggregation, reconciliation |
| Abuse | intake contract and manual hook | detection, case management |
| UI | CLI, API, Grafana dashboard | customer dashboard, operator console |
| Infrastructure | Docker Compose, examples | IaC, SLOs, DR, secrets |

Not built here on purpose: real settlement, wallet custody, chain integration, production pricing/discount rules, automated renewal/refunds,
abuse heuristics, DNS provider credentials, global routing, private dashboards and thresholds. Postgres is provisioned and a schema exists
(`migrations/`), but the reference control plane uses **in-memory stores** (state is lost on restart).

## Security and abuse: what to know

- Identity is cryptographic (Ed25519 challenge-response, single-use nonces, channel-bound tunnel proofs); a **stolen key is the identity**.
- The edge terminates TLS and sees tenant traffic in plaintext; SNI must equal Host; forwarded headers from callers are never trusted.
- The client refuses to be an open proxy: fixed origin host, loopback-only by default, no redirects, checked at dial time.
- HTTP only: no CONNECT, WebSocket/upgrade, raw TCP/UDP, or custom domains.
- Abuse: public intake endpoint (rate limited, sanitised, never fetches reported URLs) plus admin suspension hooks; **no automated detection**.
  Terms/AUP pages are not included; a hosted service needs qualified legal review.
- Full analysis and residual risks: [docs/threat-model.md](docs/threat-model.md). **No penetration test has been performed.**
- Dependency scanning: the module has zero third-party Go dependencies; `govulncheck` is clean on go1.26.6+ (it reported 18 standard-library
  issues on go1.26.0, so `go.mod` pins `toolchain go1.26.8`). See [benchmarks/results](benchmarks/results/2026-09-21-i7-1165g7-laptop.md).

## Measured claims (reproducible)

On a laptop-class machine (i7-1165G7, loopback, load generator sharing the CPU), Go 1.26.0:

| Claim | Result |
|---|---|
| 10,000 idle authenticated tunnels held open | reached; 1.6 GB RSS for both ends + control plane (≈ 163 KB/tunnel), 0.127 cores idle, established in 7.0 s |
| Added median latency of one proxied request (concurrency 1) | ≈ 125 µs (161-174 µs vs 35-37 µs direct) |
| Bulk throughput through the proxy | 416-455 MB/s (1 stream), 612-659 MB/s (8 streams), request + response bytes |
| Free-tier limiter accuracy | 500 kB in 3.004 s (expected 3.0 s); aggregate rate held within ±0.05% at any stream count |
| Quota overshoot after an edge handoff | worst case 1.22-1.25 MB, equal (± a few kB) to the usage the old edge had counted but not reported; < 9 kB when flushed before the handoff |

Methodology and limitations: [benchmarks/methodology.md](benchmarks/methodology.md). Raw results: [benchmarks/results/](benchmarks/results/).

## Testing

```bash
make all               # gofmt check, vet, race-detector tests
make fuzz              # 13 fuzz targets, 10 s each (found and fixed a money-parsing overflow)
make vuln              # govulncheck
make staticcheck
make test-redis        # directory contract against a real Redis (docker)
make bench             # micro + request benchmarks;  make bench-idle N=10000
make faults            # fault injection against the running Compose stack
```

Unit, protocol, integration, failure and architecture tests all run under `-race`: authentication replay and wrong keys, concurrent
streams, flow control and backpressure, cancellation, slow/dying origins, reconnects, control-plane outage with cached policy, suspension,
exact tier limits, bandwidth and quota enforcement, duplicate usage and settlement, 24 h name release, certificate rotation, multi-edge routing.

## Documentation

| Document | Contents |
|---|---|
| [architecture.md](docs/architecture.md) | components, trust boundaries, control/data split, degraded modes |
| [tunnel-protocol.md](docs/tunnel-protocol.md) | frames, handshake, state machine, flow control, compatibility |
| [payment-protocol.md](docs/payment-protocol.md) | the 402 contract, offers, payment states, idempotency, dev-only behaviour |
| [threat-model.md](docs/threat-model.md) | assets, actors, threats, mitigations, residual risks |
| [failure-model.md](docs/failure-model.md) | invariants, recovery, data-loss bounds, retry safety |
| [operations.md](docs/operations.md) | deployment, TLS/ACME, rotation, drain, suspension, debugging, known limitations |
| [docs/adr/](docs/adr/) | decisions (language/transport, wildcard TLS, control/data split, policy snapshots, Redis directory, usage batching, boundary, telemetry) |
| [postmortem](docs/postmortems/2026-09-synthetic-quota-overshoot-on-edge-handoff.md) | a synthetic, reproducible incident |
| [api/openapi.yaml](api/openapi.yaml) | control-plane API (OpenAPI 3.1) |

## Repository layout

`cmd/` binaries · `controlplane/` domain services and API · `dataplane/` edge · `client/` CLI and tunnel client · `protocol/` shared wire contracts
· `internal/` shared plumbing · `benchmarks/` · `deploy/docker/` · `docs/` · `tests/` (integration, failure, architecture) · `migrations/` · `api/`.
The data plane never imports the control plane (enforced by `TestDataPlaneDoesNotImportControlPlane`).

## Roadmap and non-goals

**Known gaps in this reference:** PostgreSQL-backed stores; OTLP trace export; upgrade/downgrade and renewal flows; a second protocol transport (QUIC)
behind the existing session seam; independent security review; longer soak testing.

**Non-goals of the public reference:** raw TCP/UDP/SSH/SOCKS/CONNECT forwarding, WebSocket support, custom customer domains, a browser UI or
billing dashboard, real crypto settlement or multiple networks, automatic renewal/refund/reconciliation, global multi-region operation,
zero-downtime migration of in-flight streams between edges, and Kubernetes as a prerequisite.

## License

MIT (see [LICENSE](LICENSE)).
