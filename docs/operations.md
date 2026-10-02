# Operations guide

> The public reference implementation is **not production-ready** (see README). This
> guide documents how the reference behaves and how the pieces are meant to be
> operated; production infrastructure, alert thresholds, DNS credentials and
> topology are intentionally not part of this repository.

## 1. Running it

```bash
make up                 # docker compose up --build (control plane, edge, demo origin+client, postgres, redis, prometheus, grafana)
make down               # stop and remove volumes
go test -race ./...     # unit + integration + failure tests
```

Host ports (all bound to 127.0.0.1, overridable):

| Service | Default | Variable |
|---|---|---|
| Control plane API | 8080 | `OHOH_CP_PORT` |
| Control plane metrics | 19101 | `OHOH_CP_METRICS_PORT` |
| Edge public ingress (HTTPS) | 8443 | `OHOH_INGRESS_PORT` |
| Edge tunnel listener | 7443 | `OHOH_TUNNEL_PORT` |
| Edge admin (`/healthz`, `/readyz`, `/metrics`) | 19100 | `OHOH_EDGE_ADMIN_PORT` |
| Prometheus / Grafana | 19090 / 13001 | `OHOH_PROM_PORT` / `OHOH_GRAFANA_PORT` |

The stack generates a local CA in `./.devtls`. Trust `./.devtls/ca.pem` (or pass it to
`curl --cacert` / the CLI `--ca`).

## 2. Configuration

Typed, validated, JSON file (`-config`) plus environment overrides (`OHOH_*`, env wins).
Startup **fails** (non-zero exit) on missing or inconsistent configuration; there is no
silent insecure fallback. See `.env.example` and `internal/config`.

Development gates are explicit, loudly logged, and **refused when `app_env=production`**:
`development_payments`, `ingress_plain_http`, generated dev TLS, ephemeral signing key.

**Request duration model.** Three independent knobs govern one proxied exchange
(`request_max_duration`, `request_idle_timeout`, `response_header_timeout`), and only one
of them is a flat wall-clock cap:

- `request_max_duration` bounds opening the tunnel stream only — a fast, bounded operation
  with no activity to watch. It does **not** limit how long a request/response body, or an
  upgraded (WebSocket) connection, may run once bytes start flowing.
- `request_idle_timeout` is the real duration control for everything after that: it ends an
  exchange only after *no progress in either direction* for that long, shared across the
  request body, the response body, and (for an upgrade) both directions at once. A
  long-lived but active exchange — an SSE feed, a long-poll response, a large download, a
  WebSocket connection — is never cut off while it keeps making progress; raise this value
  to tolerate a slower origin, not `request_max_duration`.
- `response_header_timeout` bounds only the wait for the origin's first byte (zero activity
  since the stream opened); raise it to support a slower long-poll before the origin has
  anything to send.

## 3. TLS and certificates

One certificate covers `127ohoh1.com` and `*.127ohoh1.com`; no per-name certificates
(ADR 0002). The edge reads `cert_file`/`key_file` through a `CertificateProvider` that
hands the current certificate to each handshake (`dataplane/cert`).

**DNS.** Point `*.127ohoh1.com` (and the apex) at the ingress address.

**Issuance (ACME DNS-01).** Use any ACME client that supports DNS-01 for the wildcard
(the reference intentionally embeds no ACME client and no DNS-provider credentials).
Run it outside the edge with credentials scoped to `_acme-challenge.127ohoh1.com` only,
and have it write `cert.pem`/`key.pem` **atomically** (write temp file, then rename; the
key file mode `0600`). Renew well before expiry (for example at 30 days remaining).

**Rotation.** The edge detects a replaced file pair (poll every `cert_reload_interval`)
or on `SIGHUP`, then validates it before use: it must parse, be currently valid, and
cover both the apex and a tenant name. A bad replacement is **rejected and the previous
certificate keeps serving** (`edge_certificate_reloads_total{result="error"}`, an
error log). Established tunnels and in-flight requests are unaffected; new handshakes
(ingress *and* tunnel) use the new certificate. Alert on
`edge_certificate_expiry_seconds` well before it reaches zero, and on reload errors.

**Access.** Only the edge process (and the certificate manager) can read the private
key. Do not bake it into images.

## 4. Key rotation (tunnel and session credentials)

Credentials are Ed25519-signed tokens verified locally by edges against the key set
published at `GET /v1/keys` (multiple key ids may be live).

```bash
control-plane -keygen new.key            # prints kid, public key and a previous_verify_keys entry
control-plane -pubkey current.key        # same, for the key being retired
# 1. deploy control plane: signing_key_file=new.key, previous_verify_keys="<kid>=<pub of the retired key>"
# 2. wait longer than session_ttl and tunnel_credential_ttl (defaults 15 min / 2 min)
# 3. redeploy without previous_verify_keys
```

Edges refresh the published set periodically and immediately (rate limited) when they
see an unknown `kid`, so no edge restart is needed. Tested: `TestSigningKeyRotationOverlap`.
Emergency revocation of a compromised *signing key*: publish only the new key; all old
credentials die at the edges within one key-refresh interval (tunnels already established
stay up until they reconnect or policy revokes them).

## 5. Background work

| Loop | Where | Interval | Notes |
|---|---|---|---|
| Free-name reaper, entitlement sweep, offer/payment expiry, expired-reserved release | control plane | `reaper_interval` (1 m) | idempotent; safe to run on one instance |
| Policy refresh + change feed | edge | `policy_refresh` (30 s) + long-poll | metrics: `edge_policy_*` |
| Usage flush | edge | `usage_flush` (1 s) | metrics: `edge_usage_*` |
| Presence heartbeat | edge | 20 s | drives the 24 h free-name clock |
| Certificate watch | edge | `cert_reload_interval` | see §3 |

## 6. Suspension, revocation, emergency

Admin hooks exist only when `admin_token` is set (otherwise `404`); all are audited with
a reason.

```bash
A="Authorization: Bearer $OHOH_ADMIN_TOKEN"
curl -X POST -H "$A" -d '{"reason":"abuse case 42"}' $CP/v1/admin/endpoints/$EP/suspend
curl -X POST -H "$A" $CP/v1/admin/endpoints/$EP/unsuspend
curl -X POST -H "$A" $CP/v1/admin/principals/$PR/suspend      # every endpoint of a principal
curl -X POST -H "$A" -d '{"enabled":true}' $CP/v1/admin/emergency   # global safety override
```

Suspension precedence is total: it beats any entitlement. It reaches edges through the
change feed; the edge drops the live tunnel and refuses re-admission. Verified:
`TestSuspensionTerminatesTunnelAndBlocksReconnect`.

## 7. Health, drain, shutdown

- `GET /healthz` — **liveness**: fails only if an internal loop stalled. It does *not*
  fail when the control plane is down (a restart would not help and would drop tunnels).
- `GET /readyz` — **readiness**: edge is ready once it holds signing keys and is not
  draining; the control plane reports its own checks.
- `SIGTERM`/`SIGINT` graceful shutdown order: readiness goes false → stop accepting
  public requests and wait for in-flight ones → tunnels receive `GOAWAY` and drain
  (bounded) → **usage is flushed** → final presence → listeners and workers stop.
  Bounds: `shutdown_grace`, `drain_timeout`.
- Rolling deploy: remove the edge from load balancing on `/readyz`, wait for drain, replace.
  Clients reconnect (GOAWAY-aware, with jittered backoff) to another edge.

## 8. Observability

Structured JSON logs (stable `event` names, correlation fields `request_id`, `trace_id`,
`endpoint_id`, `edge_id`, `tunnel_session_id`, `error_code`, `duration_ms`, `bytes_in/out`).
Never logged: private keys, bearer tokens, signatures, payment proofs, cookies, query
strings or paths, bodies (enforced by key-based redaction and tested).

Metrics (Prometheus text): `edge_tunnel_sessions_active`, `edge_tunnel_auth_*`,
`edge_streams_active`, `edge_ingress_requests_total{status_class,platform_error}`,
`edge_ingress_request_duration_seconds` (p50/p95/p99 via histogram),
`edge_proxied_bytes_total{direction}`, `edge_bandwidth_throttle_seconds_total`,
`edge_quota_exhausted_total{phase}`, `edge_policy_cache_requests_total{result}`,
`edge_policy_stale_use_total`, `edge_policy_max_version`, `edge_control_plane_reachable`,
`edge_usage_*`, `edge_certificate_*`, `cp_http_*`, `cp_auth_failures_total{reason}`,
`cp_free_endpoints_reaped_total`, and `process_goroutines|heap|open_fds`.

Trace context: W3C `traceparent` is propagated ingress → tunnel → origin using an
explicit allowlist. A caller's trace id is kept for correlation but its span id is never
trusted; `tracestate`/`baggage` are dropped. **OpenTelemetry export (OTLP) is not
implemented in the public reference**: trace ids appear in logs and headers, and an OTLP
exporter is a future adapter. Metrics are exposed in the Prometheus format directly.

A dashboard is provisioned in the Compose stack (`deploy/docker/grafana/dashboards`).

## 9. Debugging one request

1. Take `X-Request-Id` from the response (and the platform error header
   `X-127ohoh1-Error`, if any). Platform-generated responses are always marked; an
   origin cannot forge that header.
2. Find `ingress.request` with that `request_id` on the edge: status, endpoint, bytes,
   duration, trace id.
3. Use the `trace_id` to find the origin's own logs (the origin receives `traceparent`).
4. Check `edge_policy_cache_requests_total`, `edge_control_plane_reachable` and
   `edge_usage_batches_pending` if behaviour looks policy- or quota-related.

Platform errors: `unknown_host`, `bad_host`, `misdirected_request` (SNI ≠ Host),
`endpoint_not_found`, `tunnel_offline|lost|busy`, `origin_unreachable`, `origin_timeout`,
`bad_origin_response`, `quota_exhausted`, `endpoint_suspended|expired`,
`policy_unavailable|expired`, `too_many_requests`, `request_headers_too_large`,
`request_body_too_large`, `method_not_allowed`.

The body format depends on the caller. API clients get the JSON envelope
(`{"error":{"code","message","request_id"}}`). A browser (`Accept` contains
`text/html`) gets a short HTML page written for the site's visitor, with the
code and request id in small print (`dataplane/ingress/errorpage.go`). Status
code and `X-127ohoh1-Error` are identical either way, so tooling should key
on those rather than on the body.

## 10. Backups and recovery

The reference control plane keeps state **in memory**; a restart loses principals,
endpoints, offers, payments, entitlements and usage. Consequences and recovery:
clients re-login (the client transparently re-authenticates a stale session once) but
their endpoints no longer exist and must be recreated. `migrations/0001_init.sql`
defines the durable schema a PostgreSQL-backed store must implement (uniqueness of
active hostnames, one entitlement per settlement, one usage batch per id, ...).
Caches (policy, tunnel directory) are always rebuilt from authoritative state and
leases are never restored as live.

## 11. Known limitations (honest list)

- Persistence is `InMemory`; PostgreSQL is provisioned and the schema exists, but there is no Postgres-backed store.
- The multi-edge Redis directory is optional development routing (see README); the default profile is single-edge.
- No OTLP exporter (see §8); no distributed tracing backend in Compose.
- No raw TCP/UDP, no custom domains (explicit non-goals). Any HTTP protocol
  upgrade (WebSocket included) is proxied transparently; see §2's request
  duration model for how long-lived exchanges are bounded.
- No HA control plane; usage/presence are edge→CP pushes to one control plane.
- Dependency scanning, SAST and an external penetration test have **not** been performed; see `threat-model.md`.
