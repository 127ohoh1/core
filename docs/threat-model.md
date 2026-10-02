# Threat model

> **Status:** written by the authors from the code. It has **not** been reviewed by
> an independent party and no penetration test has been performed. Treat every
> mitigation below as "implemented and tested here", not "proven secure".

## 1. Assets

| Asset | Why it matters |
|---|---|
| Client Ed25519 private key | Sole authority over an identity's endpoints |
| Control-plane signing key | Forges session and tunnel credentials for anyone |
| Edge TLS private key (wildcard) | Impersonates every tenant hostname |
| Edge service token / admin token | Reads policy, reports usage, suspends endpoints |
| Tenant traffic (bodies, headers) | Confidentiality and integrity of customers' applications |
| Endpoint ownership and names | Availability and reputation of a customer's URL |
| Usage ledger, entitlements | Fair use and (in a product) revenue |
| Audit log | Accountability for security-sensitive mutations |

## 2. Actors

Anonymous public caller · malicious tenant (owns endpoints, runs an origin) · other
tenant · network attacker between client and edge · compromised origin behind a client ·
operator (admin token holder) · a compromised edge process · a compromised control plane.

## 3. Trust boundaries

1. Public Internet → ingress (fully untrusted input).
2. Client → edge over TLS 1.3 (authenticated, scoped, but the *tenant* is not trusted).
3. Edge ⇄ control plane (service credential; the edge is trusted to enforce, not to decide).
4. Edge → client → origin (the client is trusted by its owner only; the origin is trusted by nobody else).
5. Operator → admin API (separate secret, audited).

## 4. Threats, mitigations, residual risk

Each mitigation names the test that exercises it.

### Identity and authentication

| Threat | Mitigation | Residual risk |
|---|---|---|
| **Stolen client private key** | Key is stored `0600` under a `0700` directory, never printed or transmitted; loading refuses group/other-readable files; an identity file is never overwritten (`client/identity` tests). Endpoint credentials are short-lived (2 min) and scoped to one endpoint. | A stolen key **is** the identity: the thief can create and use endpoints and read what the owner can. There is no key revocation or account recovery in the public reference (private product: device linking, recovery, cooling period). Protect the file like an SSH key. |
| **Authentication replay** | Challenges are single use, expire in 60 s, bind a ≥128-bit nonce, audience and key fingerprint in a canonical, domain-separated, length-prefixed signing input; consumed *before* the signature is checked so a failed attempt burns it (`identity_test`: replay, expiry, wrong key, concurrent consume). Tunnel proofs are bound to the TLS exporter and a per-connection nonce (`TestTunnelAuthReplayRejected`). | None known beyond clock assumptions (challenge/credential expiry uses server time; 5 s skew tolerated). |
| **Raw public key used as a credential** | Public keys/fingerprints only identify; possession is always proven. | — |
| **Registration spam / namespace exhaustion** | Per-IP rate limit on challenge/session (`TestChallengeRateLimit`), per-principal endpoint cap, bounded challenge store, free names released after 24 h idle, random names with entropy plus authoritative uniqueness (`TestPerPrincipalCap`, `TestCollisionRetriesBoundedly`). | An attacker with many source IPs can create many principals; per-IP limits use the TCP peer (forwarded headers are not trusted) so a shared NAT can be rate limited together. Production anti-abuse is private. |

### Tunnel and routing

| Threat | Mitigation | Residual risk |
|---|---|---|
| **Tunnel hijacking** (attach to someone else's endpoint) | Credential signed by the control plane, scoped `{principal, endpoint, edge audience, type=tunnel, jti, exp}`, verified locally; proof of possession of the embedded key; `REGISTER_ENDPOINT` must match the credential; admission checks lifecycle (`TestTunnelRejectsWrongKey`, `…ExpiredAndForeignCredentials`, `TestPreIssuedCredentialRefusedForSuspendedEndpoint`). | A compromised **signing key** forges everything; rotation procedure in `operations.md` (`TestSigningKeyRotationOverlap`). |
| **Duplicate/stale sessions** | New session supersedes old (GOAWAY + bounded drain); superseded session cannot evict its successor; leases expire (`TestDuplicateSessionSupersedesOld`, directory contract). | Partition windows: cross-edge supersede is best-effort until the lease heartbeat re-syncs (documented, tested degraded mode). |
| **Hostname takeover / stale-link takeover** | Released names are tombstoned for others (previous owner may recover); expired reserved names are held through a recovery window; offers are not issued for tombstoned names (`TestCheckNameRespectsTombstoneForOthersOnly`, `TestEntitlementExpiryAndRelease`). | Free names *are* released after 24 h idle by design; old links to them can later resolve to a different tenant. The random suffix limits targeted re-registration but does not make it impossible. |
| **Cross-tenant routing / data leaks** | Exactly one label under the base domain is routable; SNI must equal Host; routing is by an exact registry key; API objects are owner-scoped and return `404` (not `403`) for others (`TestSNIHostMismatchIsRejected`, `TestCrossTenantIsolation`, `TestOfferAndPaymentOwnership`). | A bug in the multiplexer's stream bookkeeping could mix streams: covered by concurrent-stream integrity tests and race testing, not by formal verification. |
| **Compromised edge** | The edge holds the wildcard key and sees plaintext tenant traffic (TLS terminates there), the service token, and cached policies. It cannot mint credentials (no signing key), cannot see payment data, and usage batches are attributable to an edge id. | A compromised edge can read/alter traffic it serves and misreport usage. Mitigations belong to deployment (isolation, least privilege, per-edge credentials, mTLS between edges) and are not in the reference. |
| **Compromised control plane** | Can issue credentials and policies for anyone. | Same as above; audit log and admin separation help detection only. |

### Public-facing input

| Threat | Mitigation | Residual risk |
|---|---|---|
| **Request smuggling / header ambiguity** | HTTP parsing is Go's `net/http` (strict); requests are re-serialised from a validated metadata object, never byte-forwarded; hop-by-hop headers stripped incl. `Connection`-named ones; `Transfer-Encoding` removed; metadata rejects CR/LF/NUL and non-token names (`FuzzDecodeRequestMeta`, `TestStripHopByHop…`). | The origin's own HTTP implementation sees a clean HTTP/1.1 request from the client. |
| **Spoofed forwarding/trace headers** | Client-supplied `Forwarded`, `X-Forwarded-*`, `X-Real-Ip`, `Via`, `Traceparent`, `Tracestate` are dropped; the edge sets values from the TCP peer; external trace ids kept for correlation only (`TestClientSuppliedForwardingHeadersAreNotTrusted`). | Inter-edge hop trusts `X-127ohoh1-Client-Ip` from an authenticated peer edge only. |
| **Origin impersonating the platform** | `X-127ohoh1-*` response headers from origins are stripped so platform errors stay distinguishable. | — |
| **Oversized frames / memory exhaustion** | Declared length checked against a configured cap **before** allocation; bounded queues, windows, stream counts, metadata size; keep-alive detects dead peers (`TestNoAllocationFromUntrustedLength`, `FuzzReadFrame`, flow-control tests). | Very large numbers of *authenticated* sessions cost ~160 KB each (measured, `benchmarks/`); capped by `max_sessions`. |
| **Slowloris / idle connections** | Read-header timeout, idle timeouts, total request duration, handshake deadlines, write deadlines (`TestSlowlorisHeaderTimeout`, tunnel garbage tests). | Application-layer slow-body attacks are bounded by duration and body limits, not eliminated. |
| **Malicious public caller (DoS)** | Per-endpoint concurrency cap, stream cap per session with `503 tunnel_busy`, bandwidth bucket, quota, header/body limits; ingress never blocks unrelated tenants behind one stalled stream (`TestStalledStreamDoesNotBlockOthers`, `TestStreamLimitYieldsTunnelBusyNotCrash`). | Volumetric attacks need network-level protection outside this repository. |
| **Websocket/CONNECT abuse** | Upgrades → `501`, `CONNECT` → `405`; no raw TCP/UDP tunnelling. | — |

### Client-side misuse

| Threat | Mitigation | Residual risk |
|---|---|---|
| **SSRF / open proxy through the client** | Origin host fixed at startup; the request target supplies path and query only; loopback only unless an explicit unsafe flag; checked on the *resolved address at dial time* (DNS rebinding); redirects not followed; only `http://` (`TestRequestTargetCannotChangeOriginHost`, `client/origin` tests). | With the unsafe flag the user chooses the host; that is their decision. |
| **Malicious/compromised origin** | Response metadata re-validated; hop-by-hop stripped; sizes bounded; mid-response failure aborts the connection instead of faking completion (`TestOriginClosesMidResponseIsNotSilentlyTruncated`). | An origin controls its own content: XSS/phishing hosted on a tunnel is an *abuse* problem, handled by intake + suspension hooks, not by the proxy. |

### Commercial and policy

| Threat | Mitigation | Residual risk |
|---|---|---|
| **Payment-event replay / double grant** | Settlement is state-driven under a per-payment lock; event ids bind to one payment; entitlement is unique per settlement; mismatches fail the payment (`payment_test`, `TestSimulatedSettlementGrantsOneEntitlementIdempotently`). | The reference verifier is a mock; real verification (chain finality, reorgs) is out of scope. |
| **Simulation reachable in production** | Three independent gates (config validation, mock-verifier constructor, handler check); disabled path returns `404` (`TestProductionCannotEnableSimulation`, `TestSimulationFailsClosedWhenNotEnabled`, `TestMockVerifier`). | A code change removing all three. |
| **Stale permissive policy** | Versions monotonic; non-active states applied on receipt; validity + bounded stale grace then fail closed; suspension via change feed drops live tunnels (`policycache` tests, `TestEstablishedTunnelSurvives…`, `TestSuspensionTerminatesTunnel…`). | Between a policy change and delivery, a revoked endpoint keeps working: ≈ feed latency when the control plane is reachable, up to `valid_until` + grace when not (configurable trade-off, ADR 0004). |
| **Quota evasion via reconnects/concurrency** | One shared bucket and one meter per endpoint regardless of streams or sessions; usage attributed to the endpoint, not the connection; quota state pushed to all edges on exhaustion (`TestConcurrencyDoesNotMultiplyBandwidth`, `TestQuotaExhaustedMidStreamTerminatesConsistently`). | Multi-edge overshoot bound documented in `failure-model.md` and reproduced in `TestTwoEdgesQuotaOvershootIsBounded`. |

### Secrets and telemetry

| Threat | Mitigation | Residual risk |
|---|---|---|
| **Log / trace leakage** | Key-based redaction (`authorization`, `token`, `secret`, `signature`, `cookie`, `proof`, `payment_request`, `nonce`, `query`…); requests are logged without path or query; bodies never logged (`TestLoggerRedactsSensitiveKeys`, `TestRequestIsDiagnosableAndLogsAreRedacted`). | Redaction is by key name; a new field with an unusual name would not be caught. Reviewing new log fields is a code-review duty. |
| **Compromised service credentials** | Constant-time comparison; separate admin token; admin API absent unless configured; every admin action audited. | Shared static bearer secrets are development-grade. Production should use per-service workload identity/mTLS, rotation and least-privilege database roles. |
| **Certificate misissue / bad rotation** | Replacement validated before use; previous certificate kept on failure (`TestCertificateRotationWithoutDroppingTunnels`). | ACME account and DNS credentials are operational assets outside this repository. |

## 5. Explicit non-mitigations

Volumetric DoS, BGP/DNS attacks, malicious content hosted on tunnels (only reporting + manual suspension), legal/compliance obligations, multi-region failure, insider threats with database access, side channels, supply-chain compromise of the Go toolchain. Dependency policy: the module has **no third-party Go dependencies**; `govulncheck` and static analysis results are recorded in `benchmarks/results/` next to the benchmark run that used the same toolchain.
