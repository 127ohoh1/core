# ADR 0009: On-demand HTTP-01 certificates, deviating from ADR 0002

Status: accepted

## Decision
For the 127ohoh1.com deployment, the edge issues certificates on demand via ACME HTTP-01 (`dataplane/cert.Autocert`) instead of the single wildcard DNS-01 certificate ADR 0002 called for. Each accepted hostname — the base domain, `www.`, any single tenant label under it, and the fixed `tunnel.` control hostname — gets its own certificate the first time it is dialled, cached to disk and renewed automatically.

## Rationale
ADR 0002's wildcard requires an ACME DNS-01 challenge, which needs an automatable DNS provider API. This domain's registrar (an InterNetX/AutoDNS reseller) offers none to this deployment, and no DNS credentials were available. Repository owner's decision (2026-10-01): use standard HTTP-01 rather than pursue DNS credentials or a delegated zone.

## Consequences
- ADR 0002's stated tradeoffs are given up deliberately: every tenant hostname is now individually visible in Certificate Transparency logs, and endpoint creation can incur first-use ACME latency (mitigated: the client already retries the tunnel dial with backoff).
- `CertificateProvider` absorbed the change with no interface break — `Autocert` implements the same `GetCertificate`/`NotAfter` contract as `File`. ADR 0002's SNI==Host enforcement in ingress is unaffected either way.
- Two edge replicas sharing one Autocert cache volume, with ACME HTTP-01 challenges for tenant/tunnel hostnames pinned to edge-1 only, avoids a validation-routing race; see the product repository's `docs/adr/0018-http01-autocert-and-haproxy.md` for the full deployment-side reasoning (HAProxy routing, port budget, ohohcp's separate Autocert instance).
- If DNS credentials become available later, swapping back to a DNS-01 client is a `CertificateProvider` replacement, not an architecture change.
