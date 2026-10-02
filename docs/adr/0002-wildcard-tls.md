# ADR 0002: One wildcard certificate for the base domain

Status: accepted

## Decision
A single certificate covers `127ohoh1.com` and `*.127ohoh1.com`, obtained via ACME DNS-01. We never request a certificate per random subdomain.

## Rationale
- Per-name certificates would leak every hostname into Certificate Transparency logs and would put ACME latency and rate limits on the endpoint-creation path.
- Wildcard keeps ingress certificate handling independent of endpoint lifecycle.

## Consequences
- The private key protects all tenants; it is held only by ingress and rotated atomically (`CertificateProvider` returns a fresh `tls.Certificate` per handshake).
- Ingress must enforce SNI == Host itself, because the certificate cannot.
- Custom customer domains are out of scope.
