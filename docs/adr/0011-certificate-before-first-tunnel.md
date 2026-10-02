# ADR 0011: Certificates for paid names before their first tunnel

**Status:** accepted (repository owner, 2026-10-02) · **Context:** ADR 0009 (HTTP-01 on-demand certificates).

## Problem

ADR 0009 issues a certificate the first time a hostname is dialled, and only for a name with a live tunnel. That check closes an unauthenticated-issuance DoS: without it, spraying random SNI names could spend Let's Encrypt's per-domain rate limit. The cost is that the first visitor of a newly paid name waits several seconds for an ACME issuance, and the control plane can't fetch the certificate in advance, because no tunnel exists right after payment.

## Decision

The edge also issues for a label the control plane confirms is an **active reserved name**, meaning a paid one:

- New edge-service route **`GET /v1/hostnames/{label}`** returns `{endpoint_id, kind, state}`. The `state` is the endpoint's resolved policy state, so suspension and expiry count. An unknown label is a 404. The route needs the edge service credential.
- `HostnameStatus.CertificateIssuable()` is true only for `kind == "reserved"` with `state == active`. Random (free) names still need a live tunnel.
- `cert.IssuanceGate` is the edge's issuance check: a live tunnel, **or** a control-plane confirmation.
  - Lookups for labels without a tunnel are bounded. A refused label is remembered for a minute, and at most 2 lookups per second (burst 10) go out.
  - So sprayed names never trigger an issuance and can't flood the control plane. At worst they delay a brand-new paid name until the next attempt.

A deployment can now warm a paid name's certificate right after payment with a TLS handshake for that name. The hosted service does this; see its ADR 0022.

## Not changed

Free names, the shape check for the port-80 handler, and every existing certificate are unaffected.
