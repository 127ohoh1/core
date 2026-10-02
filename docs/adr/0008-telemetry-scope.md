# ADR 0008: Telemetry scope of the public reference

Status: accepted

## Context
The specification asks for OpenTelemetry traces and metrics, structured logs, Prometheus-compatible metrics and W3C trace propagation.
An OTLP exporter pulls in a large dependency tree (SDK, protobuf, gRPC/HTTP exporters) into every binary.

## Decision
- **Metrics:** a small in-repo registry emitting the Prometheus text format directly; no client library.
- **Logs:** `log/slog` JSON with stable event names, correlation fields and key-based redaction.
- **Traces:** W3C `traceparent` is parsed, validated and propagated across ingress -> tunnel -> origin using an explicit allowlist; a caller's trace id is kept for correlation while its span id is never trusted. Trace ids appear in logs and response-adjacent headers. **No OTLP exporter is included.**

## Consequences
- The module has zero third-party Go dependencies, which keeps the vulnerability surface to the standard library (scanned; see `benchmarks/results/`).
- Operators get full request diagnosability from logs and metrics today; wiring an OTel SDK is an additive adapter behind the existing trace-context type and does not change the wire contract.
- This is a documented gap against the specification's wording, not an oversight.
