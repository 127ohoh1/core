# ADR 0001: Go, and TLS over TCP with an application-level multiplexer

Status: accepted

## Context
The system needs a concurrent network service (edge), a small HTTP API (control plane) and a portable CLI. The tunnel needs multiplexed streams with half-close, per-stream and per-connection flow control, and cancellation.

## Decision
- Go (1.24+) for every component; the standard library is preferred over frameworks.
- The tunnel is TLS 1.3 over a single TCP connection carrying a small length-delimited binary frame protocol (see `docs/tunnel-protocol.md`). Control payloads are JSON; DATA and WINDOW_UPDATE payloads are raw/binary.
- TLS 1.3 gives us an exporter secret, used to channel-bind the client's proof of possession to the connection.
- QUIC is a later milestone behind a `Transport` seam; it is not a prerequisite.

## Consequences
- We own head-of-line behaviour of one TCP connection: mitigated by per-stream windows and a bounded write queue.
- HTTP/2 was considered for the tunnel; a bespoke framing gives explicit control of stream states, GOAWAY drain semantics and flow-control windows that are easier to test and fuzz, at the cost of writing the multiplexer.
- Zero third-party dependencies in the core keeps the supply-chain surface small.
