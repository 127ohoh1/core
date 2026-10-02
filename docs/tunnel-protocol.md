# Tunnel protocol (version 1)

The tunnel carries multiplexed HTTP exchanges between an **edge** (server) and a **client** over one outbound-initiated TLS 1.3 connection. Implementation: [`protocol/tunnel`](../protocol/tunnel), handshake helpers in [`protocol/tunnel/handshake.go`](../protocol/tunnel/handshake.go), authentication primitives in [`protocol/auth`](../protocol/auth).

The client always dials the edge. No inbound port is opened at the origin.

## 1. Transport

- TLS **1.3 only** (the proof of possession is channel-bound through the TLS exporter, RFC 8446 §7.5).
- One TCP connection per session. QUIC is a possible later transport behind the same session interface; it is not part of version 1.
- The edge's certificate is validated by the client as usual (development uses a generated CA; see `operations.md`).

## 2. Frames

Every frame has a fixed 12-byte header followed by `length` payload bytes. All integers are big-endian.

```text
 0      1      2      3      4                8                12
+------+------+------+------+----------------+----------------+----------
| ver  | type | flags| rsvd | stream id (u32)| length (u32)   | payload
+------+------+------+------+----------------+----------------+----------
```

| Field | Rules |
|---|---|
| `ver` | Must be `1`. Anything else is a connection error. |
| `type` | See table below. Unknown types are a connection error. |
| `flags`, `rsvd` | Must be `0` in version 1 (reserved for compatible extensions). |
| `stream id` | `0` for connection-scoped frames; non-zero for stream-scoped frames; the high bit is reserved. `WINDOW_UPDATE` may be either. |
| `length` | Checked against the configured maximum (default 64 KiB, hard ceiling 1 MiB) **before** any payload memory is allocated. |

A hostile peer therefore cannot make the decoder allocate more than the configured limit; oversize frames end the connection with `FRAME_SIZE_ERROR` (fuzzed: `FuzzReadFrame`).

### Frame types

| # | Type | Scope | Payload |
|--:|---|---|---|
| 1 | `HELLO` | handshake | JSON (see §3) |
| 2 | `AUTH` | handshake | JSON `{token, jti, proof}` |
| 3 | `AUTH_OK` | handshake | JSON `{session_id, endpoint_id, hostname}` |
| 4 | `AUTH_ERROR` | handshake | JSON `{code, message, retryable}` |
| 5 | `REGISTER_ENDPOINT` | handshake | JSON `{endpoint_id, hostname}` |
| 6 | `REGISTER_OK` | handshake | empty |
| 7 | `OPEN` | stream | request metadata (JSON, §5) |
| 8 | `OPEN_OK` | stream | response metadata (JSON, §5) |
| 9 | `DATA` | stream | 1..`data_chunk` bytes of body (empty DATA is invalid) |
| 10 | `HALF_CLOSE` | stream | empty; sender will send no more DATA |
| 11 | `CLOSE` | stream | empty; graceful full close, sender discards further data |
| 12 | `RESET` | stream | u32 error code |
| 13 | `WINDOW_UPDATE` | stream or conn | u32 increment, `1..2^31-1` |
| 14 | `PING` | conn | u64 opaque token |
| 15 | `PONG` | conn | echoed token |
| 16 | `GOAWAY` | conn | u32 last-processed peer stream id, u32 code |
| 17 | `ERROR` | conn | u32 code + short UTF-8 message (<= 256 bytes) |

### Error codes

`0 NO_ERROR`, `1 PROTOCOL_ERROR`, `2 FLOW_CONTROL_ERROR`, `3 STREAM_CLOSED`, `4 REFUSED_STREAM`, `5 CANCEL`, `6 INTERNAL_ERROR`, `7 FRAME_SIZE_ERROR`, `8 UNAUTHENTICATED`, `9 ENHANCE_YOUR_CALM`, `10 SUPERSEDED`, `11 SHUTDOWN`, `12 QUOTA_EXHAUSTED`, `13 POLICY_REVOKED`, `14 TIMEOUT`.

`RESET` codes are also how the client reports origin problems before any response was sent: `INTERNAL_ERROR` → the edge answers `502 origin_unreachable`, `TIMEOUT` → `504 origin_timeout`.

## 3. Handshake

Handshake frames are exchanged before multiplexing starts, on stream id 0, with payloads capped at 8 KiB and a 10 s overall deadline.

```text
C -> S  HELLO   {"versions":[1],"client":"127ohoh1-cli/0.1"}
S -> C  HELLO   {"version":1,"edge_id":"edge-1","nonce":"<32 random bytes, base64url>","params":{...}}
C -> S  AUTH    {"token":"v1.<kid>.<claims>.<sig>","jti":"tok_...","proof":"<base64url Ed25519 signature>"}
S -> C  AUTH_OK {"session_id":"ts_...","endpoint_id":"ep_...","hostname":"quiet-river-7f2c"}
        or AUTH_ERROR {"code":"invalid_credential","message":"...","retryable":false} + close
C -> S  REGISTER_ENDPOINT {"endpoint_id":"ep_...","hostname":"quiet-river-7f2c"}
S -> C  REGISTER_OK
```

**Version negotiation.** The client lists the versions it speaks; the edge picks one or replies with an `ERROR` naming what it supports. Version 1 is the only version. Frame-header flags and reserved bits allow compatible extensions without a version bump; anything that changes framing or state machines increments the version.

**Session parameters.** The edge dictates `max_frame_payload`, `data_chunk`, `stream_window`, `conn_window`, `max_streams`, ping timings and `max_meta_bytes`. The client rejects values that would make it allocate without bound (`Params.Config`).

**Authentication.** Two independent checks, both must pass:

1. **Credential.** `token` is a control-plane-issued, Ed25519-signed, short-lived credential scoped to `{principal, endpoint, audience=edge, type=tunnel, jti, exp}` and embeds the public key that must prove possession. The edge verifies it **locally** against the cached key set (multiple `kid`s may be live at once, which is how key rotation overlaps). No control-plane call is needed, so tunnels can be (re)established during a control-plane outage as long as the cached policy allows it.
2. **Proof of possession.** `proof` is an Ed25519 signature by the client key over
   `"127ohoh1/tunnel-proof/v1\0" || u16 version || lp(TLS exporter) || lp(server nonce) || lp(jti) || lp(endpoint id)`
   (`lp` = u32 length prefix). The TLS exporter (`EXPORTER-127ohoh1-tunnel-v1`, 32 bytes) and the per-connection nonce bind the proof to *this* connection: a captured `AUTH` message is useless on another connection (tested: `TestTunnelAuthReplayRejected`), and a stolen credential is useless without the private key (`TestTunnelRejectsWrongKey`).

Failure detail is deliberately coarse (`invalid_credential`), retryable only for expiry, capacity and transient policy unavailability.

**Registration.** `REGISTER_ENDPOINT` must match the credential exactly. The edge then claims the endpoint in the tunnel directory. If a live session already owns the endpoint, the new session **supersedes** it (§8).

## 4. Streams

Stream ids: the server opens **odd** ids, the client **even** ids, each strictly increasing. In this deployment the edge opens every stream (one per public HTTP request); the client-initiated half of the id space is reserved. A peer that reuses parity, goes backwards, or sends a frame for an id it never opened is violating the protocol and the connection is closed.

### State machine

```text
                  OPEN(send/recv)
        idle ------------------------> open
                                        |  \
                     HALF_CLOSE(local) /    \ HALF_CLOSE(remote)
                                      v      v
              half-closed(local)          half-closed(remote)
                     |                          |
        HALF_CLOSE(remote)                 HALF_CLOSE(local)
                     \                        /
                      v                      v
                              closed          <---- CLOSE / RESET from any non-idle state
```

`DATA` is legal to send in `open`/`half-closed(remote)` and to receive in `open`/`half-closed(local)`. Anything else is a **stream error**: that stream is reset (`STREAM_CLOSED`); other streams and the connection are unaffected. The pure state machine is table-tested and fuzzed (`FuzzStateMachine`); its properties: illegal events never change state, `closed` is absorbing.

Half-close lets request and response bodies finish independently: the edge half-closes after the request body; the client half-closes after the response body. When both directions are half-closed the stream is finished and no further frame is needed. `CLOSE` ends a stream early and gracefully in both directions; `RESET` aborts with a reason.

### One HTTP exchange

```text
edge:   OPEN{method,target,headers,...}  DATA* ... HALF_CLOSE
client:                                   OPEN_OK{status,headers}  DATA* ... HALF_CLOSE
```

Requests are never replayed automatically. If the session dies, in-flight streams fail with `ErrSessionClosed` and the edge answers `502 tunnel_lost` (or aborts a partially sent response).

## 5. Metadata

`OPEN` carries the request line and headers as JSON, `OPEN_OK` the status and headers. Both are validated on receipt (size, header count, token characters, no CR/LF/NUL, origin-form target only, no `CONNECT`) and fuzzed (`FuzzDecodeRequestMeta`, `FuzzDecodeResponseMeta`). Before encoding, the edge removes hop-by-hop headers and any client-supplied `Forwarded`/`X-Forwarded-*`/`X-Real-Ip`/`Via`/trace headers, then adds its own forwarded values derived from the TCP peer and a fresh `traceparent` (external trace ids are kept for correlation; external span ids are never trusted). Origin responses lose hop-by-hop headers and anything in the reserved `X-127ohoh1-` namespace so that an origin cannot impersonate a platform error.

## 6. Flow control

Credit-based, per stream and per connection, in bytes of `DATA` payload.

- The receiver grants each stream `stream_window` and the connection `conn_window` initially (edge-dictated, default 256 KiB / 4 MiB).
- A sender may not send `DATA` beyond available credit; `Stream.Write` blocks (with cancellation) until credit arrives.
- The receiver returns credit with `WINDOW_UPDATE` as the application *consumes* data, batched at half a window. Data for streams that already finished is still credited back to the connection, so a reset cannot leak connection window.
- Overrunning the **stream** window resets that stream (`FLOW_CONTROL_ERROR`); overrunning the **connection** window is a connection error. Window increases that would exceed 2^31-1 are errors.

Consequence: receiver memory per stream is bounded by `stream_window` no matter how slowly the application reads (tested by `TestBackpressureBoundsReceiverBuffer`). Every queue is bounded: pending accepts (`max_streams`), the ordered stream-frame write queue (`write_queue`), the control-frame queue (256; overflow means the peer is not reading and the session is failed).

### Ordering and prioritisation

All frames of a stream (`OPEN`, `OPEN_OK`, `DATA`, `HALF_CLOSE`, `CLOSE`) share one FIFO so per-stream order is preserved. Connection-level frames (`PING`, `PONG`, `WINDOW_UPDATE`, `RESET`, `GOAWAY`, `ERROR`) use a separate queue that the writer serves first, so credit and liveness are not stuck behind bulk data.

## 7. Keepalive, GOAWAY and shutdown

- **Keepalive.** With `ping_interval > 0`, an idle session sends `PING`; any received frame counts as liveness. No frame for `ping_interval + ping_timeout` fails the session (`ErrKeepalive`). Dead peers are therefore detected even on half-open TCP.
- **GOAWAY.** Carries the last peer stream id the sender processed and a code. After sending or receiving it, no new streams may be opened; streams already open continue. Streams the peer opened above `last` are refused (`REFUSED_STREAM`).
- **Drain.** `Drain(ctx)` = `GOAWAY`, wait until all streams finish or `ctx` expires, then close (still-open streams are reset). `Close()` flushes already queued frames (bounded to 1 s) so a `GOAWAY`/`RESET` is not lost.
- **Client reconnect.** After `GOAWAY` or session loss the client reconnects with capped exponential backoff and jitter, obtains a fresh credential, re-authenticates and re-registers. Completed requests are never replayed.

## 8. Duplicate sessions

Only one session serves an endpoint. When a second authenticated session registers the same endpoint it **supersedes** the first: the new session is immediately routable, the old one receives `GOAWAY(SUPERSEDED)`, existing streams drain for `drain_timeout` (default 10 s), then it is closed. A superseded session must not evict its successor from the registry (`Registry.Remove` compares identity). Across edges the tunnel directory lease enforces the same rule; a session that loses its lease receives `GOAWAY(SUPERSEDED)` from its heartbeat loop.

## 9. Limits (defaults)

| Limit | Default | Where enforced |
|---|---:|---|
| Frame payload | 64 KiB (ceiling 1 MiB) | decoder, before allocation |
| DATA chunk | 16 KiB | writer |
| Request metadata | 64 KiB, 100 header fields | `Encode/Decode…Meta` |
| Stream window / conn window | 256 KiB / 4 MiB | receiver |
| Concurrent streams / session | 128 | both sides |
| Concurrent handshakes / edge | 256 | edge |
| Handshake time | 10 s | edge/client |
| Socket write | 30 s per write | writer |

## 10. Compatibility rules

- The protocol version in the frame header changes for any incompatible change to framing, handshake semantics or state machines. Peers must reject versions they do not implement.
- New frame types require a version bump because receivers reject unknown types (fail-safe).
- New JSON fields in handshake and metadata payloads are ignored by older peers *except* that the decoders reject unknown **values** for fields they validate. Adding optional fields is compatible.
- Error codes may be added; unknown codes are treated as `INTERNAL_ERROR`.
- The private product repository consumes this package through versioned releases (see ADR 0007); breaking changes need a migration plan and a compatibility window.
