package tunnel

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"time"
)

// Handshake payloads. They are exchanged before the multiplexer starts, on
// stream id 0, as JSON in frames whose payload is capped at MaxHandshakePayload.
//
//	C -> S  HELLO   {versions, client}
//	S -> C  HELLO   {version, edge_id, nonce, params}
//	C -> S  AUTH    {token, jti, proof}
//	S -> C  AUTH_OK {session_id, endpoint_id, hostname} | AUTH_ERROR {code, message, retryable}
//	C -> S  REGISTER_ENDPOINT {endpoint_id, hostname}
//	S -> C  REGISTER_OK  (or ERROR)
const MaxHandshakePayload = 8 << 10

// ExporterLabel is the TLS exporter label used to channel-bind the proof.
const ExporterLabel = "EXPORTER-127ohoh1-tunnel-v1"

// Params are the session parameters dictated by the edge.
type Params struct {
	MaxFramePayload int `json:"max_frame_payload"`
	DataChunk       int `json:"data_chunk"`
	StreamWindow    int `json:"stream_window"`
	ConnWindow      int `json:"conn_window"`
	MaxStreams      int `json:"max_streams"`
	PingIntervalMS  int `json:"ping_interval_ms"`
	PingTimeoutMS   int `json:"ping_timeout_ms"`
	MaxMetaBytes    int `json:"max_meta_bytes"`
}

// ParamsFromConfig captures the negotiated parameters of cfg.
func ParamsFromConfig(cfg Config) Params {
	cfg.normalize()
	return Params{MaxFramePayload: cfg.MaxFramePayload, DataChunk: cfg.DataChunk, StreamWindow: cfg.StreamWindow,
		ConnWindow: cfg.ConnWindow, MaxStreams: cfg.MaxStreams, PingIntervalMS: int(cfg.PingInterval / time.Millisecond),
		PingTimeoutMS: int(cfg.PingTimeout / time.Millisecond), MaxMetaBytes: cfg.Meta.MaxBytes}
}

// Config converts negotiated parameters back to a session Config, refusing
// values that would let the edge make the client allocate without bound.
func (p Params) Config() (Config, error) {
	if p.MaxFramePayload < 1024 || p.MaxFramePayload > 1<<20 || p.StreamWindow < p.MaxFramePayload ||
		p.StreamWindow > 16<<20 || p.ConnWindow < p.StreamWindow || p.ConnWindow > 64<<20 ||
		p.MaxStreams < 1 || p.MaxStreams > 4096 || p.DataChunk < 1 || p.DataChunk > p.MaxFramePayload {
		return Config{}, fmt.Errorf("tunnel: edge proposed unacceptable parameters %+v", p)
	}
	c := Defaults()
	c.MaxFramePayload, c.DataChunk, c.StreamWindow, c.ConnWindow, c.MaxStreams = p.MaxFramePayload, p.DataChunk, p.StreamWindow, p.ConnWindow, p.MaxStreams
	c.PingInterval, c.PingTimeout = time.Duration(p.PingIntervalMS)*time.Millisecond, time.Duration(p.PingTimeoutMS)*time.Millisecond
	c.Meta = MetaLimits{MaxBytes: p.MaxMetaBytes}
	return c, nil
}

// Hello is both directions of the HELLO exchange (fields depend on direction).
type Hello struct {
	Versions []int   `json:"versions,omitempty"` // client
	Client   string  `json:"client,omitempty"`   // client
	Version  int     `json:"version,omitempty"`  // server: chosen
	EdgeID   string  `json:"edge_id,omitempty"`  // server
	Nonce    string  `json:"nonce,omitempty"`    // server: per-connection, base64url
	Params   *Params `json:"params,omitempty"`   // server
}

// Auth is the client's credential and proof of possession.
type Auth struct {
	Token string `json:"token"`
	JTI   string `json:"jti"`
	Proof string `json:"proof"` // base64url Ed25519 signature over auth.TunnelProofBytes
}

// AuthOK acknowledges authentication.
type AuthOK struct {
	SessionID  string `json:"session_id"`
	EndpointID string `json:"endpoint_id"`
	Hostname   string `json:"hostname"`
}

// AuthError reports a failed authentication. Messages are deliberately generic.
type AuthError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

func (e *AuthError) Error() string {
	return fmt.Sprintf("tunnel auth failed: %s: %s (retryable=%v)", e.Code, e.Message, e.Retryable)
}

// Register binds the authenticated session to an endpoint.
type Register struct {
	EndpointID string `json:"endpoint_id"`
	Hostname   string `json:"hostname"`
}

// WriteHandshake writes one handshake frame with a deadline.
func WriteHandshake(conn net.Conn, t Type, v any, timeout time.Duration) error {
	var payload []byte
	if v != nil {
		var err error
		if payload, err = json.Marshal(v); err != nil {
			return err
		}
	}
	b, err := AppendFrame(nil, Frame{Type: t, Payload: payload}, MaxHandshakePayload)
	if err != nil {
		return err
	}
	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	_, err = conn.Write(b)
	return err
}

// ReadHandshake reads one frame, which must be of type want (or ERROR /
// AUTH_ERROR, which are decoded into errors).
func ReadHandshake(conn net.Conn, want Type, v any, timeout time.Duration) error {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	f, err := ReadFrame(io.LimitReader(conn, HeaderSize+MaxHandshakePayload), MaxHandshakePayload)
	if err != nil {
		return err
	}
	switch f.Type {
	case want:
		if v == nil {
			return nil
		}
		if err := json.Unmarshal(f.Payload, v); err != nil {
			return fmt.Errorf("tunnel: bad %s payload: %w", f.Type, err)
		}
		return nil
	case TypeAuthError:
		var ae AuthError
		if json.Unmarshal(f.Payload, &ae) != nil {
			return &AuthError{Code: "unknown", Message: "authentication failed"}
		}
		return &ae
	case TypeError:
		code, msg, _ := ParseError(f.Payload)
		return &RemoteError{Code: code, Msg: msg}
	}
	return fmt.Errorf("tunnel: expected %s, got %s", want, f.Type)
}

// ClearDeadlines resets connection deadlines after the handshake.
func ClearDeadlines(conn net.Conn) { _ = conn.SetDeadline(time.Time{}) }
