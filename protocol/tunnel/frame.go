// Package tunnel implements the 127ohoh1 tunnel protocol: length-delimited
// frames, a stream state machine, flow control and a stream multiplexer that
// runs over one TLS connection. See docs/tunnel-protocol.md.
package tunnel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Version is the protocol version carried in every frame header.
const Version = 1

// HeaderSize is the fixed frame header length.
const HeaderSize = 12

// Absolute ceiling for any configured frame payload limit. The decoder never
// allocates more than the configured limit, which must not exceed this.
const AbsoluteMaxPayload = 1 << 20

// Type is a frame type.
type Type uint8

// Frame types (values are wire-stable).
const (
	TypeHello            Type = 1
	TypeAuth             Type = 2
	TypeAuthOK           Type = 3
	TypeAuthError        Type = 4
	TypeRegisterEndpoint Type = 5
	TypeRegisterOK       Type = 6
	TypeOpen             Type = 7
	TypeOpenOK           Type = 8
	TypeData             Type = 9
	TypeHalfClose        Type = 10
	TypeClose            Type = 11
	TypeReset            Type = 12
	TypeWindowUpdate     Type = 13
	TypePing             Type = 14
	TypePong             Type = 15
	TypeGoAway           Type = 16
	TypeError            Type = 17
)

var typeNames = map[Type]string{
	TypeHello: "HELLO", TypeAuth: "AUTH", TypeAuthOK: "AUTH_OK", TypeAuthError: "AUTH_ERROR",
	TypeRegisterEndpoint: "REGISTER_ENDPOINT", TypeRegisterOK: "REGISTER_OK", TypeOpen: "OPEN", TypeOpenOK: "OPEN_OK",
	TypeData: "DATA", TypeHalfClose: "HALF_CLOSE", TypeClose: "CLOSE", TypeReset: "RESET",
	TypeWindowUpdate: "WINDOW_UPDATE", TypePing: "PING", TypePong: "PONG", TypeGoAway: "GOAWAY", TypeError: "ERROR",
}

func (t Type) String() string {
	if n, ok := typeNames[t]; ok {
		return n
	}
	return fmt.Sprintf("UNKNOWN(%d)", uint8(t))
}

// streamScoped reports whether frames of this type carry a non-zero stream id.
func (t Type) streamScoped() bool {
	switch t {
	case TypeOpen, TypeOpenOK, TypeData, TypeHalfClose, TypeClose, TypeReset:
		return true
	}
	return false
}

// WINDOW_UPDATE may target a stream (id != 0) or the connection (id == 0).
func (t Type) valid() bool { _, ok := typeNames[t]; return ok }

// ErrorCode is a numeric code carried by RESET, GOAWAY and ERROR frames.
type ErrorCode uint32

// Error codes (wire-stable).
const (
	CodeNoError          ErrorCode = 0
	CodeProtocolError    ErrorCode = 1
	CodeFlowControlError ErrorCode = 2
	CodeStreamClosed     ErrorCode = 3
	CodeRefusedStream    ErrorCode = 4
	CodeCancel           ErrorCode = 5
	CodeInternalError    ErrorCode = 6
	CodeFrameSizeError   ErrorCode = 7
	CodeUnauthenticated  ErrorCode = 8
	CodeEnhanceYourCalm  ErrorCode = 9 // limits exceeded
	CodeSuperseded       ErrorCode = 10
	CodeShutdown         ErrorCode = 11
	CodeQuotaExhausted   ErrorCode = 12
	CodePolicyRevoked    ErrorCode = 13
	CodeTimeout          ErrorCode = 14
)

func (c ErrorCode) String() string {
	names := [...]string{"NO_ERROR", "PROTOCOL_ERROR", "FLOW_CONTROL_ERROR", "STREAM_CLOSED", "REFUSED_STREAM", "CANCEL",
		"INTERNAL_ERROR", "FRAME_SIZE_ERROR", "UNAUTHENTICATED", "ENHANCE_YOUR_CALM", "SUPERSEDED", "SHUTDOWN",
		"QUOTA_EXHAUSTED", "POLICY_REVOKED", "TIMEOUT"}
	if int(c) < len(names) {
		return names[c]
	}
	return fmt.Sprintf("CODE(%d)", uint32(c))
}

// Frame is one protocol frame. Payload is owned by the receiver after decode.
type Frame struct {
	Type    Type
	Stream  uint32
	Payload []byte
}

// Decoding errors. All are connection-level protocol violations unless noted.
var (
	ErrBadVersion    = errors.New("tunnel: unsupported protocol version")
	ErrUnknownType   = errors.New("tunnel: unknown frame type")
	ErrFrameTooLarge = errors.New("tunnel: frame payload exceeds limit")
	ErrBadHeader     = errors.New("tunnel: malformed frame header")
	ErrBadPayload    = errors.New("tunnel: malformed frame payload")
	ErrBadStreamID   = errors.New("tunnel: invalid stream id for frame type")
)

// AppendFrame appends the wire form of f to dst. It panics never; oversize
// payloads are reported so callers cannot emit frames peers must reject.
func AppendFrame(dst []byte, f Frame, maxPayload int) ([]byte, error) {
	if len(f.Payload) > maxPayload || len(f.Payload) > AbsoluteMaxPayload {
		return dst, ErrFrameTooLarge
	}
	if !f.Type.valid() {
		return dst, ErrUnknownType
	}
	if f.Type.streamScoped() != (f.Stream != 0) && f.Type != TypeWindowUpdate {
		return dst, ErrBadStreamID
	}
	dst = append(dst, Version, byte(f.Type), 0, 0)
	dst = binary.BigEndian.AppendUint32(dst, f.Stream)
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(f.Payload)))
	return append(dst, f.Payload...), nil
}

// ReadFrame reads and validates one frame. The declared length is checked
// against maxPayload *before* any payload allocation, so a hostile peer cannot
// force large allocations. Fixed-size payloads are validated by type.
func ReadFrame(r io.Reader, maxPayload int) (Frame, error) {
	if maxPayload > AbsoluteMaxPayload || maxPayload <= 0 {
		maxPayload = AbsoluteMaxPayload
	}
	var h [HeaderSize]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return Frame{}, err
	}
	if h[0] != Version {
		return Frame{}, ErrBadVersion
	}
	t := Type(h[1])
	if !t.valid() {
		return Frame{}, ErrUnknownType
	}
	if h[2] != 0 || h[3] != 0 {
		return Frame{}, ErrBadHeader // flags/reserved must be zero in v1
	}
	stream := binary.BigEndian.Uint32(h[4:8])
	n := binary.BigEndian.Uint32(h[8:12])
	if uint64(n) > uint64(maxPayload) {
		return Frame{}, ErrFrameTooLarge
	}
	if stream&0x80000000 != 0 {
		return Frame{}, ErrBadStreamID // high bit reserved
	}
	if t != TypeWindowUpdate && t.streamScoped() != (stream != 0) {
		return Frame{}, ErrBadStreamID
	}
	if err := checkFixed(t, int(n)); err != nil {
		return Frame{}, err
	}
	f := Frame{Type: t, Stream: stream}
	if n > 0 {
		f.Payload = make([]byte, n)
		if _, err := io.ReadFull(r, f.Payload); err != nil {
			if errors.Is(err, io.EOF) {
				err = io.ErrUnexpectedEOF
			}
			return Frame{}, err
		}
	}
	return f, nil
}

func checkFixed(t Type, n int) error {
	want := -1
	switch t {
	case TypeWindowUpdate, TypeReset:
		want = 4
	case TypePing, TypePong, TypeGoAway:
		want = 8
	case TypeHalfClose, TypeClose, TypeRegisterOK:
		want = 0
	case TypeData:
		if n == 0 {
			return ErrBadPayload // empty DATA is pointless and a CPU-spin vector
		}
	}
	if want >= 0 && n != want {
		return ErrBadPayload
	}
	return nil
}

// ---- typed payload helpers -------------------------------------------------

// WindowUpdate builds a WINDOW_UPDATE payload.
func WindowUpdate(stream uint32, increment uint32) Frame {
	p := make([]byte, 4)
	binary.BigEndian.PutUint32(p, increment)
	return Frame{Type: TypeWindowUpdate, Stream: stream, Payload: p}
}

// ParseWindowUpdate returns the increment (must be 1..2^31-1).
func ParseWindowUpdate(p []byte) (uint32, error) {
	if len(p) != 4 {
		return 0, ErrBadPayload
	}
	v := binary.BigEndian.Uint32(p)
	if v == 0 || v > 0x7fffffff {
		return 0, ErrBadPayload
	}
	return v, nil
}

// ResetFrame builds RESET.
func ResetFrame(stream uint32, code ErrorCode) Frame {
	p := make([]byte, 4)
	binary.BigEndian.PutUint32(p, uint32(code))
	return Frame{Type: TypeReset, Stream: stream, Payload: p}
}

// ParseReset returns the code.
func ParseReset(p []byte) (ErrorCode, error) {
	if len(p) != 4 {
		return 0, ErrBadPayload
	}
	return ErrorCode(binary.BigEndian.Uint32(p)), nil
}

// GoAwayFrame builds GOAWAY: no streams with id > lastStream will be processed.
func GoAwayFrame(lastStream uint32, code ErrorCode) Frame {
	p := make([]byte, 8)
	binary.BigEndian.PutUint32(p, lastStream)
	binary.BigEndian.PutUint32(p[4:], uint32(code))
	return Frame{Type: TypeGoAway, Payload: p}
}

// ParseGoAway returns the last processed stream id and code.
func ParseGoAway(p []byte) (uint32, ErrorCode, error) {
	if len(p) != 8 {
		return 0, 0, ErrBadPayload
	}
	return binary.BigEndian.Uint32(p), ErrorCode(binary.BigEndian.Uint32(p[4:])), nil
}

// PingFrame builds PING/PONG with an opaque 8-byte token.
func PingFrame(t Type, token uint64) Frame {
	p := make([]byte, 8)
	binary.BigEndian.PutUint64(p, token)
	return Frame{Type: t, Payload: p}
}

// ErrorFrame builds a connection-level ERROR with a short message (truncated).
func ErrorFrame(code ErrorCode, msg string) Frame {
	if len(msg) > 256 {
		msg = msg[:256]
	}
	p := make([]byte, 4, 4+len(msg))
	binary.BigEndian.PutUint32(p, uint32(code))
	return Frame{Type: TypeError, Payload: append(p, msg...)}
}

// ParseError parses an ERROR payload.
func ParseError(p []byte) (ErrorCode, string, error) {
	if len(p) < 4 {
		return 0, "", ErrBadPayload
	}
	return ErrorCode(binary.BigEndian.Uint32(p)), string(p[4:]), nil
}
