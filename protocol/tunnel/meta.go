package tunnel

import (
	"encoding/json"
	"errors"
	"strings"
)

// RequestMeta is the payload of OPEN: the HTTP request line and headers. The
// body follows as DATA frames. Only an explicit allowlist of tracing headers
// crosses the tunnel besides normal end-to-end request headers (the edge
// strips hop-by-hop and client-supplied forwarding headers before encoding).
type RequestMeta struct {
	Method string              `json:"m"`
	Target string              `json:"t"` // origin-form request target, always starts with "/"
	Host   string              `json:"h"` // original Host header, informational
	Header map[string][]string `json:"hd,omitempty"`
	// Peer info added by the edge (never taken from the client).
	RemoteAddr string `json:"ra,omitempty"`
	Proto      string `json:"p,omitempty"` // "https"
	// ContentLength is -1 when unknown (chunked).
	ContentLength int64  `json:"cl"`
	Traceparent   string `json:"tp,omitempty"`
}

// ResponseMeta is the payload of OPEN_OK.
type ResponseMeta struct {
	Status        int                 `json:"s"`
	Header        map[string][]string `json:"hd,omitempty"`
	ContentLength int64               `json:"cl"`
}

// MetaLimits bound decoded metadata.
type MetaLimits struct {
	MaxBytes   int // total encoded size
	MaxHeaders int // number of header fields
}

// DefaultMetaLimits are used when zero.
var DefaultMetaLimits = MetaLimits{MaxBytes: 64 << 10, MaxHeaders: 100}

// Metadata errors.
var (
	ErrMetaTooLarge = errors.New("tunnel: metadata too large")
	ErrMetaInvalid  = errors.New("tunnel: invalid metadata")
)

func isTokenChar(c byte) bool {
	switch {
	case c >= '0' && c <= '9', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		return true
	}
	return strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0
}

func validToken(s string) bool {
	if s == "" || len(s) > 256 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isTokenChar(s[i]) {
			return false
		}
	}
	return true
}

func validValue(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\r' || c == '\n' || c == 0 {
			return false
		}
	}
	return true
}

func checkHeaders(h map[string][]string, lim MetaLimits) error {
	n := 0
	for k, vs := range h {
		if !validToken(k) {
			return ErrMetaInvalid
		}
		for _, v := range vs {
			if !validValue(v) {
				return ErrMetaInvalid
			}
			n++
		}
	}
	if n > lim.MaxHeaders {
		return ErrMetaTooLarge
	}
	return nil
}

func (l MetaLimits) norm() MetaLimits {
	if l.MaxBytes <= 0 {
		l.MaxBytes = DefaultMetaLimits.MaxBytes
	}
	if l.MaxHeaders <= 0 {
		l.MaxHeaders = DefaultMetaLimits.MaxHeaders
	}
	return l
}

// EncodeRequestMeta validates and encodes m.
func EncodeRequestMeta(m RequestMeta, lim MetaLimits) ([]byte, error) {
	lim = lim.norm()
	if err := validateRequest(m, lim); err != nil {
		return nil, err
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	if len(b) > lim.MaxBytes {
		return nil, ErrMetaTooLarge
	}
	return b, nil
}

func validateRequest(m RequestMeta, lim MetaLimits) error {
	if !validToken(m.Method) || !strings.HasPrefix(m.Target, "/") {
		return ErrMetaInvalid
	}
	if !validValue(m.Target) || strings.ContainsAny(m.Target, " ") || !validValue(m.Host) || len(m.Host) > 255 {
		return ErrMetaInvalid
	}
	if m.Method == "CONNECT" {
		return ErrMetaInvalid
	}
	return checkHeaders(m.Header, lim)
}

// DecodeRequestMeta parses and validates OPEN metadata from an untrusted peer.
func DecodeRequestMeta(b []byte, lim MetaLimits) (RequestMeta, error) {
	lim = lim.norm()
	var m RequestMeta
	if len(b) > lim.MaxBytes {
		return m, ErrMetaTooLarge
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return RequestMeta{}, ErrMetaInvalid
	}
	if err := validateRequest(m, lim); err != nil {
		return RequestMeta{}, err
	}
	return m, nil
}

// EncodeResponseMeta validates and encodes m.
func EncodeResponseMeta(m ResponseMeta, lim MetaLimits) ([]byte, error) {
	lim = lim.norm()
	if m.Status < 100 || m.Status > 599 {
		return nil, ErrMetaInvalid
	}
	if err := checkHeaders(m.Header, lim); err != nil {
		return nil, err
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	if len(b) > lim.MaxBytes {
		return nil, ErrMetaTooLarge
	}
	return b, nil
}

// DecodeResponseMeta parses OPEN_OK metadata from the (untrusted) client.
func DecodeResponseMeta(b []byte, lim MetaLimits) (ResponseMeta, error) {
	lim = lim.norm()
	var m ResponseMeta
	if len(b) > lim.MaxBytes {
		return m, ErrMetaTooLarge
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return ResponseMeta{}, ErrMetaInvalid
	}
	if m.Status < 100 || m.Status > 599 {
		return ResponseMeta{}, ErrMetaInvalid
	}
	if err := checkHeaders(m.Header, lim); err != nil {
		return ResponseMeta{}, err
	}
	return m, nil
}
