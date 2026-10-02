// Package session establishes and maintains the client's outbound tunnel to an
// edge. The client only ever dials out: no inbound port is required.
package session

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"time"

	"github.com/127ohoh1/core/client/api"
	cid "github.com/127ohoh1/core/client/identity"
	"github.com/127ohoh1/core/protocol/auth"
	proto "github.com/127ohoh1/core/protocol/tunnel"
)

var b64 = base64.RawURLEncoding

// ClientName is sent in HELLO for diagnostics.
const ClientName = "127ohoh1-cli/0.1"

// Connection is an authenticated, registered tunnel session.
type Connection struct {
	Session    *proto.Session
	SessionID  string
	EdgeID     string
	EndpointID string
	Hostname   string
}

// Connect performs one full connection attempt: TLS, HELLO, AUTH (with a
// channel-bound proof of possession) and REGISTER_ENDPOINT.
func Connect(ctx context.Context, addr string, tlsCfg *tls.Config, cred api.TunnelCredential, id cid.Identity, timeout time.Duration) (*Connection, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	cfg := tlsCfg.Clone()
	cfg.MinVersion = tls.VersionTLS13 // the channel binding needs the TLS 1.3 exporter
	if cfg.ServerName == "" {
		if host, _, err := net.SplitHostPort(addr); err == nil {
			cfg.ServerName = host
		}
	}
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	d := tls.Dialer{NetDialer: &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}, Config: cfg}
	raw, err := d.DialContext(dctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial edge: %w", err)
	}
	conn := raw.(*tls.Conn)
	ok := false
	defer func() {
		if !ok {
			conn.Close()
		}
	}()

	if err := proto.WriteHandshake(conn, proto.TypeHello, proto.Hello{Versions: []int{proto.Version}, Client: ClientName}, timeout); err != nil {
		return nil, err
	}
	var hello proto.Hello
	if err := proto.ReadHandshake(conn, proto.TypeHello, &hello, timeout); err != nil {
		return nil, fmt.Errorf("edge hello: %w", err)
	}
	if hello.Version != proto.Version || hello.Params == nil {
		return nil, fmt.Errorf("edge selected unsupported protocol version %d", hello.Version)
	}
	scfg, err := hello.Params.Config()
	if err != nil {
		return nil, err
	}
	nonce, err := b64.Strict().DecodeString(hello.Nonce)
	if err != nil || len(nonce) < auth.MinNonceBytes {
		return nil, fmt.Errorf("edge sent an invalid nonce")
	}
	claims, err := auth.PeekClaims(cred.Token)
	if err != nil {
		return nil, fmt.Errorf("bad credential: %w", err)
	}
	cs := conn.ConnectionState()
	exporter, err := cs.ExportKeyingMaterial(proto.ExporterLabel, nil, 32)
	if err != nil {
		return nil, fmt.Errorf("tls exporter: %w", err)
	}
	sig := ed25519.Sign(id.Private, auth.TunnelProofBytes(exporter, nonce, claims.ID, claims.Endpoint))
	if err := proto.WriteHandshake(conn, proto.TypeAuth, proto.Auth{Token: cred.Token, JTI: claims.ID, Proof: b64.EncodeToString(sig)}, timeout); err != nil {
		return nil, err
	}
	var aok proto.AuthOK
	if err := proto.ReadHandshake(conn, proto.TypeAuthOK, &aok, timeout); err != nil {
		return nil, err // *proto.AuthError carries the retryable hint
	}
	if err := proto.WriteHandshake(conn, proto.TypeRegisterEndpoint, proto.Register{EndpointID: aok.EndpointID, Hostname: aok.Hostname}, timeout); err != nil {
		return nil, err
	}
	if err := proto.ReadHandshake(conn, proto.TypeRegisterOK, nil, timeout); err != nil {
		return nil, fmt.Errorf("register: %w", err)
	}
	proto.ClearDeadlines(conn)
	ok = true
	return &Connection{Session: proto.NewSession(conn, proto.RoleClient, scfg), SessionID: aok.SessionID, EdgeID: hello.EdgeID,
		EndpointID: aok.EndpointID, Hostname: aok.Hostname}, nil
}

// StreamHandler serves one accepted tunnel stream.
type StreamHandler interface {
	Serve(st *proto.Stream)
}

// Serve accepts streams from the session and hands each to h in its own
// goroutine until the session ends or ctx is cancelled. It returns the reason
// the session ended.
func Serve(ctx context.Context, s *proto.Session, h StreamHandler) error {
	go func() {
		select {
		case <-ctx.Done():
			s.Close()
		case <-s.Done():
		}
	}()
	for {
		st, err := s.Accept(ctx)
		if err != nil {
			<-s.Done()
			return s.Err()
		}
		go h.Serve(st)
	}
}
