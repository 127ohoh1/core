package session

import (
	"context"
	"crypto/tls"
	"errors"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/127ohoh1/core/client/api"
	cid "github.com/127ohoh1/core/client/identity"
	proto "github.com/127ohoh1/core/protocol/tunnel"
)

// State is the connection state exposed to logs and metrics.
type State string

const (
	StateConnecting   State = "connecting"
	StateConnected    State = "connected"
	StateReconnecting State = "reconnecting"
	StateStopped      State = "stopped"
)

// Backoff computes capped exponential delays with full jitter:
// delay = uniform(0, min(Max, Base * 2^attempt)). Full jitter spreads a
// reconnect storm (many clients dropped at once) instead of synchronising it.
type Backoff struct {
	Base, Max time.Duration
	Rand      func() float64 // uniform [0,1); nil = math/rand
}

// Delay returns the wait before retry number attempt (0-based).
func (b Backoff) Delay(attempt int) time.Duration {
	base, max := b.Base, b.Max
	if base <= 0 {
		base = 500 * time.Millisecond
	}
	if max <= 0 {
		max = 30 * time.Second
	}
	ceil := max
	if attempt < 32 { // avoid overflow
		if d := base << uint(attempt); d > 0 && d < max {
			ceil = d
		}
	}
	r := rand.Float64
	if b.Rand != nil {
		r = b.Rand
	}
	return time.Duration(r() * float64(ceil))
}

// RunOptions configures the reconnecting client.
type RunOptions struct {
	// Credential obtains a fresh tunnel credential for every attempt.
	Credential func(ctx context.Context) (api.TunnelCredential, error)
	// EdgeAddr overrides the address from the credential.
	EdgeAddr string
	TLS      *tls.Config
	Identity cid.Identity
	Handler  StreamHandler
	Backoff  Backoff
	// StableAfter: a session that lasted this long resets the backoff.
	StableAfter time.Duration
	// DrainGrace bounds how long a session that received GOAWAY may keep serving
	// in-flight streams while its replacement is already connected.
	DrainGrace time.Duration
	// OnState is called on every transition (never concurrently).
	OnState func(s State, info string)
	// OnConnected is called after each successful (re)registration.
	OnConnected func(c *Connection)
}

// FatalError wraps errors that retrying cannot fix (bad credential, released
// endpoint, revoked identity).
type FatalError struct{ Err error }

func (e *FatalError) Error() string { return "fatal: " + e.Err.Error() }
func (e *FatalError) Unwrap() error { return e.Err }

// retryable classifies a connection or credential failure.
func retryable(err error) bool {
	var ae *proto.AuthError
	if errors.As(err, &ae) {
		return ae.Retryable
	}
	var api_ *api.Error
	if errors.As(err, &api_) {
		switch api_.Status {
		case 401, 403, 404, 409, 410:
			return false // identity rejected, endpoint gone/suspended/not active
		}
		return true // 429, 5xx
	}
	var re *proto.RemoteError
	if errors.As(err, &re) && re.Code == proto.CodeUnauthenticated {
		return false
	}
	return true // network errors, TLS, timeouts
}

// Run keeps the tunnel up until ctx is cancelled or a fatal error occurs. It
// reauthenticates and reregisters after every disconnect, honours GOAWAY by
// connecting the replacement before the draining session finishes its streams,
// and never replays requests: streams of a dead session simply fail.
func Run(ctx context.Context, o RunOptions) error {
	if o.StableAfter <= 0 {
		o.StableAfter = 30 * time.Second
	}
	if o.DrainGrace <= 0 {
		o.DrainGrace = 15 * time.Second
	}
	var stateMu sync.Mutex
	set := func(s State, info string) {
		stateMu.Lock()
		defer stateMu.Unlock()
		if o.OnState != nil {
			o.OnState(s, info)
		}
	}
	var wg sync.WaitGroup
	defer func() { wg.Wait(); set(StateStopped, "") }()

	attempt := 0
	first := true
	for {
		if ctx.Err() != nil {
			return nil
		}
		if first {
			set(StateConnecting, "")
		}
		conn, err := connectOnce(ctx, o)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if !retryable(err) {
				return &FatalError{Err: err}
			}
			d := o.Backoff.Delay(attempt)
			attempt++
			set(StateReconnecting, err.Error())
			if err := sleep(ctx, d); err != nil {
				return nil
			}
			first = false
			continue
		}
		first = false
		set(StateConnected, conn.Hostname)
		if o.OnConnected != nil {
			o.OnConnected(conn)
		}
		started := time.Now()
		serveDone := make(chan error, 1)
		sctx, scancel := context.WithCancel(ctx)
		wg.Add(1)
		go func() { defer wg.Done(); serveDone <- Serve(sctx, conn.Session, o.Handler); scancel() }()

		select {
		case <-ctx.Done():
			scancel()
			return nil
		case cause := <-serveDone:
			if time.Since(started) >= o.StableAfter {
				attempt = 0
			}
			set(StateReconnecting, causeString(cause))
			d := o.Backoff.Delay(attempt)
			attempt++
			if err := sleep(ctx, d); err != nil {
				return nil
			}
		case <-conn.Session.GoAwayReceived():
			// Edge is draining (shutdown, supersede). Connect the replacement now;
			// the old session keeps serving in-flight streams until DrainGrace.
			if time.Since(started) >= o.StableAfter {
				attempt = 0
			}
			set(StateReconnecting, "edge sent GOAWAY")
			time.AfterFunc(o.DrainGrace, func() { conn.Session.Close() })
			// A superseding GOAWAY means another client instance owns the endpoint:
			// reconnecting immediately would ping-pong forever, so back off.
			if err := sleep(ctx, o.Backoff.Delay(attempt)); err != nil {
				scancel()
				return nil
			}
			attempt++
		}
	}
}

func causeString(err error) string {
	if err == nil {
		return "session ended"
	}
	return err.Error()
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func connectOnce(ctx context.Context, o RunOptions) (*Connection, error) {
	cred, err := o.Credential(ctx)
	if err != nil {
		return nil, err
	}
	addr := o.EdgeAddr
	if addr == "" {
		addr = cred.Edge.Addr
	}
	return Connect(ctx, addr, o.TLS, cred, o.Identity, 10*time.Second)
}
