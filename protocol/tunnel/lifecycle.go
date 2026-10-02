package tunnel

import (
	"context"
	"errors"
	"time"
)

// ErrKeepalive is the session failure cause when the peer stops responding.
var ErrKeepalive = errors.New("tunnel: keepalive timeout")

// keepalive pings when the connection is idle and fails the session if
// nothing at all is received within PingInterval+PingTimeout. Any received
// frame counts as liveness.
func (s *Session) keepalive() {
	t := time.NewTicker(s.cfg.PingInterval)
	defer t.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-t.C:
		}
		idle := time.Since(time.Unix(0, s.lastRecv.Load()))
		if idle >= s.cfg.PingInterval+s.cfg.PingTimeout {
			s.fail(ErrKeepalive)
			return
		}
		if idle >= s.cfg.PingInterval {
			s.sendCtrl(PingFrame(TypePing, 0)) // token 0 is never awaited; any PONG refreshes lastRecv
		}
	}
}

// GoAway announces that no new streams will be accepted. Streams already open
// continue; the peer must stop opening streams and reconnect. It is
// idempotent.
func (s *Session) GoAway(code ErrorCode) {
	s.mu.Lock()
	if s.goawaySent {
		s.mu.Unlock()
		return
	}
	s.goawaySent = true
	last := s.lastPeerID
	s.mu.Unlock()
	s.sendCtrl(GoAwayFrame(last, code))
	s.markDrainedIfIdle()
}

// Draining reports whether GOAWAY was sent or received.
func (s *Session) Draining() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.goawaySent || s.goawayRecv
}

func (s *Session) markDrainedIfIdle() {
	s.mu.Lock()
	idle := len(s.streams) == 0 && (s.goawaySent || s.goawayRecv)
	s.mu.Unlock()
	select {
	case <-s.done:
		idle = true
	default:
	}
	if idle {
		s.drainOnce.Do(func() { close(s.drained) })
	}
}

// Drain sends GOAWAY and waits until all streams finished or ctx expires, then
// closes the session. Streams still open at the deadline are reset by Close.
func (s *Session) Drain(ctx context.Context, code ErrorCode) {
	s.GoAway(code)
	select {
	case <-s.drained:
	case <-ctx.Done():
	case <-s.done:
	}
	s.Close()
}
