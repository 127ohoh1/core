package tunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
)

// Stream is one bidirectional byte stream (one HTTP exchange). Reads and
// writes may proceed concurrently; at most one goroutine may Write at a time
// (Write serialises callers to keep frames ordered).
type Stream struct {
	s  *Session
	id uint32

	// OpenMeta is the OPEN payload, set on streams returned by Accept.
	OpenMeta []byte

	ctx    context.Context
	cancel context.CancelCauseFunc
	done   chan struct{}

	mu       sync.Mutex
	state    State
	finished bool
	err      error // abnormal termination cause
	discard  bool  // local side no longer reads

	// receive side
	rq        [][]byte
	rqBytes   int
	recvOut   int // received, not yet credited back
	credit    int // consumed, not yet announced
	remoteEnd bool
	notify    chan struct{}

	resp    []byte
	respGot bool
	respCh  chan struct{}

	// send side
	sendWin int64
	winCh   chan struct{}
	wmu     sync.Mutex
	okSent  bool
}

func (s *Session) newStream(id uint32) *Stream {
	ctx, cancel := context.WithCancelCause(context.Background())
	return &Stream{s: s, id: id, ctx: ctx, cancel: cancel, done: make(chan struct{}),
		notify: make(chan struct{}, 1), respCh: make(chan struct{}),
		sendWin: int64(s.cfg.StreamWindow), winCh: make(chan struct{})}
}

// ID returns the stream id.
func (st *Stream) ID() uint32 { return st.id }

// Context is cancelled when the stream terminates for any reason (reset,
// close, session loss). Use it to propagate cancellation to the origin/client.
func (st *Stream) Context() context.Context { return st.ctx }

// Done is closed when the stream has fully terminated.
func (st *Stream) Done() <-chan struct{} { return st.done }

func (st *Stream) wake() {
	select {
	case st.notify <- struct{}{}:
	default:
	}
}

// terminate ends the stream. It is idempotent and reports whether this call
// performed the termination. err == nil means graceful end.
func (st *Stream) terminate(err error) bool {
	st.mu.Lock()
	if st.finished {
		st.mu.Unlock()
		return false
	}
	st.finished = true
	st.state = StateClosed
	if err != nil {
		st.err = err
	}
	dropped := 0
	if err != nil || st.discard {
		dropped = st.rqBytes
		st.rq, st.rqBytes = nil, 0
	}
	st.recvOut -= dropped
	oldWin := st.winCh
	st.winCh = make(chan struct{})
	respClosed := st.respGot
	st.respGot = true // unblock WaitResponse; err/closed tells the truth
	st.mu.Unlock()

	// Session bookkeeping happens BEFORE the completion signal, so anything woken
	// by Done() (or by the cancelled context) already sees this stream removed
	// from ActiveStreams and the stream table.
	s := st.s
	s.mu.Lock()
	delete(s.streams, st.id)
	s.mu.Unlock()
	s.active.Add(-1)

	close(st.done)
	close(oldWin)
	if !respClosed {
		close(st.respCh)
	}
	st.cancel(err)
	st.wake()

	if dropped > 0 {
		s.creditConn(dropped)
	}
	s.markDrainedIfIdle()
	return true
}

// ---- receiving frames (called from the session read loop) -------------------

func (st *Stream) receive(f Frame) error {
	switch f.Type {
	case TypeOpenOK:
		st.mu.Lock()
		_, err := st.state.Recv(EvOpenOK)
		dup := st.respGot
		if err == nil && !dup && len(f.Payload) > st.s.cfg.Meta.MaxBytes {
			err = ErrMetaTooLarge
		}
		if err != nil || dup {
			st.mu.Unlock()
			st.localReset(CodeProtocolError)
			return nil
		}
		st.resp, st.respGot = f.Payload, true
		st.mu.Unlock()
		close(st.respCh)
	case TypeData:
		n := len(f.Payload)
		st.mu.Lock()
		if _, err := st.state.Recv(EvData); err != nil || st.discard {
			st.mu.Unlock()
			st.s.creditConn(n) // sender spent connection window on it
			if err != nil {
				st.localReset(CodeStreamClosed)
			}
			return nil
		}
		if err := st.s.noteRecv(n); err != nil {
			st.mu.Unlock()
			return err // connection-level: window overflow
		}
		if st.recvOut+n > st.s.cfg.StreamWindow {
			st.mu.Unlock()
			st.s.creditConn(n)
			st.localReset(CodeFlowControlError)
			return nil
		}
		st.recvOut += n
		st.rq = append(st.rq, f.Payload)
		st.rqBytes += n
		st.mu.Unlock()
		st.wake()
	case TypeHalfClose:
		st.mu.Lock()
		ns, err := st.state.Recv(EvHalfClose)
		if err != nil {
			st.mu.Unlock()
			st.localReset(CodeStreamClosed)
			return nil
		}
		st.state, st.remoteEnd = ns, true
		st.mu.Unlock()
		st.wake()
		if ns == StateClosed {
			st.terminate(nil)
		}
	case TypeClose:
		st.mu.Lock()
		st.remoteEnd = true
		st.mu.Unlock()
		st.terminate(nil)
	case TypeReset:
		code, err := ParseReset(f.Payload)
		if err != nil {
			return protoErr(CodeProtocolError, "bad RESET")
		}
		st.terminate(&StreamError{Code: code, Remote: true})
	default:
		return protoErr(CodeProtocolError, "unexpected %s on stream %d", f.Type, st.id)
	}
	return nil
}

func (st *Stream) localReset(code ErrorCode) {
	if st.terminate(&StreamError{Code: code}) {
		st.s.sendCtrl(ResetFrame(st.id, code))
	}
}

func (st *Stream) addSendWindow(inc int64) {
	st.mu.Lock()
	if st.sendWin+inc > 0x7fffffff {
		st.mu.Unlock()
		st.localReset(CodeFlowControlError)
		return
	}
	st.sendWin += inc
	old := st.winCh
	st.winCh = make(chan struct{})
	st.mu.Unlock()
	close(old)
}

// ---- application API ---------------------------------------------------------

// Read implements io.Reader. It returns io.EOF after the peer half-closed and
// all buffered data was read, or the stream error after a reset.
func (st *Stream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		st.mu.Lock()
		if len(st.rq) > 0 {
			n := 0
			for n < len(p) && len(st.rq) > 0 {
				c := copy(p[n:], st.rq[0])
				n += c
				if c == len(st.rq[0]) {
					st.rq = st.rq[1:]
				} else {
					st.rq[0] = st.rq[0][c:]
				}
			}
			st.rqBytes -= n
			st.recvOut -= n
			st.credit += n
			var inc int
			if st.credit >= st.s.cfg.StreamWindow/2 && !st.remoteEnd && !st.finished {
				inc, st.credit = st.credit, 0
			}
			st.mu.Unlock()
			if inc > 0 {
				st.s.sendCtrl(WindowUpdate(st.id, uint32(inc)))
			}
			st.s.creditConn(n)
			return n, nil
		}
		if st.err != nil {
			err := st.err
			st.mu.Unlock()
			return 0, err
		}
		if st.remoteEnd || st.finished {
			st.mu.Unlock()
			return 0, io.EOF
		}
		st.mu.Unlock()
		select {
		case <-st.notify:
		case <-st.done:
		}
	}
}

// Write implements io.Writer with flow control. It blocks while windows are
// exhausted and returns when the stream or session ends.
func (st *Stream) Write(p []byte) (int, error) { return st.WriteContext(context.Background(), p) }

// WriteContext is Write with cancellation.
func (st *Stream) WriteContext(ctx context.Context, p []byte) (int, error) {
	st.wmu.Lock()
	defer st.wmu.Unlock()
	written := 0
	for len(p) > 0 {
		want := min(len(p), st.s.cfg.DataChunk)
		n, err := st.reserve(ctx, want)
		if err != nil {
			return written, err
		}
		buf := make([]byte, n)
		copy(buf, p[:n])
		if err := st.s.sendData(ctx, Frame{Type: TypeData, Stream: st.id, Payload: buf}); err != nil {
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}

func (st *Stream) sendErr() error {
	if st.err != nil {
		return st.err
	}
	if st.finished {
		return ErrStreamClosed
	}
	if _, err := st.state.Send(EvData); err != nil {
		return fmt.Errorf("%w: %v", ErrStreamClosed, err)
	}
	return nil
}

// reserve waits for stream and connection send window and takes up to want bytes.
func (st *Stream) reserve(ctx context.Context, want int) (int, error) {
	for {
		st.mu.Lock()
		if err := st.sendErr(); err != nil {
			st.mu.Unlock()
			return 0, err
		}
		var wait <-chan struct{}
		if avail := min(int64(want), st.sendWin); avail > 0 {
			ch := st.s.connWinChan() // fetch before taking: no lost wakeup
			if got := st.s.takeConn(int(avail)); got > 0 {
				st.sendWin -= int64(got)
				st.mu.Unlock()
				return got, nil
			}
			wait = ch
		} else {
			wait = st.winCh
		}
		st.mu.Unlock()
		select {
		case <-wait:
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-st.done:
		case <-st.s.done:
		}
	}
}

// CloseWrite half-closes the stream: the peer sees EOF after buffered data.
func (st *Stream) CloseWrite() error {
	st.wmu.Lock()
	defer st.wmu.Unlock()
	st.mu.Lock()
	if st.err != nil {
		err := st.err
		st.mu.Unlock()
		return err
	}
	ns, err := st.state.Send(EvHalfClose)
	if err != nil {
		st.mu.Unlock()
		if st.finished {
			return ErrStreamClosed
		}
		return err
	}
	st.state = ns
	st.mu.Unlock()
	if err := st.s.sendData(context.Background(), Frame{Type: TypeHalfClose, Stream: st.id}); err != nil {
		return err
	}
	if ns == StateClosed {
		st.terminate(nil)
	}
	return nil
}

// Close ends the stream gracefully in both directions and discards unread
// data. Data already queued for the peer is sent first (ordered queue).
func (st *Stream) Close() error {
	st.wmu.Lock()
	defer st.wmu.Unlock()
	st.mu.Lock()
	if st.finished {
		st.mu.Unlock()
		return nil
	}
	st.discard = true
	st.mu.Unlock()
	if err := st.s.sendData(context.Background(), Frame{Type: TypeClose, Stream: st.id}); err != nil {
		st.terminate(err)
		return err
	}
	st.terminate(nil)
	return nil
}

// Reset aborts the stream immediately, telling the peer why.
func (st *Stream) Reset(code ErrorCode) { st.localReset(code) }

// SendResponse sends OPEN_OK with encoded response metadata (acceptor side).
func (st *Stream) SendResponse(meta []byte) error {
	if len(meta) > st.s.cfg.Meta.MaxBytes {
		return ErrMetaTooLarge
	}
	st.wmu.Lock()
	defer st.wmu.Unlock()
	st.mu.Lock()
	if st.err != nil {
		err := st.err
		st.mu.Unlock()
		return err
	}
	if st.okSent {
		st.mu.Unlock()
		return errors.New("tunnel: response already sent")
	}
	if _, err := st.state.Send(EvOpenOK); err != nil {
		st.mu.Unlock()
		return err
	}
	st.okSent = true
	st.mu.Unlock()
	return st.s.sendData(context.Background(), Frame{Type: TypeOpenOK, Stream: st.id, Payload: meta})
}

// WaitResponse waits for OPEN_OK (opener side) and returns its metadata.
func (st *Stream) WaitResponse(ctx context.Context) ([]byte, error) {
	select {
	case <-st.respCh:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.resp != nil {
		return st.resp, nil
	}
	if st.err != nil {
		return nil, st.err
	}
	return nil, ErrStreamClosed
}
