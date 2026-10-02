package tunnel

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ioBufSize is the per-direction socket buffer. Frames larger than this bypass
// the buffer (bufio reads/writes large slices directly), so it only has to be big
// enough to coalesce small control frames; keeping it small is what makes tens of
// thousands of idle sessions affordable (measured: benchmarks/results).
const ioBufSize = 8 << 10

// Role decides stream-id parity: the server (edge) opens odd ids, the client
// even ids, so both sides can open streams without collisions.
type Role uint8

const (
	RoleServer Role = iota
	RoleClient
)

// Config configures a Session. All limits are enforced on untrusted input.
type Config struct {
	MaxFramePayload int           // max payload of any received frame
	DataChunk       int           // max DATA payload emitted (<= MaxFramePayload)
	StreamWindow    int           // per-stream receive window (bytes)
	ConnWindow      int           // per-connection receive window (bytes)
	MaxStreams      int           // max concurrently open streams (both directions)
	WriteQueue      int           // bounded queued frames per priority class
	WriteTimeout    time.Duration // deadline for a single socket write
	PingInterval    time.Duration // 0 disables keepalive
	PingTimeout     time.Duration
	Meta            MetaLimits
	Logger          *slog.Logger
}

// Defaults returns production-shaped defaults.
func Defaults() Config {
	return Config{MaxFramePayload: 64 << 10, DataChunk: 16 << 10, StreamWindow: 256 << 10, ConnWindow: 4 << 20,
		MaxStreams: 128, WriteQueue: 64, WriteTimeout: 30 * time.Second,
		PingInterval: 15 * time.Second, PingTimeout: 10 * time.Second}
}

func (c *Config) normalize() {
	d := Defaults()
	if c.MaxFramePayload <= 0 {
		c.MaxFramePayload = d.MaxFramePayload
	}
	if c.MaxFramePayload > AbsoluteMaxPayload {
		c.MaxFramePayload = AbsoluteMaxPayload
	}
	if c.DataChunk <= 0 || c.DataChunk > c.MaxFramePayload {
		c.DataChunk = min(d.DataChunk, c.MaxFramePayload)
	}
	if c.StreamWindow <= 0 {
		c.StreamWindow = d.StreamWindow
	}
	if c.ConnWindow < c.StreamWindow {
		c.ConnWindow = max(d.ConnWindow, c.StreamWindow)
	}
	if c.MaxStreams <= 0 {
		c.MaxStreams = d.MaxStreams
	}
	if c.WriteQueue <= 0 {
		c.WriteQueue = d.WriteQueue
	}
	if c.WriteTimeout <= 0 {
		c.WriteTimeout = d.WriteTimeout
	}
	if c.PingTimeout <= 0 {
		c.PingTimeout = d.PingTimeout
	}
	c.Meta = c.Meta.norm()
	if c.Meta.MaxBytes > c.MaxFramePayload {
		c.Meta.MaxBytes = c.MaxFramePayload
	}
	if c.Logger == nil {
		c.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
}

// Session errors.
var (
	ErrSessionClosed  = errors.New("tunnel: session closed")
	ErrGoAway         = errors.New("tunnel: session is draining (GOAWAY)")
	ErrTooManyStreams = errors.New("tunnel: too many concurrent streams")
	ErrStreamClosed   = errors.New("tunnel: stream closed")
	ErrCtrlOverflow   = errors.New("tunnel: peer not draining control frames")
)

// ProtocolError is a connection-level violation that terminates the session.
type ProtocolError struct {
	Code ErrorCode
	Msg  string
}

func (e *ProtocolError) Error() string {
	return fmt.Sprintf("tunnel protocol error (%s): %s", e.Code, e.Msg)
}

// RemoteError is a connection-level ERROR received from the peer.
type RemoteError struct {
	Code ErrorCode
	Msg  string
}

func (e *RemoteError) Error() string { return fmt.Sprintf("tunnel peer error (%s): %s", e.Code, e.Msg) }

// StreamError describes an abnormal end of one stream.
type StreamError struct {
	Code   ErrorCode
	Remote bool // true if the peer reset the stream
}

func (e *StreamError) Error() string {
	who := "local"
	if e.Remote {
		who = "remote"
	}
	return fmt.Sprintf("tunnel stream reset (%s, %s)", who, e.Code)
}

// Session multiplexes streams over one connection. Frames belonging to a
// stream travel through a single ordered queue so per-stream order is
// preserved; connection-level frames (PING, WINDOW_UPDATE, RESET, GOAWAY) use
// a separate priority queue.
type Session struct {
	conn net.Conn
	cfg  Config
	role Role

	ctrlCh chan []byte
	dataCh chan []byte

	done      chan struct{}
	closeReq  chan struct{} // graceful close requested: flush queues, then fail
	closeReqO sync.Once
	closeOnce sync.Once
	errMu     sync.Mutex
	err       error

	mu         sync.Mutex // guards streams, ids, goaway flags
	streams    map[uint32]*Stream
	lastOwnID  uint32
	lastPeerID uint32
	goawaySent bool
	goawayRecv bool
	openMu     sync.Mutex // serialises id allocation + OPEN enqueue (ids must hit the wire in order)
	acceptCh   chan *Stream
	active     atomic.Int64

	// connection-level flow control
	wmu     sync.Mutex // send window
	connSnd int64
	winCh   chan struct{}

	rmu         sync.Mutex // receive accounting
	connRcvOut  int64      // bytes received and not yet credited back
	connPending int64      // consumed bytes not yet announced

	// keepalive / RTT
	lastRecv  atomic.Int64 // unix nanos of last received frame
	pingMu    sync.Mutex
	pingSeq   uint64
	pingWait  map[uint64]chan time.Time
	goawayCh  chan struct{} // closed when GOAWAY is first received
	goawayO   sync.Once
	drained   chan struct{}
	drainOnce sync.Once
	onClose   func(error)
	bytesIn   atomic.Uint64
	bytesOut  atomic.Uint64
}

// NewSession starts a session on conn and takes ownership of it. The
// negotiated cfg must match on both sides (the edge dictates it in HELLO).
func NewSession(conn net.Conn, role Role, cfg Config) *Session {
	cfg.normalize()
	s := &Session{
		conn: conn, cfg: cfg, role: role,
		ctrlCh: make(chan []byte, 256), dataCh: make(chan []byte, cfg.WriteQueue),
		done: make(chan struct{}), closeReq: make(chan struct{}), streams: map[uint32]*Stream{},
		acceptCh: make(chan *Stream, cfg.MaxStreams),
		connSnd:  int64(cfg.ConnWindow), winCh: make(chan struct{}),
		pingWait: map[uint64]chan time.Time{}, drained: make(chan struct{}), goawayCh: make(chan struct{}),
	}
	s.lastRecv.Store(time.Now().UnixNano())
	go s.writeLoop()
	go s.readLoop()
	if cfg.PingInterval > 0 {
		go s.keepalive()
	}
	return s
}

// OnClose registers a callback invoked once when the session ends.
func (s *Session) OnClose(f func(error)) {
	s.mu.Lock()
	s.onClose = f
	s.mu.Unlock()
	select {
	case <-s.done:
		f(s.Err())
	default:
	}
}

func (s *Session) ownParityFirst() uint32 {
	if s.role == RoleServer {
		return 1
	}
	return 2
}

func (s *Session) isOwnID(id uint32) bool { return id%2 == s.ownParityFirst()%2 }

// Done is closed when the session has terminated.
func (s *Session) Done() <-chan struct{} { return s.done }

// Err returns the terminal error (nil while running).
func (s *Session) Err() error {
	s.errMu.Lock()
	defer s.errMu.Unlock()
	return s.err
}

// ActiveStreams returns the number of open streams.
func (s *Session) ActiveStreams() int { return int(s.active.Load()) }

// BytesIn/BytesOut report raw framed bytes (diagnostic only, not metering).
func (s *Session) BytesIn() uint64  { return s.bytesIn.Load() }
func (s *Session) BytesOut() uint64 { return s.bytesOut.Load() }

// Close terminates the session and resets every stream. Frames already queued
// (for example a GOAWAY or RESET) are flushed first, bounded to one second so
// a stalled peer cannot block shutdown.
func (s *Session) Close() error {
	s.closeReqO.Do(func() { close(s.closeReq) })
	t := time.NewTimer(time.Second)
	defer t.Stop()
	select {
	case <-s.done:
	case <-t.C:
		s.fail(ErrSessionClosed)
	}
	return nil
}

func (s *Session) fail(err error) {
	s.closeOnce.Do(func() {
		s.errMu.Lock()
		s.err = err
		s.errMu.Unlock()
		close(s.done)
		_ = s.conn.Close()
		s.mu.Lock()
		sts := make([]*Stream, 0, len(s.streams))
		for _, st := range s.streams {
			sts = append(sts, st)
		}
		cb := s.onClose
		s.mu.Unlock()
		for _, st := range sts {
			st.terminate(fmt.Errorf("%w: %v", ErrSessionClosed, err))
		}
		s.markDrainedIfIdle()
		if cb != nil {
			cb(err)
		}
	})
}

// ---- write path ------------------------------------------------------------

func (s *Session) encode(f Frame) ([]byte, error) {
	return AppendFrame(make([]byte, 0, HeaderSize+len(f.Payload)), f, s.cfg.MaxFramePayload)
}

// sendCtrl enqueues a connection-level frame without blocking: a peer that
// leaves >256 control frames unwritten is stalled or abusive.
func (s *Session) sendCtrl(f Frame) {
	b, err := s.encode(f)
	if err != nil {
		s.fail(err)
		return
	}
	select {
	case s.ctrlCh <- b:
	case <-s.done:
	default:
		s.fail(ErrCtrlOverflow)
	}
}

// sendData enqueues an ordered stream frame, blocking (backpressure) until
// there is queue space, ctx is done or the session ends.
func (s *Session) sendData(ctx context.Context, f Frame) error {
	b, err := s.encode(f)
	if err != nil {
		return err
	}
	select {
	case s.dataCh <- b:
		return nil
	case <-s.done:
		return s.sessionErr()
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Session) sessionErr() error {
	if e := s.Err(); e != nil {
		return fmt.Errorf("%w: %v", ErrSessionClosed, e)
	}
	return ErrSessionClosed
}

func (s *Session) writeLoop() {
	bw := bufio.NewWriterSize(s.conn, ioBufSize)
	write := func(b []byte) bool {
		_ = s.conn.SetWriteDeadline(time.Now().Add(s.cfg.WriteTimeout))
		if _, err := bw.Write(b); err != nil {
			s.fail(fmt.Errorf("write: %w", err))
			return false
		}
		s.bytesOut.Add(uint64(len(b)))
		if len(s.ctrlCh) == 0 && len(s.dataCh) == 0 {
			if err := bw.Flush(); err != nil {
				s.fail(fmt.Errorf("flush: %w", err))
				return false
			}
		}
		return true
	}
	for {
		var b []byte
		select { // control frames first
		case b = <-s.ctrlCh:
		default:
			select {
			case b = <-s.ctrlCh:
			case b = <-s.dataCh:
			case <-s.closeReq:
				s.flushAll(write)
				s.fail(ErrSessionClosed)
				return
			case <-s.done:
				return
			}
		}
		if !write(b) {
			return
		}
	}
}

// flushAll writes everything already queued (used by graceful Close).
func (s *Session) flushAll(write func([]byte) bool) {
	for {
		select {
		case b := <-s.ctrlCh:
			if !write(b) {
				return
			}
		case b := <-s.dataCh:
			if !write(b) {
				return
			}
		default:
			return
		}
	}
}

// ---- read path -------------------------------------------------------------

func (s *Session) readLoop() {
	br := bufio.NewReaderSize(s.conn, ioBufSize)
	for {
		f, err := ReadFrame(br, s.cfg.MaxFramePayload)
		if err != nil {
			if isProtocolDecodeErr(err) {
				s.violation(&ProtocolError{Code: codeForDecodeErr(err), Msg: err.Error()})
				return
			}
			s.fail(err)
			return
		}
		s.lastRecv.Store(time.Now().UnixNano())
		s.bytesIn.Add(uint64(HeaderSize + len(f.Payload)))
		if err := s.handle(f); err != nil {
			s.violation(err)
			return
		}
	}
}

func isProtocolDecodeErr(err error) bool {
	return errors.Is(err, ErrBadVersion) || errors.Is(err, ErrUnknownType) || errors.Is(err, ErrFrameTooLarge) ||
		errors.Is(err, ErrBadHeader) || errors.Is(err, ErrBadPayload) || errors.Is(err, ErrBadStreamID)
}

func codeForDecodeErr(err error) ErrorCode {
	if errors.Is(err, ErrFrameTooLarge) {
		return CodeFrameSizeError
	}
	return CodeProtocolError
}

// violation sends one bounded ERROR frame (best effort) and closes.
func (s *Session) violation(err error) {
	var pe *ProtocolError
	if errors.As(err, &pe) {
		if b, e := s.encode(ErrorFrame(pe.Code, pe.Msg)); e == nil {
			select {
			case s.ctrlCh <- b:
				// give the writer a moment to flush before the socket closes
				t := time.NewTimer(200 * time.Millisecond)
				select {
				case <-t.C:
				case <-s.done:
				}
				t.Stop()
			default:
			}
		}
	}
	s.fail(err)
}

func protoErr(code ErrorCode, format string, a ...any) error {
	return &ProtocolError{Code: code, Msg: fmt.Sprintf(format, a...)}
}

func (s *Session) handle(f Frame) error {
	switch f.Type {
	case TypePing:
		s.sendCtrl(Frame{Type: TypePong, Payload: f.Payload})
		return nil
	case TypePong:
		s.onPong(f.Payload)
		return nil
	case TypeGoAway:
		last, _, err := ParseGoAway(f.Payload)
		if err != nil {
			return protoErr(CodeProtocolError, "bad GOAWAY")
		}
		s.onGoAway(last)
		return nil
	case TypeError:
		code, msg, _ := ParseError(f.Payload)
		return &RemoteError{Code: code, Msg: msg}
	case TypeWindowUpdate:
		inc, err := ParseWindowUpdate(f.Payload)
		if err != nil {
			return protoErr(CodeProtocolError, "bad WINDOW_UPDATE")
		}
		if f.Stream == 0 {
			return s.addConnWindow(int64(inc))
		}
		if st := s.lookup(f.Stream); st != nil {
			st.addSendWindow(int64(inc))
		}
		return nil
	case TypeHello, TypeAuth, TypeAuthOK, TypeAuthError, TypeRegisterEndpoint, TypeRegisterOK:
		return protoErr(CodeProtocolError, "%s not valid after handshake", f.Type)
	}
	return s.handleStream(f)
}

func (s *Session) lookup(id uint32) *Stream {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.streams[id]
}

func (s *Session) handleStream(f Frame) error {
	if f.Type == TypeOpen {
		return s.handleOpen(f)
	}
	st := s.lookup(f.Stream)
	if st == nil {
		s.mu.Lock()
		var seen bool
		if s.isOwnID(f.Stream) {
			seen = f.Stream <= s.lastOwnID
		} else {
			seen = f.Stream <= s.lastPeerID
		}
		s.mu.Unlock()
		if !seen {
			return protoErr(CodeProtocolError, "%s on idle stream %d", f.Type, f.Stream)
		}
		// Stream already finished (reset/close race): ignore, but return the
		// connection-window credit that the sender spent on this DATA.
		if f.Type == TypeData {
			s.creditConn(len(f.Payload))
		}
		return nil
	}
	return st.receive(f)
}

func (s *Session) handleOpen(f Frame) error {
	if s.isOwnID(f.Stream) {
		return protoErr(CodeProtocolError, "peer opened stream %d with our parity", f.Stream)
	}
	s.mu.Lock()
	if f.Stream <= s.lastPeerID {
		s.mu.Unlock()
		return protoErr(CodeProtocolError, "stream id %d not monotonic", f.Stream)
	}
	s.lastPeerID = f.Stream
	refuse := s.goawaySent || len(s.streams) >= s.cfg.MaxStreams
	s.mu.Unlock()
	if refuse || len(f.Payload) > s.cfg.Meta.MaxBytes {
		code := CodeRefusedStream
		if len(f.Payload) > s.cfg.Meta.MaxBytes {
			code = CodeFrameSizeError
		}
		s.sendCtrl(ResetFrame(f.Stream, code))
		return nil
	}
	st := s.newStream(f.Stream)
	st.state, _ = StateIdle.Recv(EvOpen)
	st.OpenMeta = f.Payload
	s.mu.Lock()
	s.streams[f.Stream] = st
	s.mu.Unlock()
	s.active.Add(1)
	select {
	case s.acceptCh <- st:
	default: // accept queue full: shed load rather than buffer without bound
		st.Reset(CodeRefusedStream)
	}
	return nil
}

// ---- opening and accepting -------------------------------------------------

// Open starts a new stream carrying meta (encoded request metadata).
func (s *Session) Open(ctx context.Context, meta []byte) (*Stream, error) {
	if len(meta) > s.cfg.Meta.MaxBytes {
		return nil, ErrMetaTooLarge
	}
	s.openMu.Lock()
	defer s.openMu.Unlock()
	s.mu.Lock()
	switch {
	case s.goawaySent || s.goawayRecv:
		s.mu.Unlock()
		return nil, ErrGoAway
	case len(s.streams) >= s.cfg.MaxStreams:
		s.mu.Unlock()
		return nil, ErrTooManyStreams
	}
	select {
	case <-s.done:
		s.mu.Unlock()
		return nil, s.sessionErr()
	default:
	}
	id := s.lastOwnID + 2
	if s.lastOwnID == 0 {
		id = s.ownParityFirst()
	}
	if id >= 0x7ffffffe {
		s.mu.Unlock()
		return nil, ErrGoAway // id space exhausted: caller must reconnect
	}
	s.lastOwnID = id
	st := s.newStream(id)
	st.state, _ = StateIdle.Send(EvOpen)
	s.streams[id] = st
	s.mu.Unlock()
	s.active.Add(1)
	if err := s.sendData(ctx, Frame{Type: TypeOpen, Stream: id, Payload: meta}); err != nil {
		st.terminate(err)
		return nil, err
	}
	return st, nil
}

// Accept returns the next peer-opened stream.
func (s *Session) Accept(ctx context.Context) (*Stream, error) {
	select {
	case st := <-s.acceptCh:
		return st, nil
	case <-s.done:
		return nil, s.sessionErr()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// ---- connection-level flow control -----------------------------------------

func (s *Session) addConnWindow(inc int64) error {
	s.wmu.Lock()
	if s.connSnd+inc > 0x7fffffff {
		s.wmu.Unlock()
		return protoErr(CodeFlowControlError, "connection window overflow")
	}
	s.connSnd += inc
	old := s.winCh
	s.winCh = make(chan struct{})
	s.wmu.Unlock()
	close(old)
	return nil
}

// connWinChan returns a channel closed at the next connection window increase.
func (s *Session) connWinChan() <-chan struct{} {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	return s.winCh
}

// takeConn removes up to n bytes of connection send window.
func (s *Session) takeConn(n int) int {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if s.connSnd <= 0 {
		return 0
	}
	if int64(n) > s.connSnd {
		n = int(s.connSnd)
	}
	s.connSnd -= int64(n)
	return n
}

// noteRecv records n received DATA bytes against the connection window.
func (s *Session) noteRecv(n int) error {
	s.rmu.Lock()
	defer s.rmu.Unlock()
	if s.connRcvOut+int64(n) > int64(s.cfg.ConnWindow) {
		return protoErr(CodeFlowControlError, "connection receive window exceeded")
	}
	s.connRcvOut += int64(n)
	return nil
}

// creditConn returns n bytes of connection window to the peer once the
// application consumed (or discarded) them; updates are batched at half window.
func (s *Session) creditConn(n int) {
	s.rmu.Lock()
	s.connRcvOut -= int64(n)
	if s.connRcvOut < 0 {
		s.connRcvOut = 0
	}
	s.connPending += int64(n)
	var inc int64
	if s.connPending >= int64(s.cfg.ConnWindow/2) {
		inc, s.connPending = s.connPending, 0
	}
	s.rmu.Unlock()
	if inc > 0 {
		s.sendCtrl(WindowUpdate(0, uint32(inc)))
	}
}

// ---- GOAWAY, ping ----------------------------------------------------------

// GoAwayReceived is closed once the peer has sent GOAWAY.
func (s *Session) GoAwayReceived() <-chan struct{} { return s.goawayCh }

func (s *Session) onGoAway(last uint32) {
	s.goawayO.Do(func() { close(s.goawayCh) })
	s.mu.Lock()
	s.goawayRecv = true
	var refused []*Stream
	for id, st := range s.streams {
		if s.isOwnID(id) && id > last {
			refused = append(refused, st)
		}
	}
	s.mu.Unlock()
	for _, st := range refused {
		st.terminate(&StreamError{Code: CodeRefusedStream, Remote: true})
	}
}

func (s *Session) onPong(p []byte) {
	if len(p) != 8 {
		return
	}
	var tok uint64
	for _, b := range p {
		tok = tok<<8 | uint64(b)
	}
	s.pingMu.Lock()
	ch := s.pingWait[tok]
	delete(s.pingWait, tok)
	s.pingMu.Unlock()
	if ch != nil {
		ch <- time.Now()
	}
}

// Ping measures the round trip to the peer.
func (s *Session) Ping(ctx context.Context) (time.Duration, error) {
	ch := make(chan time.Time, 1)
	s.pingMu.Lock()
	s.pingSeq++
	tok := s.pingSeq
	s.pingWait[tok] = ch
	s.pingMu.Unlock()
	start := time.Now()
	s.sendCtrl(PingFrame(TypePing, tok))
	select {
	case t := <-ch:
		return t.Sub(start), nil
	case <-ctx.Done():
		s.pingMu.Lock()
		delete(s.pingWait, tok)
		s.pingMu.Unlock()
		return 0, ctx.Err()
	case <-s.done:
		return 0, s.sessionErr()
	}
}
