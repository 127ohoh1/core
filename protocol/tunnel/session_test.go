package tunnel

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func tcpPair(t testing.TB) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ch := make(chan net.Conn, 1)
	go func() { c, _ := ln.Accept(); ch <- c }()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return <-ch, c
}

func pair(t testing.TB, cfg Config) (srv, cli *Session) {
	t.Helper()
	a, b := tcpPair(t)
	srv, cli = NewSession(a, RoleServer, cfg), NewSession(b, RoleClient, cfg)
	t.Cleanup(func() { srv.Close(); cli.Close() })
	return
}

var bg = context.Background()

func testCfg() Config {
	c := Defaults()
	c.PingInterval = 0
	return c
}

func mustAccept(t testing.TB, s *Session) *Stream {
	t.Helper()
	ctx, cancel := context.WithTimeout(bg, 5*time.Second)
	defer cancel()
	st, err := s.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func TestEchoAndHalfClose(t *testing.T) {
	srv, cli := pair(t, testCfg())
	go func() { // client side: echo server
		st := mustAccept(t, cli)
		if string(st.OpenMeta) != "hello" {
			t.Errorf("meta %q", st.OpenMeta)
		}
		st.SendResponse([]byte("ok"))
		io.Copy(st, st)
		st.CloseWrite()
	}()
	st, err := srv.Open(bg, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if st.ID() != 1 {
		t.Fatalf("server opens odd ids, got %d", st.ID())
	}
	meta, err := st.WaitResponse(bg)
	if err != nil || string(meta) != "ok" {
		t.Fatalf("%q %v", meta, err)
	}
	st.Write([]byte("ping"))
	st.CloseWrite() // request body done; response continues independently
	got, err := io.ReadAll(st)
	if err != nil || string(got) != "ping" {
		t.Fatalf("%q %v", got, err)
	}
	select {
	case <-st.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("stream did not terminate after both half-closes")
	}
	if srv.ActiveStreams() != 0 {
		t.Fatalf("active = %d", srv.ActiveStreams())
	}
}

func TestClientOpensEvenIDs(t *testing.T) {
	srv, cli := pair(t, testCfg())
	go func() {
		if st, err := srv.Accept(bg); err == nil {
			st.Close()
		}
	}()
	st, err := cli.Open(bg, []byte("x"))
	if err != nil || st.ID() != 2 {
		t.Fatalf("%v %d", err, st.ID())
	}
	st2, err := cli.Open(bg, []byte("y"))
	if err != nil {
		t.Fatalf("second open: %v (srv=%v cli=%v)", err, srv.Err(), cli.Err())
	}
	if st2.ID() != 4 {
		t.Fatalf("ids must increase by 2: %d", st2.ID())
	}
}

// Many concurrent streams over one session; every response must match its own request.
func TestConcurrentStreamsNoMixups(t *testing.T) {
	srv, cli := pair(t, testCfg())
	go func() {
		for {
			st, err := cli.Accept(bg)
			if err != nil {
				return
			}
			go func() {
				st.SendResponse([]byte("r"))
				io.Copy(st, st) // echo body
				st.CloseWrite()
			}()
		}
	}()
	const N = 100
	var wg sync.WaitGroup
	errs := make(chan error, N)
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			payload := bytes.Repeat([]byte(fmt.Sprintf("stream-%03d;", i)), 500+i*13) // varied sizes, 5-25 KiB
			st, err := srv.Open(bg, []byte("m"))
			if err != nil {
				errs <- err
				return
			}
			go func() { st.Write(payload); st.CloseWrite() }()
			got, err := io.ReadAll(st)
			if err != nil || !bytes.Equal(got, payload) {
				errs <- fmt.Errorf("stream %d: mismatch (%d vs %d bytes, err=%v)", i, len(got), len(payload), err)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// A payload far larger than every window must flow completely and intact.
func TestLargeTransferUnderFlowControl(t *testing.T) {
	cfg := testCfg()
	cfg.StreamWindow, cfg.ConnWindow = 32<<10, 64<<10
	srv, cli := pair(t, cfg)
	payload := make([]byte, 8<<20)
	rand.Read(payload)
	go func() {
		st := mustAccept(t, cli)
		st.SendResponse([]byte("r"))
		st.Write(payload)
		st.CloseWrite()
	}()
	st, _ := srv.Open(bg, []byte("m"))
	st.CloseWrite()
	got, err := io.ReadAll(st)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("transfer corrupt: %d bytes err=%v", len(got), err)
	}
}

// A reader that never reads must stall the writer at the window, not cause
// unbounded buffering on the receiver.
func TestBackpressureBoundsReceiverBuffer(t *testing.T) {
	cfg := testCfg()
	cfg.StreamWindow, cfg.ConnWindow = 64<<10, 256<<10
	srv, cli := pair(t, cfg)
	stC := make(chan *Stream, 1)
	go func() { st, _ := cli.Accept(bg); stC <- st }()
	st, _ := srv.Open(bg, []byte("m"))
	rst := <-stC

	wrote := make(chan int, 1)
	ctx, cancel := context.WithCancel(bg)
	defer cancel()
	go func() {
		n, _ := st.WriteContext(ctx, make([]byte, 4<<20))
		wrote <- n
	}()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		rst.mu.Lock()
		buffered := rst.rqBytes
		rst.mu.Unlock()
		if buffered >= cfg.StreamWindow {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond) // give an overflowing sender the chance to overflow
	rst.mu.Lock()
	buffered := rst.rqBytes
	rst.mu.Unlock()
	if buffered > cfg.StreamWindow {
		t.Fatalf("receiver buffered %d > window %d", buffered, cfg.StreamWindow)
	}
	if buffered < cfg.StreamWindow {
		t.Fatalf("sender should have filled the window, buffered %d", buffered)
	}
	cancel() // unblock the writer
	if n := <-wrote; n > cfg.StreamWindow+cfg.DataChunk {
		t.Fatalf("writer got %d bytes through a %d window", n, cfg.StreamWindow)
	}
}

func TestResetPropagatesAndIsolatesStreams(t *testing.T) {
	srv, cli := pair(t, testCfg())
	go func() {
		for {
			st, err := cli.Accept(bg)
			if err != nil {
				return
			}
			go func() {
				if string(st.OpenMeta) == "victim" {
					st.Reset(CodeCancel)
					return
				}
				st.SendResponse([]byte("r"))
				io.Copy(st, st)
				st.CloseWrite()
			}()
		}
	}()
	good, _ := srv.Open(bg, []byte("good"))
	victim, _ := srv.Open(bg, []byte("victim"))
	_, err := io.ReadAll(victim)
	var se *StreamError
	if !errors.As(err, &se) || se.Code != CodeCancel || !se.Remote {
		t.Fatalf("victim: %v", err)
	}
	select {
	case <-victim.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("victim context not cancelled")
	}
	// The unrelated stream still works.
	good.Write([]byte("still alive"))
	good.CloseWrite()
	got, err := io.ReadAll(good)
	if err != nil || string(got) != "still alive" {
		t.Fatalf("%q %v", got, err)
	}
	if srv.Err() != nil {
		t.Fatalf("session failed: %v", srv.Err())
	}
}

func TestLocalCancelReachesPeer(t *testing.T) {
	srv, cli := pair(t, testCfg())
	stC := make(chan *Stream, 1)
	go func() { st, _ := cli.Accept(bg); stC <- st }()
	st, _ := srv.Open(bg, []byte("m"))
	peer := <-stC
	st.Reset(CodeCancel)
	select {
	case <-peer.Context().Done():
	case <-time.After(3 * time.Second):
		t.Fatal("peer stream context not cancelled")
	}
	if _, err := peer.Write([]byte("x")); err == nil {
		t.Fatal("write after peer reset must fail")
	}
}

func TestSessionLossFailsInFlightStreams(t *testing.T) {
	srv, cli := pair(t, testCfg())
	stC := make(chan *Stream, 1)
	go func() { st, _ := cli.Accept(bg); stC <- st }()
	st, _ := srv.Open(bg, []byte("m"))
	<-stC
	cli.Close()
	_, err := io.ReadAll(st)
	if err == nil || errors.Is(err, io.EOF) {
		t.Fatalf("in-flight stream must fail clearly, got %v", err)
	}
	if !errors.Is(err, ErrSessionClosed) {
		t.Fatalf("want ErrSessionClosed, got %v", err)
	}
	if _, err := srv.Open(bg, []byte("x")); err == nil {
		t.Fatal("open on dead session")
	}
}

func TestMaxStreamsRefused(t *testing.T) {
	cfg := testCfg()
	cfg.MaxStreams = 2
	srv, cli := pair(t, cfg)
	go func() {
		for {
			if _, err := cli.Accept(bg); err != nil {
				return
			}
		}
	}()
	for i := 0; i < 2; i++ {
		if _, err := srv.Open(bg, []byte("m")); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := srv.Open(bg, []byte("m")); !errors.Is(err, ErrTooManyStreams) {
		t.Fatalf("local limit: %v", err)
	}
}

// A peer exceeding its limit gets REFUSED_STREAM for the extra stream while
// the session and existing streams survive.
func TestPeerExceedingStreamLimitIsRefused(t *testing.T) {
	scfg := testCfg()
	ccfg := testCfg()
	ccfg.MaxStreams = 1000 // client believes it may open many
	scfg.MaxStreams = 2
	a, b := tcpPair(t)
	srv, cli := NewSession(a, RoleServer, scfg), NewSession(b, RoleClient, ccfg)
	defer srv.Close()
	defer cli.Close()
	var streams []*Stream
	for i := 0; i < 4; i++ {
		st, err := cli.Open(bg, []byte("m"))
		if err != nil {
			t.Fatal(err)
		}
		streams = append(streams, st)
	}
	refused := 0
	for _, st := range streams[2:] {
		_, err := io.ReadAll(st)
		var se *StreamError
		if errors.As(err, &se) && se.Code == CodeRefusedStream {
			refused++
		}
	}
	if refused != 2 || srv.Err() != nil || cli.Err() != nil {
		t.Fatalf("refused=%d srv=%v cli=%v", refused, srv.Err(), cli.Err())
	}
}

// ---- protocol violations close the connection with one bounded ERROR --------

func rawServer(t *testing.T) (*Session, net.Conn) {
	t.Helper()
	a, b := tcpPair(t)
	s := NewSession(a, RoleServer, testCfg())
	t.Cleanup(func() { s.Close(); b.Close() })
	return s, b
}

func expectViolation(t *testing.T, s *Session, peer net.Conn, wantCode ErrorCode) {
	t.Helper()
	peer.SetReadDeadline(time.Now().Add(3 * time.Second))
	f, err := ReadFrame(peer, 1<<16)
	if err != nil || f.Type != TypeError {
		t.Fatalf("expected ERROR frame, got %+v %v", f, err)
	}
	if code, _, _ := ParseError(f.Payload); code != wantCode {
		t.Fatalf("code %v want %v", code, wantCode)
	}
	select {
	case <-s.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("session not closed after violation")
	}
	var pe *ProtocolError
	if !errors.As(s.Err(), &pe) {
		t.Fatalf("err %v", s.Err())
	}
}

func TestViolationOversizeFrame(t *testing.T) {
	s, peer := rawServer(t)
	peer.Write(hdr(1, byte(TypeData), 0, 0, 2, 1<<20)) // declares 1 MiB
	expectViolation(t, s, peer, CodeFrameSizeError)
}

func TestViolationWrongParity(t *testing.T) {
	s, peer := rawServer(t)
	b, _ := AppendFrame(nil, Frame{Type: TypeOpen, Stream: 1, Payload: []byte("m")}, 1<<16) // odd = server's own parity
	peer.Write(b)
	expectViolation(t, s, peer, CodeProtocolError)
}

func TestViolationNonMonotonicStreamID(t *testing.T) {
	s, peer := rawServer(t)
	for _, id := range []uint32{4, 2} {
		b, _ := AppendFrame(nil, Frame{Type: TypeOpen, Stream: id, Payload: []byte("m")}, 1<<16)
		peer.Write(b)
	}
	expectViolation(t, s, peer, CodeProtocolError)
}

func TestViolationFrameOnIdleStream(t *testing.T) {
	s, peer := rawServer(t)
	b, _ := AppendFrame(nil, Frame{Type: TypeData, Stream: 8, Payload: []byte("m")}, 1<<16)
	peer.Write(b)
	expectViolation(t, s, peer, CodeProtocolError)
}

func TestViolationHandshakeFrameAfterHandshake(t *testing.T) {
	s, peer := rawServer(t)
	b, _ := AppendFrame(nil, Frame{Type: TypeAuth, Payload: []byte("{}")}, 1<<16)
	peer.Write(b)
	expectViolation(t, s, peer, CodeProtocolError)
}

func TestViolationConnWindowOverflow(t *testing.T) {
	cfg := testCfg()
	cfg.StreamWindow, cfg.ConnWindow = 16<<10, 16<<10
	a, b := tcpPair(t)
	s := NewSession(a, RoleServer, cfg)
	defer s.Close()
	defer b.Close()
	w := func(f Frame) { x, _ := AppendFrame(nil, f, 1<<16); b.Write(x) }
	w(Frame{Type: TypeOpen, Stream: 2, Payload: []byte("m")})
	w(Frame{Type: TypeOpen, Stream: 4, Payload: []byte("m")})
	w(Frame{Type: TypeData, Stream: 2, Payload: make([]byte, 10<<10)})
	w(Frame{Type: TypeData, Stream: 4, Payload: make([]byte, 10<<10)}) // conn total 20 KiB > 16 KiB
	expectViolation(t, s, b, CodeFlowControlError)
}

// Exceeding only the *stream* window resets that stream, not the connection.
func TestStreamWindowOverflowResetsStreamOnly(t *testing.T) {
	cfg := testCfg()
	cfg.StreamWindow, cfg.ConnWindow = 8<<10, 1<<20
	a, b := tcpPair(t)
	s := NewSession(a, RoleServer, cfg)
	defer s.Close()
	defer b.Close()
	w := func(f Frame) { x, _ := AppendFrame(nil, f, 1<<16); b.Write(x) }
	w(Frame{Type: TypeOpen, Stream: 2, Payload: []byte("m")})
	w(Frame{Type: TypeData, Stream: 2, Payload: make([]byte, 6<<10)})
	w(Frame{Type: TypeData, Stream: 2, Payload: make([]byte, 6<<10)})
	b.SetReadDeadline(time.Now().Add(3 * time.Second))
	f, err := ReadFrame(b, 1<<16)
	if err != nil || f.Type != TypeReset || f.Stream != 2 {
		t.Fatalf("want RESET on stream 2, got %+v %v", f, err)
	}
	if code, _ := ParseReset(f.Payload); code != CodeFlowControlError {
		t.Fatalf("code %v", code)
	}
	if s.Err() != nil {
		t.Fatalf("connection must survive: %v", s.Err())
	}
}

func TestPingRoundTrip(t *testing.T) {
	srv, _ := pair(t, testCfg())
	ctx, cancel := context.WithTimeout(bg, 3*time.Second)
	defer cancel()
	if rtt, err := srv.Ping(ctx); err != nil || rtt <= 0 {
		t.Fatalf("%v %v", rtt, err)
	}
}

func TestKeepaliveTimeoutClosesSilentPeer(t *testing.T) {
	cfg := testCfg()
	cfg.PingInterval, cfg.PingTimeout = 50*time.Millisecond, 100*time.Millisecond
	a, b := tcpPair(t)
	defer b.Close() // b never speaks: a silent, half-dead peer
	s := NewSession(a, RoleServer, cfg)
	defer s.Close()
	select {
	case <-s.Done():
		if !errors.Is(s.Err(), ErrKeepalive) {
			t.Fatalf("err %v", s.Err())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("silent peer not detected")
	}
}

func TestKeepaliveKeepsIdleSessionAlive(t *testing.T) {
	cfg := testCfg()
	cfg.PingInterval, cfg.PingTimeout = 40*time.Millisecond, 200*time.Millisecond
	srv, cli := pair(t, cfg)
	time.Sleep(600 * time.Millisecond)
	if srv.Err() != nil || cli.Err() != nil {
		t.Fatalf("idle but healthy session died: %v %v", srv.Err(), cli.Err())
	}
}

func TestGoAwayDrain(t *testing.T) {
	srv, cli := pair(t, testCfg())
	stC := make(chan *Stream, 1)
	go func() { st, _ := cli.Accept(bg); stC <- st }()
	st, _ := srv.Open(bg, []byte("m"))
	peer := <-stC

	srv.GoAway(CodeShutdown)
	srv.GoAway(CodeShutdown) // idempotent
	if _, err := srv.Open(bg, []byte("n")); !errors.Is(err, ErrGoAway) {
		t.Fatalf("open after GOAWAY: %v", err)
	}
	// The peer learns of the drain and can no longer open streams either.
	deadline := time.Now().Add(3 * time.Second)
	for !cli.Draining() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if _, err := cli.Open(bg, []byte("n")); !errors.Is(err, ErrGoAway) {
		t.Fatalf("peer open after GOAWAY: %v", err)
	}
	// The existing stream still completes.
	drained := make(chan struct{})
	go func() { srv.Drain(bg, CodeShutdown); close(drained) }()
	peer.SendResponse([]byte("r"))
	peer.Write([]byte("done"))
	peer.CloseWrite()
	st.CloseWrite()
	got, err := io.ReadAll(st)
	if err != nil || string(got) != "done" {
		t.Fatalf("%q %v", got, err)
	}
	select {
	case <-drained:
	case <-time.After(3 * time.Second):
		t.Fatal("drain did not complete after streams finished")
	}
}

func TestDrainDeadlineResetsStragglers(t *testing.T) {
	srv, cli := pair(t, testCfg())
	stC := make(chan *Stream, 1)
	go func() { st, _ := cli.Accept(bg); stC <- st }()
	st, _ := srv.Open(bg, []byte("m"))
	<-stC
	ctx, cancel := context.WithTimeout(bg, 100*time.Millisecond)
	defer cancel()
	srv.Drain(ctx, CodeShutdown) // stream never finishes
	if _, err := io.ReadAll(st); err == nil {
		t.Fatal("straggler must be failed at the drain deadline")
	}
	<-srv.Done()
}

func TestNoGoroutineLeakAfterClose(t *testing.T) {
	before := numGoroutines()
	for i := 0; i < 5; i++ {
		srv, cli := pair(t, testCfg())
		go func() {
			st, _ := cli.Accept(bg)
			if st != nil {
				st.Close()
			}
		}()
		st, _ := srv.Open(bg, []byte("m"))
		st.Close()
		srv.Close()
		cli.Close()
	}
	deadline := time.Now().Add(3 * time.Second)
	for numGoroutines() > before+2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if n := numGoroutines(); n > before+2 {
		t.Fatalf("goroutines leaked: before=%d after=%d", before, n)
	}
}

func numGoroutines() int { return runtimeNumGoroutine() }
