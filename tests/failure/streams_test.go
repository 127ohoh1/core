package failure

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/127ohoh1/core/internal/config"
	"github.com/127ohoh1/core/internal/testenv"
)

func eventually(t *testing.T, what string, d time.Duration, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if f() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for: %s", what)
}

// A slow public client must throttle the origin through flow control instead of
// making the edge buffer the whole response.
func TestSlowPublicClientAppliesBackpressure(t *testing.T) {
	env := testenv.New(t, testenv.Options{})
	var written atomic.Int64
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	origin := env.Origin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		chunk := bytes.Repeat([]byte("x"), 32<<10)
		for i := 0; i < 8000; i++ { // 256 MB if never blocked
			if _, err := w.Write(chunk); err != nil {
				return
			}
			written.Add(int64(len(chunk)))
			select {
			case <-stop:
				return
			default:
			}
		}
	}))
	x := env.Expose(env.NewIdentity(), origin.URL, "")

	resp, err := env.Request(x.Endpoint.Hostname, "GET", "/big", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	io.CopyN(io.Discard, resp.Body, 1<<20) // read 1 MB, then stall
	time.Sleep(700 * time.Millisecond)
	w1 := written.Load()
	time.Sleep(300 * time.Millisecond)
	w2 := written.Load()
	// The origin is blocked: nothing (or almost nothing) more is written while the
	// client is stalled, and the total is bounded by windows + socket buffers,
	// nowhere near the 256 MB the origin wanted to send.
	if w2-w1 > 1<<20 {
		t.Fatalf("origin kept writing while the client stalled: %d -> %d", w1, w2)
	}
	if w2 > 48<<20 {
		t.Fatalf("no backpressure: origin wrote %d bytes to a stalled client", w2)
	}
}

// One stalled stream must not head-of-line block the session.
func TestStalledStreamDoesNotBlockOthers(t *testing.T) {
	env := testenv.New(t, testenv.Options{})
	origin := env.Origin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/big" {
			chunk := bytes.Repeat([]byte("x"), 32<<10)
			for i := 0; i < 4000; i++ {
				if _, err := w.Write(chunk); err != nil {
					return
				}
			}
			return
		}
		fmt.Fprint(w, "fast")
	}))
	x := env.Expose(env.NewIdentity(), origin.URL, "")
	slow, err := env.Request(x.Endpoint.Hostname, "GET", "/big", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer slow.Body.Close() // never read: this stream stays flow-control blocked
	time.Sleep(200 * time.Millisecond)
	for i := 0; i < 20; i++ {
		start := time.Now()
		resp, body := env.Get(x.Endpoint.Hostname, "/quick")
		if resp.StatusCode != 200 || body != "fast" {
			t.Fatalf("%d %q", resp.StatusCode, body)
		}
		if time.Since(start) > 2*time.Second {
			t.Fatalf("request %d took %v behind a stalled stream", i, time.Since(start))
		}
	}
}

// Caller cancels mid-request: the cancellation must reach the origin.
func TestPublicCancelPropagatesToOrigin(t *testing.T) {
	env := testenv.New(t, testenv.Options{})
	started := make(chan struct{})
	cancelled := make(chan struct{})
	origin := env.Origin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		select {
		case <-r.Context().Done():
			close(cancelled)
		case <-time.After(10 * time.Second):
		}
	}))
	x := env.Expose(env.NewIdentity(), origin.URL, "")

	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, "GET", "http://"+env.Edge.Addrs().Ingress+"/hang", nil)
	req.Host = x.Endpoint.Hostname + "." + testenv.BaseDomain
	done := make(chan error, 1)
	go func() { _, err := http.DefaultClient.Do(req); done <- err }()
	<-started
	cancel()
	<-done
	select {
	case <-cancelled:
	case <-time.After(5 * time.Second):
		t.Fatal("origin request context was never cancelled")
	}
	eventually(t, "stream slot released", 3*time.Second, func() bool { return x.Conn.Session.ActiveStreams() == 0 })
	if x.Conn.Session.Err() != nil {
		t.Fatal(x.Conn.Session.Err())
	}
}

func TestSlowOriginGetsGatewayTimeout(t *testing.T) {
	env := testenv.New(t, testenv.Options{Edge: func(c *config.Edge) { c.ResponseHeaderTimeout = config.Duration(300 * time.Millisecond) }})
	origin := env.Origin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}))
	x := env.Expose(env.NewIdentity(), origin.URL, "")
	start := time.Now()
	resp, _ := env.Get(x.Endpoint.Hostname, "/")
	if resp.StatusCode != 504 || resp.Header.Get("X-127ohoh1-Error") != "origin_timeout" {
		t.Fatalf("%d %s", resp.StatusCode, resp.Header.Get("X-127ohoh1-Error"))
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("timeout took %v", time.Since(start))
	}
	eventually(t, "stream slot released", 3*time.Second, func() bool { return x.Conn.Session.ActiveStreams() == 0 })
}

// If the origin dies mid-response the caller must observe an error, never a
// body that looks complete.
func TestOriginClosesMidResponseIsNotSilentlyTruncated(t *testing.T) {
	env := testenv.New(t, testenv.Options{})
	origin := env.Origin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000000")
		w.Write(bytes.Repeat([]byte("a"), 1000))
		w.(http.Flusher).Flush()
		conn, _, _ := w.(http.Hijacker).Hijack()
		conn.Close() // origin dies with 999,000 bytes still promised
	}))
	x := env.Expose(env.NewIdentity(), origin.URL, "")
	resp, err := env.Request(x.Endpoint.Hostname, "GET", "/", nil, nil)
	if err != nil {
		return // failing at header time is also acceptable
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err == nil {
		t.Fatalf("truncated response read as complete (%d bytes)", len(b))
	}
}

func TestSessionLossFailsInFlightRequestsClearly(t *testing.T) {
	env := testenv.New(t, testenv.Options{})
	started := make(chan struct{})
	origin := env.Origin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
	}))
	x := env.Expose(env.NewIdentity(), origin.URL, "")
	res := make(chan *http.Response, 1)
	go func() { r, _ := env.Request(x.Endpoint.Hostname, "GET", "/", nil, nil); res <- r }()
	<-started
	x.Conn.Session.Close() // connection lost mid-request
	r := <-res
	if r == nil {
		return
	}
	defer r.Body.Close()
	if r.StatusCode != 502 || r.Header.Get("X-127ohoh1-Error") != "tunnel_lost" {
		t.Fatalf("want 502 tunnel_lost, got %d %q", r.StatusCode, r.Header.Get("X-127ohoh1-Error"))
	}
}

func TestStreamLimitYieldsTunnelBusyNotCrash(t *testing.T) {
	env := testenv.New(t, testenv.Options{Edge: func(c *config.Edge) { c.MaxStreamsPerSession = 4 }})
	release := make(chan struct{})
	var inflight atomic.Int32
	origin := env.Origin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inflight.Add(1)
		<-release
		fmt.Fprint(w, "done")
	}))
	x := env.Expose(env.NewIdentity(), origin.URL, "")
	var wg sync.WaitGroup
	codes := make(chan int, 12)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := env.Request(x.Endpoint.Hostname, "GET", "/", nil, nil)
			if err != nil {
				codes <- -1
				return
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			codes <- resp.StatusCode
		}()
	}
	eventually(t, "4 requests in flight", 5*time.Second, func() bool { return inflight.Load() >= 4 })
	time.Sleep(200 * time.Millisecond)
	close(release)
	wg.Wait()
	close(codes)
	ok, busy := 0, 0
	for c := range codes {
		switch c {
		case 200:
			ok++
		case 503:
			busy++
		default:
			t.Errorf("unexpected status %d", c)
		}
	}
	if ok < 4 || busy < 1 {
		t.Fatalf("ok=%d busy=%d", ok, busy)
	}
	if x.Conn.Session.Err() != nil {
		t.Fatalf("session died under load: %v", x.Conn.Session.Err())
	}
}

func TestOversizedRequestHeadersRejected(t *testing.T) {
	env := testenv.New(t, testenv.Options{})
	origin := env.Origin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }))
	x := env.Expose(env.NewIdentity(), origin.URL, "")
	c, err := net.Dial("tcp", env.Edge.Addrs().Ingress)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: %s.%s\r\nX-Big: %s\r\n\r\n", x.Endpoint.Hostname, testenv.BaseDomain, strings.Repeat("a", 64<<10))
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	b, _ := io.ReadAll(io.LimitReader(c, 256))
	if !strings.Contains(string(b), "431") {
		t.Fatalf("expected 431, got %q", b)
	}
}

// An actively-streaming response (SSE, a long-poll body, a large download)
// must not be cut off by RequestMaxDuration just because it runs longer than
// that deadline: only inactivity (RequestIdleTimeout) may end it.
func TestActiveStreamingResponseIsNotCutAtMaxDuration(t *testing.T) {
	env := testenv.New(t, testenv.Options{Edge: func(c *config.Edge) {
		c.RequestMaxDuration = config.Duration(150 * time.Millisecond)
		c.RequestIdleTimeout = config.Duration(5 * time.Second) // steady activity must keep resetting this too
	}})
	const chunks = 8
	origin := env.Origin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fl := w.(http.Flusher)
		for i := 0; i < chunks; i++ {
			fmt.Fprintf(w, "chunk-%d\n", i)
			fl.Flush()
			time.Sleep(60 * time.Millisecond) // each gap is small, but the total run is well past MaxDuration
		}
	}))
	x := env.Expose(env.NewIdentity(), origin.URL, "")
	resp, err := env.Request(x.Endpoint.Hostname, "GET", "/", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("response cut short even though it was making progress: %v (got %q)", err, body)
	}
	var want strings.Builder
	for i := 0; i < chunks; i++ {
		fmt.Fprintf(&want, "chunk-%d\n", i)
	}
	if string(body) != want.String() {
		t.Fatalf("got %q, want %q", body, want.String())
	}
}

// Symmetric case for the upload side: a slow-but-active request body must not
// be cut off by RequestMaxDuration either.
func TestActiveRequestBodyIsNotCutAtMaxDuration(t *testing.T) {
	env := testenv.New(t, testenv.Options{Edge: func(c *config.Edge) {
		c.RequestMaxDuration = config.Duration(150 * time.Millisecond)
		c.RequestIdleTimeout = config.Duration(5 * time.Second)
	}})
	origin := env.Origin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(b)
	}))
	x := env.Expose(env.NewIdentity(), origin.URL, "")

	const parts = 8
	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		for i := 0; i < parts; i++ {
			fmt.Fprintf(pw, "part-%d\n", i)
			time.Sleep(60 * time.Millisecond) // chunked, unknown length: streamed as it's written
		}
	}()
	resp, err := env.Request(x.Endpoint.Hostname, "POST", "/", pr, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("upload cut short even though it was making progress: %v", err)
	}
	var want strings.Builder
	for i := 0; i < parts; i++ {
		fmt.Fprintf(&want, "part-%d\n", i)
	}
	if string(got) != want.String() {
		t.Fatalf("got %q, want %q", got, want.String())
	}
}

// A stream that truly goes silent (no progress in either direction) must
// still be cut off, proving the MaxDuration fix only changed *what* ends a
// stalled exchange (RequestIdleTimeout), not whether anything does.
func TestStalledStreamIsCutAtIdleTimeout(t *testing.T) {
	env := testenv.New(t, testenv.Options{Edge: func(c *config.Edge) {
		c.RequestIdleTimeout = config.Duration(200 * time.Millisecond)
		c.RequestMaxDuration = config.Duration(5 * time.Second) // must not be what fires here
	}})
	origin := env.Origin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "first")
		w.(http.Flusher).Flush()
		<-r.Context().Done() // then go silent until the edge gives up on us
	}))
	x := env.Expose(env.NewIdentity(), origin.URL, "")
	start := time.Now()
	resp, err := env.Request(x.Endpoint.Hostname, "GET", "/", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if _, err := io.ReadAll(resp.Body); err == nil {
		t.Fatal("stalled response was not cut off")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("idle timeout took too long: %v", elapsed)
	}
	eventually(t, "stream slot released", 3*time.Second, func() bool { return x.Conn.Session.ActiveStreams() == 0 })
}

// Slowloris: a client that never finishes its headers must not hold resources forever.
func TestSlowlorisHeaderTimeout(t *testing.T) {
	env := testenv.New(t, testenv.Options{Edge: func(c *config.Edge) { c.RequestHeaderTimeout = config.Duration(300 * time.Millisecond) }})
	c, err := net.Dial("tcp", env.Edge.Addrs().Ingress)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprint(c, "GET / HTTP/1.1\r\nHost: x.127ohoh1.test\r\nX-Slow: ")
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	start := time.Now()
	io.Copy(io.Discard, c) // server must give up and close
	if time.Since(start) > 2*time.Second {
		t.Fatalf("slow client held the connection for %v", time.Since(start))
	}
}

var bg = context.Background()
