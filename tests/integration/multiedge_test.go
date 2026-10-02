package integration

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/127ohoh1/core/client/origin"
	"github.com/127ohoh1/core/client/session"
	edgeapp "github.com/127ohoh1/core/dataplane/app"
	"github.com/127ohoh1/core/dataplane/routing"
	"github.com/127ohoh1/core/internal/clock"
	"github.com/127ohoh1/core/internal/config"
	"github.com/127ohoh1/core/internal/testenv"
)

// twoEdges starts edge-1 (via testenv) and edge-2 sharing one directory, the
// in-process stand-in for the Redis directory (which passes the same contract).
func twoEdges(t *testing.T, dir routing.TunnelDirectory, lease time.Duration) (*testenv.Env, *edgeapp.App) {
	t.Helper()
	mut := func(c *config.Edge) {
		c.InternalAddr = "127.0.0.1:0"
		c.LeaseTTL = config.Duration(lease)
		c.UsageFlush = config.Duration(50 * time.Millisecond)
	}
	env := testenv.New(t, testenv.Options{Edge: mut, EdgeOpts: func(o *edgeapp.Options) { o.Directory = dir }})
	return env, env.StartSecondEdge(dir, mut)
}

func viaEdge(t *testing.T, edge *edgeapp.App, host, method, path string, body io.Reader, hdr map[string]string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(method, "http://"+edge.Addrs().Ingress+path, body)
	req.Host = host + "." + testenv.BaseDomain
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := (&http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func TestRequestToTheWrongEdgeIsForwardedAndMeteredOnce(t *testing.T) {
	dir := routing.NewInMemory(clock.Real{})
	env, edgeB := twoEdges(t, dir, 30*time.Second)
	var seen http.Header
	origin := env.Origin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		io.Copy(io.Discard, r.Body)
		w.Write(blob(40_000))
	}))
	x := env.Expose(env.NewIdentity(), origin.URL, "") // tunnel terminates on edge-1

	resp, body := viaEdge(t, edgeB, x.Endpoint.Hostname, "POST", "/hop", strings.NewReader(strings.Repeat("u", 10_000)), nil)
	if resp.StatusCode != 200 || len(body) != 40_000 || resp.Header.Get("X-127ohoh1-Hop") != "1" {
		t.Fatalf("%d %d hop=%q", resp.StatusCode, len(body), resp.Header.Get("X-127ohoh1-Hop"))
	}
	// The origin sees the real client and scheme, not the forwarding edge.
	if seen.Get("X-Forwarded-For") != "127.0.0.1" || seen.Get("X-Forwarded-Proto") != "http" {
		t.Fatalf("forwarded headers lost across the hop: %v", seen)
	}
	// Usage: 10 kB up + 40 kB down = 50 kB, once, not per edge.
	env.Edge.Usage.Flush(bg)
	edgeB.Usage.Flush(bg)
	if u, _ := usageOf(t, env, x.Endpoint.ID); u != 50_000 {
		t.Fatalf("metered %d bytes for a 50,000-byte exchange (double counted at the forwarding edge?)", u)
	}
	if l := metricLineOf(edgeB, `edge_interedge_requests_total{result="ok"}`); !strings.HasSuffix(l, " 1") {
		t.Fatalf("hop not visible in metrics: %q", l)
	}
	// Requests straight to the owner are not marked as hopped.
	if r, _ := viaEdge(t, env.Edge, x.Endpoint.Hostname, "GET", "/", nil, nil); r.Header.Get("X-127ohoh1-Hop") != "" {
		t.Fatal("local request marked as forwarded")
	}
	// Unknown names are still a plain 404 from either edge.
	if r, _ := viaEdge(t, edgeB, "nobody-here-0000", "GET", "/", nil, nil); r.StatusCode != 404 || r.Header.Get("X-127ohoh1-Error") != "endpoint_not_found" {
		t.Fatalf("%d %q", r.StatusCode, r.Header.Get("X-127ohoh1-Error"))
	}
}

func metricLineOf(edge *edgeapp.App, prefix string) string {
	var sb strings.Builder
	edge.Metrics.WriteText(&sb)
	for _, l := range strings.Split(sb.String(), "\n") {
		if strings.HasPrefix(l, prefix) {
			return l
		}
	}
	return ""
}

func TestInternalListenerRequiresTheHopSecretAndNeverForwardsAgain(t *testing.T) {
	dir := routing.NewInMemory(clock.Real{})
	env, edgeB := twoEdges(t, dir, 30*time.Second)
	origin := env.Origin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "secret") }))
	x := env.Expose(env.NewIdentity(), origin.URL, "")

	do := func(edge *edgeapp.App, token string) (int, string) {
		req, _ := http.NewRequest("GET", "http://"+edge.Addrs().Internal+"/", nil)
		req.Host = x.Endpoint.Hostname + "." + testenv.BaseDomain
		if token != "" {
			req.Header.Set("X-127ohoh1-Internal-Auth", token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	for _, tok := range []string{"", "wrong", "Bearer " + testenv.ServiceToken} {
		if code, body := do(env.Edge, tok); code != 403 || strings.Contains(body, "secret") {
			t.Errorf("token %q: %d %s", tok, code, body)
		}
	}
	if code, body := do(env.Edge, testenv.ServiceToken); code != 200 || body != "secret" {
		t.Fatalf("%d %s", code, body)
	}
	// A hop that lands on an edge without the tunnel is answered locally: no forwarding loops.
	if code, _ := do(edgeB, testenv.ServiceToken); code != 404 {
		t.Fatalf("hop to an edge that does not own the tunnel: %d", code)
	}
}

// A client that reconnects to a different edge takes the endpoint over; the old
// edge notices through its lease and routes new requests to the new owner.
func TestTunnelMovesToAnotherEdge(t *testing.T) {
	dir := routing.NewInMemory(clock.Real{})
	env, edgeB := twoEdges(t, dir, 600*time.Millisecond)
	o1 := env.Origin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "via-origin-1") }))
	o2 := env.Origin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "via-origin-2") }))
	id := env.NewIdentity()
	x1 := env.Expose(id, o1.URL, "") // tunnel on edge-1
	if _, b := viaEdge(t, env.Edge, x1.Endpoint.Hostname, "GET", "/", nil, nil); b != "via-origin-1" {
		t.Fatal(b)
	}

	// The client "fails over": a new tunnel for the same endpoint on edge-2.
	cred, err := env.API(id).TunnelCredentials(bg, x1.Endpoint.ID)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := session.Connect(bg, edgeB.Addrs().Tunnel, env.TLSConfig(), cred, id, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	h := newOriginHandler(t, o2.URL)
	go session.Serve(bg, conn.Session, h)
	t.Cleanup(func() { conn.Session.Close() })

	// Edge-1 loses its lease, stops routing locally and hands off to edge-2.
	eventually(t, "edge-1 stops serving locally", 10*time.Second, func() bool {
		_, ok := env.Edge.Registry.ByHostname(x1.Endpoint.Hostname)
		return !ok
	})
	for _, e := range []*edgeapp.App{env.Edge, edgeB} {
		resp, body := viaEdge(t, e, x1.Endpoint.Hostname, "GET", "/", nil, nil)
		if resp.StatusCode != 200 || body != "via-origin-2" {
			t.Fatalf("edge %s: %d %q", e.Cfg.EdgeID, resp.StatusCode, body)
		}
	}
	if !x1.Conn.Session.Draining() {
		eventually(t, "old session told to drain", 5*time.Second, x1.Conn.Session.Draining)
	}
}

type failingDir struct {
	inner routing.TunnelDirectory
	down  atomic.Bool
}

var errDirDown = errors.New("directory down")

func (f *failingDir) Claim(c contextT, o routing.Owner, ttl time.Duration) (*routing.Owner, error) {
	if f.down.Load() {
		return nil, errDirDown
	}
	return f.inner.Claim(c, o, ttl)
}
func (f *failingDir) Heartbeat(c contextT, e, s string, ttl time.Duration) error {
	if f.down.Load() {
		return errDirDown
	}
	return f.inner.Heartbeat(c, e, s, ttl)
}
func (f *failingDir) Release(c contextT, e, s string) error {
	if f.down.Load() {
		return errDirDown
	}
	return f.inner.Release(c, e, s)
}
func (f *failingDir) Lookup(c contextT, h string) (routing.Owner, error) {
	if f.down.Load() {
		return routing.Owner{}, errDirDown
	}
	return f.inner.Lookup(c, h)
}

// Redis/directory unavailable: local traffic and even new local tunnels keep
// working; only cross-edge routing degrades, with an explicit platform error.
func TestDirectoryOutageDegradesGracefully(t *testing.T) {
	dir := &failingDir{inner: routing.NewInMemory(clock.Real{})}
	env, edgeB := twoEdges(t, dir, 30*time.Second)
	origin := env.Origin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "local-ok") }))
	x := env.Expose(env.NewIdentity(), origin.URL, "")

	dir.down.Store(true)
	// Established tunnel, local routing: unaffected.
	if _, b := viaEdge(t, env.Edge, x.Endpoint.Hostname, "GET", "/", nil, nil); b != "local-ok" {
		t.Fatalf("local routing broke during a directory outage: %q", b)
	}
	// A brand-new tunnel can still register locally (degraded: no cross-edge visibility).
	y := env.Expose(env.NewIdentity(), origin.URL, "")
	if _, b := viaEdge(t, env.Edge, y.Endpoint.Hostname, "GET", "/", nil, nil); b != "local-ok" {
		t.Fatalf("new tunnel during outage: %q", b)
	}
	// Cross-edge routing cannot work and says so.
	resp, _ := viaEdge(t, edgeB, x.Endpoint.Hostname, "GET", "/", nil, nil)
	if resp.StatusCode != 503 || resp.Header.Get("X-127ohoh1-Error") != "directory_unavailable" {
		t.Fatalf("%d %q", resp.StatusCode, resp.Header.Get("X-127ohoh1-Error"))
	}
	if l := metricLineOf(edgeB, `edge_directory_errors_total{op="lookup"}`); l == "" || strings.HasSuffix(l, " 0") {
		t.Fatalf("outage not visible in metrics: %q", l)
	}
	// Recovery: cross-edge routing works again once the directory returns and leases are refreshed.
	dir.down.Store(false)
	dir.inner.Claim(bg, routing.Owner{EndpointID: x.Endpoint.ID, Hostname: x.Endpoint.Hostname, EdgeID: "edge-1", SessionID: x.Conn.SessionID, InternalAddr: env.Edge.Addrs().Internal}, 30*time.Second)
	eventually(t, "cross-edge routing recovered", 5*time.Second, func() bool {
		r, b := viaEdge(t, edgeB, x.Endpoint.Hostname, "GET", "/", nil, nil)
		return r.StatusCode == 200 && b == "local-ok"
	})
}

type contextT = context.Context

func newOriginHandler(t *testing.T, url string) session.StreamHandler {
	t.Helper()
	target, err := origin.ParseTarget(url, false)
	if err != nil {
		t.Fatal(err)
	}
	return origin.New(target, origin.Options{})
}

// Quota overshoot across an edge handoff is bounded by the usage that had not
// yet reached the ledger when the handoff happened. This test measures it in
// the worst case (no periodic flush at all) and with a realistic flush.
func TestQuotaOvershootAcrossEdgeHandoffIsBounded(t *testing.T) {
	const quota = 2_000_000
	run := func(t *testing.T, flush, settle time.Duration) (ledger, unreported int64) {
		dir := routing.NewInMemory(clock.Real{})
		mut := func(c *config.Edge) {
			c.InternalAddr = "127.0.0.1:0"
			c.UsageFlush = config.Duration(flush)
			c.LeaseTTL = config.Duration(600 * time.Millisecond)
			c.PolicyRefresh = config.Duration(time.Hour) // isolate the effect of usage reporting
		}
		env := testenv.New(t, testenv.Options{Catalog: scaledCatalog(quota), Edge: mut, EdgeOpts: func(o *edgeapp.Options) { o.Directory = dir }})
		edgeB := env.StartSecondEdge(dir, mut)
		o := env.Origin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for i := 0; i < 200; i++ { // wants 6.4 MB
				if _, err := w.Write(blob(32_000)); err != nil {
					return
				}
			}
		}))
		id := env.NewIdentity()
		x := env.Expose(id, o.URL, "") // tunnel on edge-1

		pull := func(edge *edgeapp.App, want int64) int64 {
			req, _ := http.NewRequest("GET", "http://"+edge.Addrs().Ingress+"/", nil)
			req.Host = x.Endpoint.Hostname + "." + testenv.BaseDomain
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			n, _ := io.CopyN(io.Discard, resp.Body, want)
			return n
		}
		pull(env.Edge, 1_200_000) // the caller reads 1.2 MB; edge-1 has *counted* what it moved, incl. bytes in flight
		time.Sleep(settle)        // time between the traffic and the handoff
		// Unreported at handoff = bytes edge-1 counted that the ledger does not know yet.
		reported, _ := usageOf(t, env, x.Endpoint.ID)
		unreported = env.Edge.Usage.Meter(x.Endpoint.ID).Used() - reported

		// Handoff: the client fails over to edge-2 (edge-1 is superseded and drains).
		cred, _ := env.API(id).TunnelCredentials(bg, x.Endpoint.ID)
		conn, err := session.Connect(bg, edgeB.Addrs().Tunnel, env.TLSConfig(), cred, id, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		go session.Serve(bg, conn.Session, newOriginHandler(t, o.URL))
		t.Cleanup(func() { conn.Session.Close() })
		eventually(t, "edge-1 handed off", 10*time.Second, func() bool { _, ok := env.Edge.Registry.ByHostname(x.Endpoint.Hostname); return !ok })

		// Keep pulling from the new owner until the platform refuses.
		for i := 0; i < 20; i++ {
			resp, _ := viaEdge(t, edgeB, x.Endpoint.Hostname, "GET", "/", nil, nil)
			if resp.StatusCode == 429 {
				break
			}
		}
		env.Edge.Usage.Flush(bg)
		edgeB.Usage.Flush(bg)
		time.Sleep(200 * time.Millisecond)
		ledger, _ = usageOf(t, env, x.Endpoint.ID)
		return ledger, unreported
	}

	// Worst case: periodic flushing is off and the handoff follows the traffic
	// immediately, so edge-2 starts from a ledger that knows nothing of edge-1's 1.2 MB.
	worst, worstUnreported := run(t, time.Hour, 0)
	// Normal case: usage is flushed every 100 ms and the handoff comes a moment later.
	good, goodUnreported := run(t, 100*time.Millisecond, 400*time.Millisecond)
	t.Logf("MEASURED quota=%d | worst case: unreported_at_handoff=%d ledger_total=%d overshoot=%d | flushed before handoff: unreported_at_handoff=%d ledger_total=%d overshoot=%d",
		quota, worstUnreported, worst, worst-quota, goodUnreported, good, good-quota)
	// Design bound: overshoot <= usage the old owner had counted but not yet reported at the handoff
	// (this includes bytes in flight up to the flow-control window, not just what the caller read)
	// plus one 16 KiB chunk per in-flight stream on the new owner.
	if over := worst - quota; over > worstUnreported+2*16*1024 {
		t.Fatalf("worst-case overshoot %d exceeds the design bound (unreported at handoff %d + chunks)", over, worstUnreported)
	}
	if over := good - quota; over > goodUnreported+4*16*1024 {
		t.Fatalf("overshoot %d exceeds the design bound when usage was flushed before the handoff (unreported %d)", over, goodUnreported)
	}
	if goodUnreported > 64*1024 {
		t.Fatalf("with a 100 ms flush almost nothing should be unreported at the handoff, got %d", goodUnreported)
	}
}
