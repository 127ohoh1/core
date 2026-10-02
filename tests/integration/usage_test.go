package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/127ohoh1/core/controlplane/endpoint"
	"github.com/127ohoh1/core/controlplane/policy"
	"github.com/127ohoh1/core/internal/clock"
	"github.com/127ohoh1/core/internal/config"
	"github.com/127ohoh1/core/internal/testenv"
)

func blob(n int) []byte { return bytes.Repeat([]byte("x"), n) }

// Scenario 6: the canonical free tier (100,000 B/s, 2 s burst) is enforced
// from resolved policy, within a documented tolerance.
func TestFreeTierBandwidthEnforced(t *testing.T) {
	env := testenv.New(t, testenv.Options{Catalog: policy.DefaultCatalog()})
	origin := env.Origin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(blob(500_000)) }))
	x := env.Expose(env.NewIdentity(), origin.URL, "")

	start := time.Now()
	resp, body := env.Get(x.Endpoint.Hostname, "/")
	el := time.Since(start).Seconds()
	if resp.StatusCode != 200 || len(body) != 500_000 {
		t.Fatalf("%d %d", resp.StatusCode, len(body))
	}
	// 500,000 bytes with a 200,000-byte burst: (500,000-200,000)/100,000 = 3.0 s.
	// Tolerance: -10% / +35% (scheduling, chunking, loopback).
	if el < 2.7 || el > 4.1 {
		t.Fatalf("500 kB took %.2fs, expected ~3.0s at 100,000 B/s", el)
	}
	if l := metricLine(env, "edge_bandwidth_throttle_seconds_total"); strings.HasSuffix(l, " 0") || l == "" {
		t.Fatalf("throttle time not recorded: %q", l)
	}
}

// Opening more streams must not multiply the plan rate.
func TestConcurrencyDoesNotMultiplyBandwidth(t *testing.T) {
	env := testenv.New(t, testenv.Options{Catalog: policy.DefaultCatalog()})
	origin := env.Origin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(blob(150_000)) }))
	x := env.Expose(env.NewIdentity(), origin.URL, "")
	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < 4; i++ { // 4 streams x 150 kB = 600 kB total
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, body := env.Get(x.Endpoint.Hostname, "/")
			if len(body) != 150_000 {
				t.Errorf("short body %d", len(body))
			}
		}()
	}
	wg.Wait()
	el := time.Since(start).Seconds()
	// Shared bucket: (600,000-200,000)/100,000 = 4.0 s, not the ~1 s four independent buckets would give.
	if el < 3.5 || el > 5.2 {
		t.Fatalf("4 concurrent streams took %.2fs, expected ~4.0s (shared rate)", el)
	}
}

func scaledCatalog(monthly int64) *policy.Catalog {
	ps := policy.Canonical()
	for i := range ps {
		ps[i].BandwidthBytesPerSecond = 500_000_000
		if ps[i].ID == policy.PlanFree {
			ps[i].MonthlyTransferBytes = monthly
		}
	}
	return policy.NewCatalog(ps...)
}

func usageOf(t *testing.T, env *testenv.Env, epID string) (used, limit int64) {
	t.Helper()
	req, _ := http.NewRequest("GET", env.CPURL()+"/v1/endpoints/"+epID+"/usage", nil)
	req.Header.Set("Authorization", "Bearer "+testenv.ServiceToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var u struct {
		Used  int64 `json:"used_bytes"`
		Limit int64 `json:"limit_bytes"`
	}
	json.NewDecoder(resp.Body).Decode(&u)
	return u.Used, u.Limit
}

// Scenario 7 (reduced-scale fixture): bidirectional counting, prompt platform
// refusal once exhausted, and consistent termination of in-flight streams.
func TestMonthlyQuotaCountsBothDirectionsAndRefusesPromptly(t *testing.T) {
	const quota = 1_000_000
	env := testenv.New(t, testenv.Options{
		Catalog: scaledCatalog(quota),
		Edge:    func(c *config.Edge) { c.UsageFlush = config.Duration(100 * time.Millisecond) },
	})
	origin := env.Origin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Write(blob(300_000))
	}))
	x := env.Expose(env.NewIdentity(), origin.URL, "")

	// 200 kB request body + 300 kB response = 500 kB metered (both directions, once each).
	resp, err := env.Request(x.Endpoint.Hostname, "POST", "/", bytes.NewReader(blob(200_000)), nil)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	eventually(t, "usage reported", 5*time.Second, func() bool { u, _ := usageOf(t, env, x.Endpoint.ID); return u == 500_000 })
	if u, l := usageOf(t, env, x.Endpoint.ID); u != 500_000 || l != quota {
		t.Fatalf("ledger: used %d limit %d (headers/framing must not be counted)", u, l)
	}

	// Second request: 200 kB up + 300 kB down = 1,000,000 total: exactly at the limit.
	resp, _ = env.Request(x.Endpoint.Hostname, "POST", "/", bytes.NewReader(blob(200_000)), nil)
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	// Now new requests are refused promptly with a platform-generated 429.
	start := time.Now()
	resp, _ = env.Get(x.Endpoint.Hostname, "/")
	if resp.StatusCode != 429 || resp.Header.Get("X-127ohoh1-Error") != "quota_exhausted" {
		t.Fatalf("%d %q", resp.StatusCode, resp.Header.Get("X-127ohoh1-Error"))
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("refusal took %v: must not hang", time.Since(start))
	}
	if ra := resp.Header.Get("Retry-After"); ra == "" {
		t.Fatal("missing Retry-After (seconds until the period ends)")
	}
	eventually(t, "ledger reflects exhaustion", 5*time.Second, func() bool { u, _ := usageOf(t, env, x.Endpoint.ID); return u >= quota })
}

// In-flight streams are cut at the next chunk boundary once the quota runs
// out, bounding overshoot to about one chunk per stream.
func TestQuotaExhaustedMidStreamTerminatesConsistently(t *testing.T) {
	const quota = 1_000_000
	env := testenv.New(t, testenv.Options{Catalog: scaledCatalog(quota), Edge: func(c *config.Edge) { c.UsageFlush = config.Duration(100 * time.Millisecond) }})
	origin := env.Origin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for i := 0; i < 100; i++ { // wants to send 3.2 MB
			if _, err := w.Write(blob(32_000)); err != nil {
				return
			}
		}
	}))
	x := env.Expose(env.NewIdentity(), origin.URL, "")
	resp, err := env.Request(x.Endpoint.Hostname, "GET", "/big", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	n, err := io.Copy(io.Discard, resp.Body)
	if err == nil {
		t.Fatalf("a response that outran the quota must not look complete (%d bytes)", n)
	}
	if n < quota-1000 || n > quota+2*16*1024 {
		t.Fatalf("delivered %d bytes for a %d quota (overshoot bound is one 16 KiB chunk)", n, quota)
	}
	if x.Conn.Session.Err() != nil {
		t.Fatal("quota exhaustion must not kill the tunnel")
	}
}

// Scenario 13: duplicate usage batches are applied once.
func TestDuplicateUsageBatchNotDoubleApplied(t *testing.T) {
	env := testenv.New(t, testenv.Options{})
	ep, _ := env.API(env.NewIdentity()).CreateEndpoint(bg, "")
	period := time.Now().UTC().Format("2006-01") + "-01T00:00:00Z"
	body := fmt.Sprintf(`{"edge_id":"edge-x","batch_id":"edge-x.boot.1","items":[{"endpoint_id":%q,"period_start":%q,"bytes":12345}]}`, ep.ID, period)
	post := func() (int, string, string) {
		req, _ := http.NewRequest("POST", env.CPURL()+"/v1/usage/batches", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+testenv.ServiceToken)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, resp.Header.Get("Idempotent-Replayed"), string(b)
	}
	for i := 0; i < 3; i++ {
		code, replayed, b := post()
		if code != 200 || (i == 0) == (replayed == "true") {
			t.Fatalf("#%d: %d replayed=%q %s", i, code, replayed, b)
		}
	}
	if u, _ := usageOf(t, env, ep.ID); u != 12345 {
		t.Fatalf("used %d after 3 deliveries of one batch", u)
	}
	// Service authentication is required.
	req, _ := http.NewRequest("POST", env.CPURL()+"/v1/usage/batches", strings.NewReader(body))
	if resp, _ := http.DefaultClient.Do(req); resp.StatusCode != 401 {
		t.Fatalf("unauthenticated usage batch: %d", resp.StatusCode)
	}
}

// Graceful edge shutdown flushes usage: nothing metered is lost.
func TestUsageFlushedOnGracefulShutdown(t *testing.T) {
	env := testenv.New(t, testenv.Options{Edge: func(c *config.Edge) { c.UsageFlush = config.Duration(time.Hour) }}) // no periodic flush
	origin := env.Origin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(blob(77_777)) }))
	x := env.Expose(env.NewIdentity(), origin.URL, "")
	env.Get(x.Endpoint.Hostname, "/")
	if u, _ := usageOf(t, env, x.Endpoint.ID); u != 0 {
		t.Fatalf("usage reported before any flush: %d", u)
	}
	env.StopEdge(5 * time.Second)
	if u, _ := usageOf(t, env, x.Endpoint.ID); u != 77_777 {
		t.Fatalf("shutdown did not flush usage: %d", u)
	}
}

func eventuallyCtx(t *testing.T, what string, f func() bool) {
	t.Helper()
	eventually(t, what, 10*time.Second, f)
}

// Scenarios 11 & 12: a free name is released after 24 h without an
// authenticated tunnel, and not before; a connected tunnel keeps it alive; a
// reconnect resets the clock; the old owner cannot use the released endpoint.
func TestFreeNameInactivityReaping(t *testing.T) {
	clk := clock.NewFake(time.Now())
	env := testenv.New(t, testenv.Options{Clock: clk})
	origin := env.Origin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "hi") }))
	id := env.NewIdentity()
	x := env.Expose(id, origin.URL, "")
	epID := x.Endpoint.ID

	state := func() endpoint.Endpoint {
		e, err := env.CP.Endpoints.GetByID(bg, epID)
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	// advance moves time in one step, lets the edge refresh policy and report presence, then lets the reaper run.
	advance := func(d time.Duration) {
		clk.Advance(d)
		env.Edge.PolicyCache.RefreshAll(bg)
		env.Edge.Presence.Heartbeat()
		env.Edge.Presence.Flush(bg)
		env.CP.Endpoints.Reap(bg)
	}

	// 30 hours with the tunnel connected: heartbeats keep last_active_at fresh.
	for h := 0; h < 30; h++ {
		advance(time.Hour)
		eventuallyCtx(t, "heartbeat", func() bool { return clk.Now().Sub(state().LastActiveAt) < time.Minute })
	}
	if state().State != endpoint.StateActive {
		t.Fatal("a connected free endpoint was released")
	}

	// Disconnect: the 24 h window starts now.
	x.Conn.Session.Close()
	<-x.Done
	eventuallyCtx(t, "disconnect reported", func() bool { env.Edge.Presence.Flush(bg); return !state().Connected })
	disc := state().LastActiveAt

	advance(23*time.Hour + 59*time.Minute)
	if state().State != endpoint.StateActive {
		t.Fatalf("released early (inactive for %v)", clk.Now().Sub(disc))
	}
	// Reconnecting before expiry keeps the name and resets the clock.
	x2 := env.Expose(id, origin.URL, epID)
	eventuallyCtx(t, "reconnect reported", func() bool { env.Edge.Presence.Flush(bg); return state().Connected })
	x2.Conn.Session.Close()
	<-x2.Done
	eventuallyCtx(t, "second disconnect", func() bool {
		env.Edge.Presence.Flush(bg)
		return !state().Connected && state().LastActiveAt.After(disc)
	})

	cred, err := env.API(id).TunnelCredentials(bg, epID) // issued now, used after release below
	if err != nil {
		t.Fatal(err)
	}
	advance(23*time.Hour + 59*time.Minute + 59*time.Second)
	if state().State != endpoint.StateActive {
		t.Fatal("reconnect did not reset the inactivity clock")
	}
	advance(time.Second) // 24 h exactly
	if state().State != endpoint.StateReleased {
		t.Fatalf("not released after 24h inactivity: %s", state().State)
	}

	// Scenario 12: the old owner cannot use the released endpoint.
	if _, err := env.API(id).TunnelCredentials(bg, epID); err == nil {
		t.Fatal("credential issued for a released endpoint")
	}
	if _, err := connectWith(env, id, cred); err == nil {
		t.Fatal("a credential issued before release opened a tunnel afterwards")
	}
	if resp, _ := env.Get(x.Endpoint.Hostname, "/"); resp.StatusCode == 200 {
		t.Fatal("released hostname still serves")
	}
	// A fresh registration yields a new endpoint id.
	fresh, err := env.API(id).CreateEndpoint(bg, "")
	if err != nil || fresh.ID == epID {
		t.Fatalf("%v %+v", err, fresh)
	}
	_ = context.Background
}
