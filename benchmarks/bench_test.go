// Package benchmarks holds reproducible load and performance measurements.
// Methodology, machine description and results are in benchmarks/methodology.md
// and benchmarks/results/. Nothing here is a claim: run it and read the output.
//
//	go test -run '^$' -bench . -benchtime 3s ./benchmarks          # request benchmarks
//	OHOH_BENCH_IDLE=2000 go test -run TestIdleTunnels -v ./benchmarks   # idle tunnels
package benchmarks

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/127ohoh1/core/client/api"
	cid "github.com/127ohoh1/core/client/identity"
	"github.com/127ohoh1/core/client/origin"
	"github.com/127ohoh1/core/client/session"
	"github.com/127ohoh1/core/controlplane/policy"
	"github.com/127ohoh1/core/internal/config"
	"github.com/127ohoh1/core/internal/testenv"
)

var bg = context.Background()

func pct(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	i := int(float64(len(sorted)-1) * p)
	return sorted[i]
}

// benchEnv starts the full system with limits high enough that the *proxy*, not
// the plan, is what is measured (bandwidth 1000x, burst scaled with it).
func benchEnv(tb testing.TB, edge func(*config.Edge), cp func(*config.ControlPlane)) *testenv.Env {
	// The plan limiter is part of the product but must not be the bottleneck here:
	// scale bandwidth to 10 GB/s so the proxy is what is measured. (An earlier
	// run at the 1000x fixture showed the token bucket itself holding a transfer at
	// 99.95-100.04 MB/s, i.e. limiter accuracy of about +/-0.05%.)
	ps := policy.Canonical()
	for i := range ps {
		ps[i].BandwidthBytesPerSecond *= 100_000
		ps[i].MonthlyTransferBytes *= 100_000
	}
	return testenv.New(tb, testenv.Options{
		Catalog: policy.NewCatalog(ps...),
		Edge: func(c *config.Edge) {
			c.MaxSessions = 100000
			c.MaxStreamsPerSession = 1024
			if edge != nil {
				edge(c)
			}
		},
		CP: func(c *config.ControlPlane) {
			c.AuthRatePerMinute = 10_000_000
			c.MaxEndpointsPerPrincipal = 100
			if cp != nil {
				cp(c)
			}
		},
	})
}

// ---- request latency and throughput -----------------------------------------

func runLatency(b *testing.B, parallelism int, body []byte, respSize int) {
	env := benchEnv(b, nil, nil)
	origin := env.Origin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Write(make([]byte, respSize))
	}))
	x := env.Expose(env.NewIdentity(), origin.URL, "")
	host := x.Endpoint.Hostname + "." + testenv.BaseDomain
	url := "http://" + env.Edge.Addrs().Ingress + "/"
	client := &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: parallelism * 2, MaxConnsPerHost: parallelism * 2}}
	do := func() time.Duration {
		req, _ := http.NewRequest("POST", url, bytes.NewReader(body))
		req.Host = host
		t0 := time.Now()
		resp, err := client.Do(req)
		if err != nil {
			b.Error(err)
			return 0
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return time.Since(t0)
	}
	for i := 0; i < 200; i++ { // warm-up
		do()
	}
	var mu sync.Mutex
	lat := make([]time.Duration, 0, b.N)
	var next atomic.Int64
	b.ResetTimer()
	start := time.Now()
	var wg sync.WaitGroup
	for w := 0; w < parallelism; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var local []time.Duration
			for next.Add(1) <= int64(b.N) {
				local = append(local, do())
			}
			mu.Lock()
			lat = append(lat, local...)
			mu.Unlock()
		}()
	}
	wg.Wait()
	el := time.Since(start)
	b.StopTimer()
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	b.ReportMetric(float64(pct(lat, .50).Microseconds()), "p50_us")
	b.ReportMetric(float64(pct(lat, .95).Microseconds()), "p95_us")
	b.ReportMetric(float64(pct(lat, .99).Microseconds()), "p99_us")
	b.ReportMetric(float64(b.N)/el.Seconds(), "req/s")
	if len(body)+respSize > 0 {
		b.ReportMetric(float64(b.N)*float64(len(body)+respSize)/el.Seconds()/1e6, "MB/s")
	}
}

func BenchmarkProxySmallRequest(b *testing.B) {
	for _, p := range []int{1, 16, 64} {
		b.Run(fmt.Sprintf("conc=%d", p), func(b *testing.B) { runLatency(b, p, nil, 128) })
	}
}

func BenchmarkProxyBulk1MiB(b *testing.B) {
	for _, p := range []int{1, 8} {
		b.Run(fmt.Sprintf("conc=%d", p), func(b *testing.B) { runLatency(b, p, make([]byte, 1<<20), 1<<20) })
	}
}

// BenchmarkDirectBaseline measures the same origin without the platform, so
// added overhead can be read as a difference rather than an absolute.
func BenchmarkDirectBaseline(b *testing.B) {
	env := benchEnv(b, nil, nil)
	o := env.Origin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.Copy(io.Discard, r.Body); w.Write(make([]byte, 128)) }))
	for _, p := range []int{1, 16, 64} {
		b.Run(fmt.Sprintf("conc=%d", p), func(b *testing.B) {
			client := &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: p * 2, MaxConnsPerHost: p * 2}}
			var mu sync.Mutex
			var lat []time.Duration
			var next atomic.Int64
			b.ResetTimer()
			start := time.Now()
			var wg sync.WaitGroup
			for w := 0; w < p; w++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					var local []time.Duration
					for next.Add(1) <= int64(b.N) {
						t0 := time.Now()
						resp, err := client.Post(o.URL, "text/plain", nil)
						if err != nil {
							b.Error(err)
							return
						}
						io.Copy(io.Discard, resp.Body)
						resp.Body.Close()
						local = append(local, time.Since(t0))
					}
					mu.Lock()
					lat = append(lat, local...)
					mu.Unlock()
				}()
			}
			wg.Wait()
			el := time.Since(start)
			sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
			b.ReportMetric(float64(pct(lat, .50).Microseconds()), "p50_us")
			b.ReportMetric(float64(pct(lat, .95).Microseconds()), "p95_us")
			b.ReportMetric(float64(pct(lat, .99).Microseconds()), "p99_us")
			b.ReportMetric(float64(b.N)/el.Seconds(), "req/s")
		})
	}
}

// ---- idle tunnels ------------------------------------------------------------

func rssKB() int64 {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return -1
	}
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, "VmRSS:") {
			var kb int64
			fmt.Sscanf(strings.TrimSpace(strings.TrimPrefix(l, "VmRSS:")), "%d", &kb)
			return kb
		}
	}
	return -1
}

func cpuSeconds() float64 {
	var ru syscall.Rusage
	syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	return float64(ru.Utime.Sec) + float64(ru.Utime.Usec)/1e6 + float64(ru.Stime.Sec) + float64(ru.Stime.Usec)/1e6
}

func fds() int {
	e, _ := os.ReadDir("/proc/self/fd")
	return len(e)
}

// TestIdleTunnels opens N authenticated, registered tunnels and holds them idle.
// The process contains BOTH ends of every tunnel plus the control plane, so the
// memory/CPU figures are for the whole simulated system; roughly half of the
// per-tunnel cost belongs to the edge.
func TestIdleTunnels(t *testing.T) {
	var n int
	if v := os.Getenv("OHOH_BENCH_IDLE"); v == "" {
		t.Skip("set OHOH_BENCH_IDLE=<count> to run")
	} else {
		fmt.Sscanf(v, "%d", &n)
	}
	env := benchEnv(t, nil, nil)
	runtime.GC()
	baseRSS, baseGo, baseFD := rssKB(), runtime.NumGoroutine(), fds()

	o := env.Origin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "alive") }))
	target, _ := origin.ParseTarget(o.URL, false)
	h := origin.New(target, origin.Options{})

	type tun struct {
		conn *session.Connection
		host string
	}
	tuns := make([]tun, n)
	var failed atomic.Int64
	fail := func(stage string, err error) {
		if failed.Add(1) <= 5 {
			var ae *api.Error
			if errors.As(err, &ae) {
				t.Logf("tunnel setup failed at %s: %v details=%v", stage, err, ae.Details)
			} else {
				t.Logf("tunnel setup failed at %s: %v", stage, err)
			}
		}
	}
	sem := make(chan struct{}, 48)
	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < n; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			pub, priv, _ := ed25519.GenerateKey(rand.Reader)
			id := cid.Identity{Private: priv, Public: pub}
			c := api.New(env.CPServer.URL, id, nil)
			ep, err := c.CreateEndpoint(bg, "")
			if err != nil {
				fail("create endpoint", err)
				return
			}
			cred, err := c.TunnelCredentials(bg, ep.ID)
			if err != nil {
				fail("credential", err)
				return
			}
			conn, err := session.Connect(bg, env.Edge.Addrs().Tunnel, env.TLSConfig(), cred, id, 30*time.Second)
			if err != nil {
				fail("connect", err)
				return
			}
			go session.Serve(bg, conn.Session, h)
			tuns[i] = tun{conn: conn, host: ep.Hostname}
		}(i)
	}
	wg.Wait()
	setup := time.Since(start)
	ok := int64(n) - failed.Load()
	if failed.Load() > 0 {
		t.Logf("WARNING: %d/%d tunnels failed to establish", failed.Load(), n)
	}
	runtime.GC()
	establishedRSS, establishedGo, establishedFD := rssKB(), runtime.NumGoroutine(), fds()
	t.Logf("established %d tunnels in %v (%.0f tunnels/s, includes CP registration + TLS 1.3 + auth)", ok, setup.Round(time.Millisecond), float64(ok)/setup.Seconds())

	// Hold idle and measure CPU. Keepalive pings (15 s) are the only traffic.
	cpu0, t0 := cpuSeconds(), time.Now()
	time.Sleep(20 * time.Second)
	idleCPU := (cpuSeconds() - cpu0) / time.Since(t0).Seconds()

	// Prove they are alive: send requests through a sample of tunnels.
	live, sample := 0, 0
	for i := 0; i < n && sample < 200; i += max(1, n/200) {
		if tuns[i].conn == nil {
			continue
		}
		sample++
		resp, b := env.Get(tuns[i].host, "/")
		if resp.StatusCode == 200 && b == "alive" {
			live++
		}
	}
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	t.Logf("RESULT idle_tunnels=%d established=%d sample_requests_ok=%d/%d", n, ok, live, sample)
	t.Logf("RESULT rss_baseline_mb=%.0f rss_with_tunnels_mb=%.0f rss_per_tunnel_kb=%.1f (both ends of each tunnel + control plane in one process)",
		float64(baseRSS)/1024, float64(establishedRSS)/1024, float64(establishedRSS-baseRSS)/float64(max64(ok, 1)))
	t.Logf("RESULT goroutines_baseline=%d goroutines_with_tunnels=%d per_tunnel=%.1f", baseGo, establishedGo, float64(establishedGo-baseGo)/float64(max64(ok, 1)))
	t.Logf("RESULT open_fds_baseline=%d open_fds_with_tunnels=%d per_tunnel=%.1f", baseFD, establishedFD, float64(establishedFD-baseFD)/float64(max64(ok, 1)))
	t.Logf("RESULT heap_alloc_mb=%.0f heap_inuse_mb=%.0f sys_mb=%.0f", float64(ms.HeapAlloc)/1e6, float64(ms.HeapInuse)/1e6, float64(ms.Sys)/1e6)
	t.Logf("RESULT idle_cpu_cores=%.3f over 20s with keepalive pings", idleCPU)
	if live != sample {
		t.Errorf("only %d/%d sampled tunnels served a request", live, sample)
	}
	for _, x := range tuns {
		if x.conn != nil {
			x.conn.Session.Close()
		}
	}
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
