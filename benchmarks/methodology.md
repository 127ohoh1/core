# Benchmark methodology

Everything here is reproducible with the commands shown. Results (with the machine,
toolchain, configuration and raw output) are in [`results/`](results/). **No number in
this repository is quoted without a reproducible run behind it, and none is a claim about
a production deployment.**

## What is measured, and what is not

| Question | Harness | Notes |
|---|---|---|
| Added latency and throughput of one proxied request | `benchmarks/bench_test.go` `BenchmarkProxySmallRequest`, `BenchmarkProxyBulk1MiB` vs `BenchmarkDirectBaseline` | Loopback, one process holds control plane + edge + client + origin + load generator. |
| Multiplexer alone | `protocol/tunnel` `BenchmarkStreamThroughput`, `BenchmarkAppendFrame16KiB`, `BenchmarkReadFrame16KiB` | Loopback TCP, no TLS, no HTTP. |
| Bandwidth limiter cost and accuracy | `dataplane/ratelimit` benchmarks; `TestFreeTierBandwidthEnforced`; Compose measurement | Accuracy is measured end to end. |
| Metering cost | `dataplane/metering` `BenchmarkMeterAdd` | Per-chunk hot path. |
| Idle tunnels (memory, goroutines, fds, CPU) | `TestIdleTunnels` (`make bench-idle N=…`) | N authenticated, registered tunnels held idle; keepalive pings only. |
| Sustained bandwidth enforcement | `TestFreeTierBandwidthEnforced`, `TestConcurrencyDoesNotMultiplyBandwidth`, `docker compose` run | Canonical free plan, not a fixture. |

Not measured: WAN behaviour, TLS session resumption at scale, multiple machines, real
origins, memory under adversarial input at maximum legal frame size beyond the bounded
buffers (see "Limitations").

## Environment control

- One machine, one Go process for the whole system in the request benchmarks. Load
  generator and system under test **share the CPU**, so absolute numbers understate what
  a dedicated edge would do and overstate latency. Use the *difference to the direct
  baseline* to read overhead.
- Plan limits are part of the product, so benchmarks that are not *about* the limiter lift
  them (`benchEnv` scales bandwidth to 10 GB/s). An early run left them at a 100 MB/s
  fixture and produced exactly 100.0 MB/s at every concurrency: the token bucket, not the
  proxy, was the bottleneck. That run is what measured limiter accuracy (±0.05%); it is
  kept in `results/` as such and was *not* used as a throughput figure.
- `-count 3` for every request benchmark; all three runs are reported. `-benchtime 2s`.
- Latency percentiles are computed from every request's own timing (not from averages).

## Procedure

```bash
# request benchmarks (3 repetitions each)
go test -run '^$' -bench 'DirectBaseline|ProxySmallRequest|ProxyBulk1MiB' -benchtime 2s -count 3 ./benchmarks
# micro benchmarks
go test -run '^$' -bench . -benchmem -count 3 ./protocol/tunnel ./dataplane/ratelimit ./dataplane/metering
# idle tunnels (memory/goroutine/fd/CPU with N tunnels held open for 20 s, then a request sample)
OHOH_BENCH_IDLE=10000 go test -run TestIdleTunnels -v -count=1 -timeout 30m ./benchmarks
# bandwidth enforcement accuracy against the real stack
make up   # then: curl --cacert .devtls/ca.pem ... https://<host>:8443/bytes/500000  (expect ~3.0 s on the free plan)
```

## Reporting rules

Each results file states machine (CPU, cores, RAM, kernel), Go version, configuration
(limits, windows, frame size), the exact commands, repetitions, p50/p95/p99, throughput,
CPU and memory where measured, and limitations. Idle-tunnel figures are for **both ends
of every tunnel plus the control plane in one process**; roughly half of the per-tunnel
cost belongs to the edge.

## Limitations (read before quoting anything)

- Loopback only: no network latency, loss or bandwidth-delay effects.
- Same-CPU load generation (see above).
- Idle-tunnel memory includes the client side and the control plane; a real edge holds
  roughly half. It also excludes any kernel socket buffers beyond the process RSS view.
- The 10,000-tunnel figure is the highest count exercised on this 8-thread laptop with
  ~4 GB of free RAM, not a capacity claim; the trend is linear in every measured
  dimension (goroutines, fds, RSS).
- Percentiles at high concurrency include queueing inside the shared process.
- No claim is made about behaviour under sustained multi-day load (no soak test was run).
