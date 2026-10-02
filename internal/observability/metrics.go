package observability

import (
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// Registry is a minimal Prometheus-compatible metrics registry. It exists to
// keep the dependency set at zero; the text exposition format is standard.
type Registry struct {
	mu      sync.Mutex
	metrics []*family
	byName  map[string]*family
}

type family struct {
	name, help, kind string
	labels           []string
	buckets          []float64
	mu               sync.Mutex
	series           map[string]*series
	gaugeFn          func() float64
}

type series struct {
	values []string
	bits   atomic.Uint64 // float64 bits for counter/gauge
	// histogram
	hmu    sync.Mutex
	counts []uint64
	sum    float64
	count  uint64
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{byName: map[string]*family{}} }

func (r *Registry) register(f *family) *family {
	r.mu.Lock()
	defer r.mu.Unlock()
	if old, ok := r.byName[f.name]; ok {
		return old // idempotent registration
	}
	f.series = map[string]*series{}
	r.byName[f.name] = f
	r.metrics = append(r.metrics, f)
	return f
}

// Counter is a monotonically increasing value family.
type Counter struct{ f *family }

// Gauge is an arbitrary value family.
type Gauge struct{ f *family }

// Histogram observes value distributions.
type Histogram struct{ f *family }

// Counter registers a counter family with fixed label names.
func (r *Registry) Counter(name, help string, labels ...string) *Counter {
	return &Counter{r.register(&family{name: name, help: help, kind: "counter", labels: labels})}
}

// Gauge registers a gauge family.
func (r *Registry) Gauge(name, help string, labels ...string) *Gauge {
	return &Gauge{r.register(&family{name: name, help: help, kind: "gauge", labels: labels})}
}

// GaugeFunc registers an unlabeled gauge computed at scrape time.
func (r *Registry) GaugeFunc(name, help string, fn func() float64) {
	r.register(&family{name: name, help: help, kind: "gauge", gaugeFn: fn})
}

// DefaultBuckets suit request latencies in seconds.
var DefaultBuckets = []float64{.001, .0025, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30}

// Histogram registers a histogram family (nil buckets = DefaultBuckets).
func (r *Registry) Histogram(name, help string, buckets []float64, labels ...string) *Histogram {
	if buckets == nil {
		buckets = DefaultBuckets
	}
	return &Histogram{r.register(&family{name: name, help: help, kind: "histogram", labels: labels, buckets: buckets})}
}

func (f *family) get(values []string) *series {
	if len(values) != len(f.labels) {
		panic(fmt.Sprintf("metric %s: expected %d label values, got %d", f.name, len(f.labels), len(values)))
	}
	key := strings.Join(values, "\xff")
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.series[key]
	if !ok {
		s = &series{values: append([]string(nil), values...)}
		if f.kind == "histogram" {
			s.counts = make([]uint64, len(f.buckets))
		}
		f.series[key] = s
	}
	return s
}

func (s *series) add(d float64) {
	for {
		old := s.bits.Load()
		if s.bits.CompareAndSwap(old, math.Float64bits(math.Float64frombits(old)+d)) {
			return
		}
	}
}

func (s *series) set(v float64)  { s.bits.Store(math.Float64bits(v)) }
func (s *series) value() float64 { return math.Float64frombits(s.bits.Load()) }

// Add increments the series by d (d must be >= 0).
func (c *Counter) Add(d float64, labelValues ...string) {
	if d < 0 {
		return
	}
	c.f.get(labelValues).add(d)
}

// Inc adds one.
func (c *Counter) Inc(labelValues ...string) { c.Add(1, labelValues...) }

// Value returns the current value (for tests).
func (c *Counter) Value(labelValues ...string) float64 { return c.f.get(labelValues).value() }

// Set assigns the gauge.
func (g *Gauge) Set(v float64, labelValues ...string) { g.f.get(labelValues).set(v) }

// Add adjusts the gauge.
func (g *Gauge) Add(d float64, labelValues ...string) { g.f.get(labelValues).add(d) }

// Value returns the current value (for tests).
func (g *Gauge) Value(labelValues ...string) float64 { return g.f.get(labelValues).value() }

// Observe records a sample.
func (h *Histogram) Observe(v float64, labelValues ...string) {
	s := h.f.get(labelValues)
	s.hmu.Lock()
	for i, b := range h.f.buckets {
		if v <= b {
			s.counts[i]++
		}
	}
	s.sum += v
	s.count++
	s.hmu.Unlock()
}

func esc(s string) string {
	return strings.NewReplacer(`\`, `\\`, "\n", `\n`, `"`, `\"`).Replace(s)
}

func labelStr(names, values []string, extra ...string) string {
	var parts []string
	for i, n := range names {
		parts = append(parts, fmt.Sprintf(`%s="%s"`, n, esc(values[i])))
	}
	parts = append(parts, extra...)
	if len(parts) == 0 {
		return ""
	}
	return "{" + strings.Join(parts, ",") + "}"
}

// WriteText renders the Prometheus text exposition format.
func (r *Registry) WriteText(w io.Writer) {
	r.mu.Lock()
	fams := append([]*family(nil), r.metrics...)
	r.mu.Unlock()
	sort.Slice(fams, func(i, j int) bool { return fams[i].name < fams[j].name })
	for _, f := range fams {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n", f.name, f.help, f.name, f.kind)
		if f.gaugeFn != nil {
			fmt.Fprintf(w, "%s %g\n", f.name, f.gaugeFn())
			continue
		}
		f.mu.Lock()
		keys := make([]string, 0, len(f.series))
		for k := range f.series {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		ss := make([]*series, len(keys))
		for i, k := range keys {
			ss[i] = f.series[k]
		}
		f.mu.Unlock()
		for _, s := range ss {
			if f.kind != "histogram" {
				fmt.Fprintf(w, "%s%s %g\n", f.name, labelStr(f.labels, s.values), s.value())
				continue
			}
			s.hmu.Lock()
			for i, b := range f.buckets {
				fmt.Fprintf(w, "%s_bucket%s %d\n", f.name, labelStr(f.labels, s.values, fmt.Sprintf(`le="%g"`, b)), s.counts[i])
			}
			fmt.Fprintf(w, "%s_bucket%s %d\n", f.name, labelStr(f.labels, s.values, `le="+Inf"`), s.count)
			fmt.Fprintf(w, "%s_sum%s %g\n%s_count%s %d\n", f.name, labelStr(f.labels, s.values), s.sum, f.name, labelStr(f.labels, s.values), s.count)
			s.hmu.Unlock()
		}
	}
}

// Handler serves the registry at /metrics.
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		r.WriteText(w)
	})
}

// RegisterRuntime adds goroutine, heap and file-descriptor gauges.
func (r *Registry) RegisterRuntime() {
	r.GaugeFunc("process_goroutines", "Number of goroutines.", func() float64 { return float64(runtime.NumGoroutine()) })
	r.GaugeFunc("process_heap_alloc_bytes", "Heap bytes in use.", func() float64 {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		return float64(m.HeapAlloc)
	})
	r.GaugeFunc("process_open_fds", "Open file descriptors (Linux only, else -1).", func() float64 {
		ents, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			return -1
		}
		return float64(len(ents))
	})
}
