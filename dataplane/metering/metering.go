// Package metering counts proxied body bytes per endpoint, enforces the
// monthly quota locally, and reports usage to the control plane in immutable,
// idempotent batches.
//
// Guarantees (ADR 0006):
//   - what is counted: HTTP body bytes, once per direction (see ingress);
//   - a batch, once cut, is never modified: retries resend identical content
//     under the same id, and the ledger applies each id at most once;
//   - no synchronous call per proxied chunk: counters are atomic-cheap and
//     flushed on an interval and at shutdown;
//   - local view = last known ledger total + bytes not yet acknowledged, so a
//     single edge's overshoot is bounded by one chunk per in-flight stream;
//   - abrupt edge death loses at most the un-flushed interval of usage
//     (undercount bound = flush interval x endpoint rate).
package metering

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/127ohoh1/core/internal/observability"
)

// ErrQuotaExhausted is returned by Meter.Add when the monthly quota is used up.
var ErrQuotaExhausted = errors.New("metering: monthly quota exhausted")

// ErrPermanent marks a sink failure that retrying cannot fix; the batch is dropped.
var ErrPermanent = errors.New("metering: batch permanently rejected")

// Item is usage for one endpoint and period inside a batch.
type Item struct {
	EndpointID  string    `json:"endpoint_id"`
	PeriodStart time.Time `json:"period_start"`
	Bytes       int64     `json:"bytes"`
}

// Batch is an immutable unit of usage reporting.
type Batch struct {
	EdgeID  string `json:"edge_id"`
	BatchID string `json:"batch_id"`
	Items   []Item `json:"items"`
}

// Total is the ledger total for an endpoint after applying a batch.
type Total struct {
	PeriodStart time.Time `json:"period_start"`
	UsedBytes   int64     `json:"used_bytes"`
}

// Result is the ledger's answer.
type Result struct {
	Duplicate bool             `json:"duplicate"`
	Totals    map[string]Total `json:"totals"`
	Rejected  []string         `json:"rejected,omitempty"` // endpoint ids the ledger did not accept
}

// Sink delivers batches to the authoritative ledger.
type Sink interface {
	Send(ctx context.Context, b Batch) (Result, error)
}

// Meter tracks one endpoint.
type Meter struct {
	mu          sync.Mutex
	id          string
	periodStart time.Time
	periodEnd   time.Time
	limit       int64  // 0 = unlimited (not used by shipped plans)
	confirmed   int64  // last known ledger total for the current period
	unacked     int64  // bytes counted here and not yet acknowledged by the ledger
	accum       int64  // subset of unacked not yet placed into a batch
	orphans     []Item // bytes of earlier periods awaiting a batch
	synced      bool
}

func newMeter(id string) *Meter { return &Meter{id: id} }

// Sync applies the authoritative view from a policy snapshot. A period change
// (month rollover) moves un-reported bytes of the old period into orphans so
// they are still reported under the period they belong to.
func (m *Meter) Sync(periodStart, periodEnd time.Time, limit, used int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.synced && !m.periodStart.Equal(periodStart) {
		if m.accum > 0 {
			m.orphans = append(m.orphans, Item{EndpointID: m.id, PeriodStart: m.periodStart, Bytes: m.accum})
		}
		m.accum, m.unacked, m.confirmed = 0, 0, 0
	}
	m.periodStart, m.periodEnd, m.limit = periodStart, periodEnd, limit
	if used > m.confirmed || !m.synced {
		m.confirmed = used
	}
	m.synced = true
}

// Add records n body bytes. It fails, without counting, once the quota is
// already exhausted; a chunk that crosses the line is counted and the next
// call fails, so overshoot per stream is bounded by one chunk.
func (m *Meter) Add(n int64) error {
	if n <= 0 {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.limit > 0 && m.confirmed+m.unacked >= m.limit {
		return ErrQuotaExhausted
	}
	m.unacked += n
	m.accum += n
	return nil
}

// Exhausted reports whether the quota is used up (confirmed + local).
func (m *Meter) Exhausted() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.limit > 0 && m.confirmed+m.unacked >= m.limit
}

// Used returns confirmed + unacknowledged bytes.
func (m *Meter) Used() int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.confirmed + m.unacked
}

// PeriodEnd returns the end of the current usage period.
func (m *Meter) PeriodEnd() time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.periodEnd
}

func (m *Meter) cut() []Item {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Item
	out = append(out, m.orphans...)
	m.orphans = nil
	if m.accum > 0 {
		out = append(out, Item{EndpointID: m.id, PeriodStart: m.periodStart, Bytes: m.accum})
		m.accum = 0
	}
	return out
}

func (m *Meter) ack(it Item, t Total, ok bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !it.PeriodStart.Equal(m.periodStart) {
		return // belongs to a finished period: nothing to reconcile
	}
	m.unacked -= it.Bytes
	if m.unacked < 0 {
		m.unacked = 0
	}
	if ok && t.PeriodStart.Equal(m.periodStart) && t.UsedBytes > m.confirmed {
		m.confirmed = t.UsedBytes
	}
}

func (m *Meter) idle() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.unacked == 0 && m.accum == 0 && len(m.orphans) == 0
}

// unackedOrphans counts bytes of orphaned periods (for the unflushed gauge).
func (m *Meter) pendingBytes() int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := m.accum
	for _, o := range m.orphans {
		n += o.Bytes
	}
	return n
}

// Metrics of the collector.
type Metrics struct {
	Unflushed *observability.Gauge   // edge_usage_unflushed_bytes
	Pending   *observability.Gauge   // edge_usage_batches_pending
	Retried   *observability.Counter // edge_usage_batches_retried_total
	Rejected  *observability.Counter // edge_usage_batches_rejected_total
	Sent      *observability.Counter // edge_usage_batches_sent_total
	Bytes     *observability.Counter // edge_usage_bytes_reported_total
}

// NewMetrics registers collector metrics.
func NewMetrics(r *observability.Registry) Metrics {
	return Metrics{
		Unflushed: r.Gauge("edge_usage_unflushed_bytes", "Metered bytes not yet acknowledged by the ledger."),
		Pending:   r.Gauge("edge_usage_batches_pending", "Cut usage batches awaiting acknowledgement."),
		Retried:   r.Counter("edge_usage_batches_retried_total", "Usage batch send attempts that failed and will be retried."),
		Rejected:  r.Counter("edge_usage_batches_rejected_total", "Usage batches permanently rejected by the ledger."),
		Sent:      r.Counter("edge_usage_batches_sent_total", "Usage batches acknowledged by the ledger."),
		Bytes:     r.Counter("edge_usage_bytes_reported_total", "Bytes acknowledged by the ledger."),
	}
}

// MaxPendingBatches bounds the retry queue. When full, no new batch is cut;
// counters keep accumulating (a number, not memory) until the ledger recovers.
const MaxPendingBatches = 64

// Collector owns all meters of an edge and the batch pipeline.
type Collector struct {
	edgeID string
	boot   string
	sink   Sink
	m      Metrics

	mu      sync.Mutex
	meters  map[string]*Meter
	pending []Batch
	seq     uint64
	sendMu  sync.Mutex // serialises Flush

	// Tick, if set, is called on every flush interval (liveness heartbeat).
	Tick func()
}

// NewCollector builds a Collector. The boot id keeps batch ids unique across
// edge restarts.
func NewCollector(edgeID string, sink Sink, m Metrics) *Collector {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return &Collector{edgeID: edgeID, boot: hex.EncodeToString(b[:]), sink: sink, m: m, meters: map[string]*Meter{}}
}

// Meter returns the meter for an endpoint, creating it if needed.
func (c *Collector) Meter(id string) *Meter {
	c.mu.Lock()
	defer c.mu.Unlock()
	mt, ok := c.meters[id]
	if !ok {
		mt = newMeter(id)
		c.meters[id] = mt
	}
	return mt
}

func (c *Collector) cutBatch() {
	c.mu.Lock()
	if len(c.pending) >= MaxPendingBatches {
		c.mu.Unlock()
		return
	}
	ms := make([]*Meter, 0, len(c.meters))
	for _, m := range c.meters {
		ms = append(ms, m)
	}
	c.mu.Unlock()
	var items []Item
	for _, m := range ms {
		items = append(items, m.cut()...)
	}
	if len(items) == 0 {
		return
	}
	c.mu.Lock()
	c.seq++
	c.pending = append(c.pending, Batch{EdgeID: c.edgeID, BatchID: fmt.Sprintf("%s.%s.%d", c.edgeID, c.boot, c.seq), Items: items})
	c.mu.Unlock()
}

func (c *Collector) updateGauges() {
	c.mu.Lock()
	var un int64
	for _, m := range c.meters {
		un += m.pendingBytes()
	}
	for _, b := range c.pending {
		for _, it := range b.Items {
			un += it.Bytes
		}
	}
	np := len(c.pending)
	c.mu.Unlock()
	c.m.Unflushed.Set(float64(un))
	c.m.Pending.Set(float64(np))
}

// Flush cuts a batch and sends every pending batch in order. It stops at the
// first transient failure (the batch stays queued, unchanged, for the next
// attempt) and returns that error.
func (c *Collector) Flush(ctx context.Context) error {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	c.cutBatch()
	defer c.updateGauges()
	for {
		c.mu.Lock()
		if len(c.pending) == 0 {
			c.mu.Unlock()
			return nil
		}
		b := c.pending[0]
		c.mu.Unlock()

		res, err := c.sink.Send(ctx, b)
		switch {
		case err == nil:
		case errors.Is(err, ErrPermanent):
			c.m.Rejected.Inc()
			res = Result{} // drop: counters are reconciled below without totals
		default:
			c.m.Retried.Inc()
			return err
		}
		c.mu.Lock()
		c.pending = c.pending[1:]
		c.mu.Unlock()
		if err == nil {
			c.m.Sent.Inc()
		}
		for _, it := range b.Items {
			c.mu.Lock()
			mt := c.meters[it.EndpointID]
			c.mu.Unlock()
			if mt == nil {
				continue
			}
			t, ok := res.Totals[it.EndpointID]
			mt.ack(it, t, ok)
			if err == nil {
				c.m.Bytes.Add(float64(it.Bytes))
			}
		}
		c.cutBatchIfRoom()
	}
}

func (c *Collector) cutBatchIfRoom() { c.cutBatch() }

// Forget drops the meter of an endpoint that is no longer served, but only if
// it has nothing left to report (so no usage can be lost). It reports whether
// the meter was removed. Callers must not keep using a forgotten meter.
func (c *Collector) Forget(id string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	m, ok := c.meters[id]
	if !ok {
		return true
	}
	if !m.idle() {
		return false
	}
	delete(c.meters, id)
	return true
}

// Run flushes every interval until ctx ends, then performs a final flush.
func (c *Collector) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if c.Tick != nil {
				c.Tick()
			}
			fctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			_ = c.Flush(fctx)
			cancel()
		}
	}
}

// Shutdown flushes remaining usage, retrying briefly. It returns an error if
// bytes remain un-flushed at the deadline (they are then lost: bounded loss).
func (c *Collector) Shutdown(ctx context.Context) error {
	var last error
	for {
		last = c.Flush(ctx)
		if last == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return last
		case <-time.After(200 * time.Millisecond):
		}
	}
}
