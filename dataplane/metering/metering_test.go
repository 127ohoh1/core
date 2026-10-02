package metering

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/127ohoh1/core/internal/observability"
)

var (
	p1  = time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	p1e = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	p2  = p1e
	p2e = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	bg  = context.Background()
)

// fakeLedger applies batches idempotently, like the real ledger.
type fakeLedger struct {
	mu      sync.Mutex
	seen    map[string]bool
	totals  map[string]int64
	applied []Batch
	fail    error
	dropAck bool // apply but pretend the response was lost
	sends   int
}

func newLedger() *fakeLedger { return &fakeLedger{seen: map[string]bool{}, totals: map[string]int64{}} }

func (l *fakeLedger) Send(_ context.Context, b Batch) (Result, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sends++
	if l.fail != nil && !l.dropAck {
		return Result{}, l.fail
	}
	dup := l.seen[b.BatchID]
	if !dup {
		l.seen[b.BatchID] = true
		l.applied = append(l.applied, b)
		for _, it := range b.Items {
			l.totals[it.EndpointID] += it.Bytes
		}
	}
	if l.dropAck && l.fail != nil {
		return Result{}, l.fail
	}
	res := Result{Duplicate: dup, Totals: map[string]Total{}}
	for _, it := range b.Items {
		res.Totals[it.EndpointID] = Total{PeriodStart: it.PeriodStart, UsedBytes: l.totals[it.EndpointID]}
	}
	return res, nil
}

func newColl(l *fakeLedger) *Collector {
	return NewCollector("edge-1", l, NewMetrics(observability.NewRegistry()))
}

func TestQuotaBoundaryAndOvershootBound(t *testing.T) {
	c := newColl(newLedger())
	m := c.Meter("ep")
	m.Sync(p1, p1e, 1000, 0)
	for i := 0; i < 9; i++ {
		if err := m.Add(100); err != nil {
			t.Fatal(err)
		}
	}
	if m.Exhausted() {
		t.Fatal("900/1000")
	}
	if err := m.Add(200); err != nil { // crosses the line: counted (bounded overshoot of one chunk)
		t.Fatal(err)
	}
	if !m.Exhausted() || m.Used() != 1100 {
		t.Fatalf("used %d", m.Used())
	}
	if err := m.Add(1); !errors.Is(err, ErrQuotaExhausted) {
		t.Fatal("next chunk must be refused")
	}
	if m.Used() != 1100 {
		t.Fatal("a refused chunk must not be counted")
	}
}

func TestUsageFromPolicyIsIncluded(t *testing.T) {
	c := newColl(newLedger())
	m := c.Meter("ep")
	m.Sync(p1, p1e, 1000, 950) // other edges / earlier use already consumed 950
	m.Add(40)
	if m.Exhausted() {
		t.Fatal("990/1000")
	}
	m.Add(20)
	if !m.Exhausted() {
		t.Fatal("1010/1000")
	}
}

func TestFlushReportsExactlyWhatWasCounted(t *testing.T) {
	l := newLedger()
	c := newColl(l)
	a, b := c.Meter("a"), c.Meter("b")
	a.Sync(p1, p1e, 1<<40, 0)
	b.Sync(p1, p1e, 1<<40, 0)
	a.Add(123)
	a.Add(877)
	b.Add(5)
	if err := c.Flush(bg); err != nil {
		t.Fatal(err)
	}
	if l.totals["a"] != 1000 || l.totals["b"] != 5 {
		t.Fatalf("%v", l.totals)
	}
	// Nothing new: no empty batches.
	c.Flush(bg)
	if len(l.applied) != 1 {
		t.Fatalf("%d batches", len(l.applied))
	}
	// Ack folds the ledger total into the meter: local view stays exact.
	if a.Used() != 1000 {
		t.Fatalf("used %d", a.Used())
	}
}

// Duplicate delivery (lost response, retry) must not double count.
func TestRetryAfterLostResponseIsIdempotent(t *testing.T) {
	l := newLedger()
	c := newColl(l)
	m := c.Meter("ep")
	m.Sync(p1, p1e, 1<<40, 0)
	m.Add(500)
	l.fail, l.dropAck = errors.New("timeout"), true
	if err := c.Flush(bg); err == nil {
		t.Fatal("expected failure")
	}
	if l.totals["ep"] != 500 {
		t.Fatalf("ledger applied %d", l.totals["ep"])
	}
	m.Add(300) // new traffic while the first batch is stuck: must be a *different* batch
	l.fail, l.dropAck = nil, false
	if err := c.Flush(bg); err != nil {
		t.Fatal(err)
	}
	if l.totals["ep"] != 800 {
		t.Fatalf("double counted or lost: %d", l.totals["ep"])
	}
	if len(l.applied) != 2 {
		t.Fatalf("batches applied: %d", len(l.applied))
	}
	ids := map[string]bool{}
	for _, b := range l.applied {
		ids[b.BatchID] = true
	}
	if len(ids) != 2 {
		t.Fatal("batch ids must be unique")
	}
}

func TestBatchesAreImmutableAcrossRetries(t *testing.T) {
	l := newLedger()
	c := newColl(l)
	m := c.Meter("ep")
	m.Sync(p1, p1e, 1<<40, 0)
	m.Add(100)
	l.fail = errors.New("down")
	c.Flush(bg)
	first := c.pending[0]
	m.Add(999)
	c.Flush(bg)
	if got := c.pending[0]; got.BatchID != first.BatchID || got.Items[0].Bytes != 100 {
		t.Fatalf("pending batch mutated: %+v vs %+v", got, first)
	}
}

func TestPendingQueueIsBounded(t *testing.T) {
	l := newLedger()
	l.fail = errors.New("down")
	c := newColl(l)
	m := c.Meter("ep")
	m.Sync(p1, p1e, 1<<40, 0)
	for i := 0; i < MaxPendingBatches+30; i++ {
		m.Add(10)
		c.Flush(bg)
	}
	if len(c.pending) != MaxPendingBatches {
		t.Fatalf("pending %d", len(c.pending))
	}
	// Nothing is lost while the queue is full: recovery reports every byte exactly once.
	l.fail = nil
	if err := c.Flush(bg); err != nil {
		t.Fatal(err)
	}
	if l.totals["ep"] != int64((MaxPendingBatches+30)*10) {
		t.Fatalf("ledger has %d", l.totals["ep"])
	}
}

func TestPermanentRejectionDropsBatchAndUnblocksQueue(t *testing.T) {
	l := newLedger()
	c := newColl(l)
	m := c.Meter("ep")
	m.Sync(p1, p1e, 1<<40, 0)
	m.Add(10)
	l.fail = ErrPermanent
	if err := c.Flush(bg); err != nil {
		t.Fatalf("permanent rejection must not wedge the queue: %v", err)
	}
	if len(c.pending) != 0 {
		t.Fatal("poison batch retained")
	}
	if m.Used() != 0 {
		t.Fatal("dropped bytes must not stay counted forever")
	}
}

func TestPeriodRolloverReportsOldBytesUnderOldPeriod(t *testing.T) {
	l := newLedger()
	c := newColl(l)
	m := c.Meter("ep")
	m.Sync(p1, p1e, 1000, 0)
	m.Add(400)
	m.Sync(p2, p2e, 1000, 0) // new month, fresh quota
	if m.Exhausted() || m.Used() != 0 {
		t.Fatalf("new period must start clean: used %d", m.Used())
	}
	m.Add(50)
	c.Flush(bg)
	var old, cur int64
	for _, b := range l.applied {
		for _, it := range b.Items {
			if it.PeriodStart.Equal(p1) {
				old += it.Bytes
			} else if it.PeriodStart.Equal(p2) {
				cur += it.Bytes
			}
		}
	}
	if old != 400 || cur != 50 {
		t.Fatalf("old period %d (want 400), new period %d (want 50)", old, cur)
	}
}

func TestShutdownFlushesAndReportsLoss(t *testing.T) {
	l := newLedger()
	c := newColl(l)
	m := c.Meter("ep")
	m.Sync(p1, p1e, 1<<40, 0)
	m.Add(77)
	if err := c.Shutdown(bg); err != nil || l.totals["ep"] != 77 {
		t.Fatalf("%v %v", err, l.totals)
	}
	m.Add(5)
	l.fail = errors.New("down")
	ctx, cancel := context.WithTimeout(bg, 300*time.Millisecond)
	defer cancel()
	if err := c.Shutdown(ctx); err == nil {
		t.Fatal("un-flushable usage must be reported at shutdown")
	}
}

func TestConcurrentAddAndFlushExactTotals(t *testing.T) {
	l := newLedger()
	c := newColl(l)
	m := c.Meter("ep")
	m.Sync(p1, p1e, 1<<40, 0)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 2000; i++ {
				m.Add(7)
			}
		}()
	}
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				c.Flush(bg)
			}
		}
	}()
	wg.Wait()
	close(stop)
	time.Sleep(20 * time.Millisecond)
	if err := c.Flush(bg); err != nil {
		t.Fatal(err)
	}
	if l.totals["ep"] != 8*2000*7 {
		t.Fatalf("ledger %d, want %d", l.totals["ep"], 8*2000*7)
	}
}

func BenchmarkMeterAdd(b *testing.B) {
	c := newColl(newLedger())
	m := c.Meter("ep")
	m.Sync(p1, p1e, 1<<60, 0)
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			m.Add(16384)
		}
	})
}
