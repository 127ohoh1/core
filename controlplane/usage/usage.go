// Package usage is the authoritative usage ledger. It applies edge-reported
// batches exactly once per (edge, batch id), keeps per-endpoint monthly
// totals, and answers "how much has this endpoint used this period".
package usage

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/127ohoh1/core/internal/apperr"
	"github.com/127ohoh1/core/internal/clock"
)

// Batch, Item, Result and Total mirror the edge's wire types; they are
// declared here so the control plane never imports data-plane packages.
type Item struct {
	EndpointID  string    `json:"endpoint_id"`
	PeriodStart time.Time `json:"period_start"`
	Bytes       int64     `json:"bytes"`
}

type Batch struct {
	EdgeID  string `json:"edge_id"`
	BatchID string `json:"batch_id"`
	Items   []Item `json:"items"`
}

type Total struct {
	PeriodStart time.Time `json:"period_start"`
	UsedBytes   int64     `json:"used_bytes"`
}

type Result struct {
	Duplicate bool             `json:"duplicate"`
	Totals    map[string]Total `json:"totals"`
	Rejected  []string         `json:"rejected,omitempty"`
}

// Limits on a single batch (defence against a buggy or compromised edge).
const (
	MaxItemsPerBatch = 1000
	MaxItemBytes     = int64(1) << 40 // 1 TiB in one flush interval is not physical
	MaxIDLen         = 128
	// A batch may report usage for the current or the previous months only.
	maxPeriodAge = 62 * 24 * time.Hour
)

// Ledger is the storage boundary (UsageLedger in the specification).
type Ledger interface {
	Apply(ctx context.Context, b Batch, at time.Time, known func(endpointID string) bool) (Result, error)
	Used(ctx context.Context, endpointID string, periodStart time.Time) (int64, error)
}

type periodKey struct {
	endpoint string
	period   time.Time
}

// InMemory is the development ledger.
type InMemory struct {
	mu      sync.Mutex
	totals  map[periodKey]int64
	batches map[string][]periodKey // key: edge + "\x00" + batch id -> affected periods
	order   []string
	max     int
}

// NewInMemory returns a ledger remembering at most maxBatches batch ids
// (oldest evicted; an evicted id resent later would be re-applied, so the
// window must exceed any realistic retry horizon).
func NewInMemory(maxBatches int) *InMemory {
	if maxBatches <= 0 {
		maxBatches = 200000
	}
	return &InMemory{totals: map[periodKey]int64{}, batches: map[string][]periodKey{}, max: maxBatches}
}

// MonthStart reports whether t is exactly 00:00:00 UTC on the first of a month.
func MonthStart(t time.Time) bool {
	t = t.UTC()
	return t.Day() == 1 && t.Hour() == 0 && t.Minute() == 0 && t.Second() == 0 && t.Nanosecond() == 0
}

func validate(b Batch, now time.Time) error {
	if b.EdgeID == "" || len(b.EdgeID) > MaxIDLen || b.BatchID == "" || len(b.BatchID) > MaxIDLen {
		return errors.New("edge_id and batch_id are required")
	}
	if len(b.Items) == 0 || len(b.Items) > MaxItemsPerBatch {
		return fmt.Errorf("batch must contain 1..%d items", MaxItemsPerBatch)
	}
	return nil
}

func (l *InMemory) Apply(_ context.Context, b Batch, now time.Time, known func(string) bool) (Result, error) {
	if err := validate(b, now); err != nil {
		return Result{}, apperr.ErrInvalidRequest.WithDetails(map[string]any{"reason": err.Error()})
	}
	key := b.EdgeID + "\x00" + b.BatchID
	l.mu.Lock()
	defer l.mu.Unlock()
	if prior, dup := l.batches[key]; dup {
		// Idempotent replay: report *current* totals, apply nothing.
		res := Result{Duplicate: true, Totals: map[string]Total{}}
		for _, k := range prior {
			res.Totals[k.endpoint] = Total{PeriodStart: k.period, UsedBytes: l.totals[k]}
		}
		return res, nil
	}
	res := Result{Totals: map[string]Total{}}
	var applied []periodKey
	for _, it := range b.Items {
		ps := it.PeriodStart.UTC()
		switch {
		case it.EndpointID == "" || len(it.EndpointID) > MaxIDLen,
			it.Bytes <= 0 || it.Bytes > MaxItemBytes,
			!MonthStart(ps),
			ps.After(now.Add(24 * time.Hour)), now.Sub(ps) > maxPeriodAge,
			known != nil && !known(it.EndpointID):
			res.Rejected = append(res.Rejected, it.EndpointID)
			continue
		}
		k := periodKey{it.EndpointID, ps}
		l.totals[k] += it.Bytes
		applied = append(applied, k)
		res.Totals[it.EndpointID] = Total{PeriodStart: ps, UsedBytes: l.totals[k]}
	}
	l.batches[key] = applied
	l.order = append(l.order, key)
	if len(l.order) > l.max {
		delete(l.batches, l.order[0])
		l.order = l.order[1:]
	}
	return res, nil
}

func (l *InMemory) Used(_ context.Context, endpointID string, periodStart time.Time) (int64, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.totals[periodKey{endpointID, periodStart.UTC()}], nil
}

// Service wraps a Ledger with endpoint validation and change notification.
type Service struct {
	Ledger Ledger
	Clock  clock.Clock
	// Known reports whether an endpoint exists (unknown ids are rejected per item).
	Known func(ctx context.Context, endpointID string) bool
	// Updated is called after usage of an endpoint changed, so its policy can
	// be re-resolved (quota exhaustion must reach every edge).
	Updated func(ctx context.Context, endpointID string)
}

// Apply validates and applies a batch.
func (s *Service) Apply(ctx context.Context, b Batch) (Result, error) {
	known := func(id string) bool { return s.Known == nil || s.Known(ctx, id) }
	res, err := s.Ledger.Apply(ctx, b, s.Clock.Now(), known)
	if err != nil {
		return res, err
	}
	if s.Updated != nil && !res.Duplicate {
		for id := range res.Totals {
			s.Updated(ctx, id)
		}
	}
	return res, nil
}

// Used implements policy.UsageReader.
func (s *Service) Used(ctx context.Context, endpointID string, periodStart time.Time) (int64, error) {
	return s.Ledger.Used(ctx, endpointID, periodStart)
}
