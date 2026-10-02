// Package policy (control plane) owns the plan catalog, converts plans and
// entitlements into explicit endpoint policy, and publishes versioned
// snapshots. The public repository ships the canonical constants of the
// reference release; the production catalog is effective-dated and private.
package policy

import (
	"fmt"
	"sort"
)

// Decimal SI units: 1 kB = 1,000 bytes; 1 MB = 1,000,000; 1 GB = 1,000,000,000.
const (
	KB int64 = 1_000
	MB int64 = 1_000_000
	GB int64 = 1_000_000_000
)

// Plan IDs.
const (
	PlanFree  = "free"
	PlanTier1 = "tier_1"
	PlanTier2 = "tier_2"
	PlanTier3 = "tier_3"
)

// Plan is one canonical plan. Prices are per month per name, as decimal
// strings (never floating point).
type Plan struct {
	ID                      string `json:"id"`
	Name                    string `json:"name"`
	PriceAmount             string `json:"price_amount"` // decimal string
	PriceAsset              string `json:"price_asset"`  // "USDC"
	Interval                string `json:"interval"`     // "month"
	Unit                    string `json:"unit"`         // "name"
	BandwidthBytesPerSecond int64  `json:"bandwidth_bytes_per_second"`
	MonthlyTransferBytes    int64  `json:"monthly_transfer_bytes"`
	HostnameKind            string `json:"hostname"` // "random" | "reserved"
	Version                 int    `json:"version"`
	// Rank orders plans by capability (0 = free). Comparisons of "is this
	// entitlement sufficient" use Rank, never the price string.
	Rank int `json:"rank"`
}

// Paid reports whether the plan costs money.
func (p Plan) Paid() bool { return p.PriceAmount != "0" }

// canonical is the exact table from the specification, section 3.
var canonical = []Plan{
	{Rank: 0, ID: PlanFree, Name: "Free", PriceAmount: "0", PriceAsset: "USDC", Interval: "month", Unit: "name",
		BandwidthBytesPerSecond: 100 * KB, MonthlyTransferBytes: 500 * MB, HostnameKind: "random", Version: 1},
	{Rank: 1, ID: PlanTier1, Name: "Tier 1", PriceAmount: "1", PriceAsset: "USDC", Interval: "month", Unit: "name",
		BandwidthBytesPerSecond: 1 * MB, MonthlyTransferBytes: 10 * GB, HostnameKind: "reserved", Version: 1},
	{Rank: 2, ID: PlanTier2, Name: "Tier 2", PriceAmount: "2", PriceAsset: "USDC", Interval: "month", Unit: "name",
		BandwidthBytesPerSecond: 3 * MB, MonthlyTransferBytes: 100 * GB, HostnameKind: "reserved", Version: 1},
	{Rank: 3, ID: PlanTier3, Name: "Tier 3", PriceAmount: "4", PriceAsset: "USDC", Interval: "month", Unit: "name",
		BandwidthBytesPerSecond: 5 * MB, MonthlyTransferBytes: 500 * GB, HostnameKind: "reserved", Version: 1},
}

// BurstSeconds: the public reference burst policy is two seconds of
// sustained bandwidth, i.e. burst_bytes = 2 * bandwidth_bytes_per_second.
const BurstSeconds = 2

// Catalog is the read-only plan catalog.
type Catalog struct{ plans map[string]Plan }

// DefaultCatalog returns the canonical reference catalog.
func DefaultCatalog() *Catalog {
	c := &Catalog{plans: map[string]Plan{}}
	for _, p := range canonical {
		c.plans[p.ID] = p
	}
	return c
}

// Get returns a plan by id.
func (c *Catalog) Get(id string) (Plan, error) {
	p, ok := c.plans[id]
	if !ok {
		return Plan{}, fmt.Errorf("unknown plan %q", id)
	}
	return p, nil
}

// List returns plans ordered by rank: free, tier_1, tier_2, tier_3.
func (c *Catalog) List() []Plan {
	out := make([]Plan, 0, len(c.plans))
	for _, p := range c.plans {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].PriceAmount < out[j].PriceAmount || (out[i].PriceAmount == out[j].PriceAmount && out[i].ID < out[j].ID)
	})
	return out
}

// NewCatalog builds a catalog from explicit plans. It exists for test
// fixtures that need reduced-scale quotas; the canonical constants are never
// modified to make tests fast.
func NewCatalog(plans ...Plan) *Catalog {
	c := &Catalog{plans: map[string]Plan{}}
	for _, p := range plans {
		c.plans[p.ID] = p
	}
	return c
}

// Canonical returns a copy of the canonical plans (for fixtures to derive from).
func Canonical() []Plan { return append([]Plan(nil), canonical...) }
