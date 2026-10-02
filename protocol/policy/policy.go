// Package policy defines the resolved endpoint policy: the *only* description
// of an endpoint's entitlements that the data plane ever sees. It carries
// limits and lifecycle state, and deliberately nothing about prices, assets,
// wallets, transactions, subscriptions or plans: the edge must not be able to
// depend on commercial concepts (spec section 7.2).
package policy

import (
	"encoding/json"
	"errors"
	"time"
)

// State is the resolved enforcement state of an endpoint.
type State string

const (
	StateActive    State = "active"
	StateSuspended State = "suspended"
	StateExpired   State = "expired"
	StateReleased  State = "released"
	StatePending   State = "pending"
)

// Limits are the numeric enforcement limits.
type Limits struct {
	BandwidthBytesPerSecond int64 `json:"bandwidth_bytes_per_second"`
	BurstBytes              int64 `json:"burst_bytes"`
	MonthlyTransferBytes    int64 `json:"monthly_transfer_bytes"`
	ConcurrentRequests      int   `json:"concurrent_requests"`
	MaxRequestHeaderBytes   int   `json:"max_request_header_bytes"`
	MaxRequestBodyBytes     int64 `json:"max_request_body_bytes"`
}

// Usage is the authoritative usage snapshot at resolution time.
type Usage struct {
	PeriodStart time.Time `json:"period_start"`
	PeriodEnd   time.Time `json:"period_end"`
	UsedBytes   int64     `json:"used_bytes"`
}

// Hostname describes hostname lifecycle for the endpoint.
type Hostname struct {
	Kind                 string `json:"kind"` // "random" | "reserved"
	InactiveExpirySecond *int64 `json:"inactive_expiry_seconds"`
}

// EndpointPolicy is an immutable, versioned enforcement snapshot.
type EndpointPolicy struct {
	EndpointID    string    `json:"endpoint_id"`
	PolicyVersion int64     `json:"policy_version"`
	State         State     `json:"state"`
	Limits        Limits    `json:"limits"`
	Usage         Usage     `json:"usage"`
	Hostname      Hostname  `json:"hostname"`
	ValidUntil    time.Time `json:"valid_until"`
}

// Validation errors.
var ErrInvalid = errors.New("policy: invalid")

// Validate rejects structurally impossible policies from an untrusted (or
// buggy) source so the edge never enforces nonsense.
func (p EndpointPolicy) Validate() error {
	switch p.State {
	case StateActive, StateSuspended, StateExpired, StateReleased, StatePending:
	default:
		return ErrInvalid
	}
	l := p.Limits
	if p.EndpointID == "" || p.PolicyVersion < 0 || l.BandwidthBytesPerSecond < 0 || l.BurstBytes < 0 ||
		l.MonthlyTransferBytes < 0 || l.ConcurrentRequests < 0 || l.MaxRequestHeaderBytes < 0 || l.MaxRequestBodyBytes < 0 ||
		p.Usage.UsedBytes < 0 {
		return ErrInvalid
	}
	if p.State == StateActive && (l.BandwidthBytesPerSecond == 0 || l.BurstBytes < 1) {
		return ErrInvalid // an active endpoint must have a positive rate; zero would deadlock the limiter
	}
	if !p.Usage.PeriodEnd.After(p.Usage.PeriodStart) {
		return ErrInvalid
	}
	return nil
}

// Decode parses a policy from JSON and validates it.
func Decode(b []byte) (EndpointPolicy, error) {
	var p EndpointPolicy
	if err := json.Unmarshal(b, &p); err != nil {
		return EndpointPolicy{}, ErrInvalid
	}
	return p, p.Validate()
}

// Change is one entry of the policy change feed.
type Change struct {
	Seq        int64  `json:"seq"`
	EndpointID string `json:"endpoint_id"`
	Version    int64  `json:"policy_version"`
}

// Changes is the long-poll response of the change feed.
type Changes struct {
	Seq     int64    `json:"seq"`     // latest sequence number
	Reset   bool     `json:"reset"`   // consumer fell behind: refresh everything
	Changes []Change `json:"changes"` // ascending
}

// HostnameStatus is the control plane's answer about one tenant label
// (GET /v1/hostnames/{label}, edge service credential only).
type HostnameStatus struct {
	EndpointID string `json:"endpoint_id"`
	Kind       string `json:"kind"` // "random" | "reserved"
	State      State  `json:"state"`
}

// CertificateIssuable reports whether an edge may obtain a public
// certificate for the label before any tunnel has connected: only for a
// reserved (paid) name that is active. Random names still wait for a live
// tunnel, so issuance can't be sprayed with free, never-connected names.
func (h HostnameStatus) CertificateIssuable() bool {
	return h.Kind == "reserved" && h.State == StateActive
}
