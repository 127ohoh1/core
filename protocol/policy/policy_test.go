package policy

import (
	"encoding/json"
	"testing"
	"time"
)

func FuzzDecodePolicy(f *testing.F) {
	good := EndpointPolicy{EndpointID: "ep", PolicyVersion: 1, State: StateActive,
		Limits: Limits{BandwidthBytesPerSecond: 1, BurstBytes: 2}, Usage: Usage{PeriodStart: time.Unix(0, 0), PeriodEnd: time.Unix(10, 0)}, ValidUntil: time.Unix(5, 0)}
	b, _ := json.Marshal(good)
	f.Add(b)
	f.Add([]byte(`{"state":"active"}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, in []byte) {
		p, err := Decode(in)
		if err != nil {
			return
		}
		// Anything accepted must satisfy every invariant the edge relies on.
		if err := p.Validate(); err != nil {
			t.Fatalf("Decode accepted a policy that fails Validate: %v", err)
		}
		if p.State == StateActive && (p.Limits.BandwidthBytesPerSecond <= 0 || p.Limits.BurstBytes < 1) {
			t.Fatalf("active policy with unusable limits accepted: %+v", p.Limits)
		}
	})
}
