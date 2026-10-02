package cli

import "testing"

func TestFormatDecimalSI(t *testing.T) {
	cases := map[int64]string{
		0: "0 B", 999: "999 B", 1_000: "1 kB", 100_000: "100 kB", 1_000_000: "1 MB", 3_000_000: "3 MB", 5_000_000: "5 MB",
		500_000_000: "500 MB", 10_000_000_000: "10 GB", 100_000_000_000: "100 GB", 500_000_000_000: "500 GB", 1_500_000: "1.5 MB", 1_234_567: "1.23 MB",
	}
	for n, want := range cases {
		if got := formatBytes(n); got != want {
			t.Errorf("%d: %q want %q", n, got, want)
		}
	}
	if formatRate(100_000) != "100 kB/s" {
		t.Error("rate")
	}
	if formatPrice("2", "USDC", "month", "name") != "2 USDC/month/name" || formatPrice("0", "USDC", "month", "name") != "Free" {
		t.Error("price")
	}
}
