package cli

import (
	"fmt"
	"strconv"
	"strings"
)

// formatBytes renders decimal SI quantities (1 kB = 1,000 bytes), matching
// the units used by every API and policy calculation.
func formatBytes(n int64) string {
	units := []struct {
		size int64
		name string
	}{{1_000_000_000_000, "TB"}, {1_000_000_000, "GB"}, {1_000_000, "MB"}, {1_000, "kB"}}
	for _, u := range units {
		if n >= u.size {
			v := float64(n) / float64(u.size)
			s := strconv.FormatFloat(v, 'f', 2, 64)
			s = strings.TrimRight(strings.TrimRight(s, "0"), ".")
			return s + " " + u.name
		}
	}
	return fmt.Sprintf("%d B", n)
}

func formatRate(n int64) string { return formatBytes(n) + "/s" }

func formatPrice(amount, asset, interval, unit string) string {
	if amount == "0" {
		return "Free"
	}
	return fmt.Sprintf("%s %s/%s/%s", amount, asset, interval, unit)
}
