// Package payment holds the payment domain: an explicit state machine, integer
// money, the verifier boundary and idempotent settlement processing.
//
// PUBLIC REFERENCE SCOPE: this repository only ships a *development* payment
// adapter (MockVerifier + simulated settlement). Real USDC settlement, chain
// confirmation, reorg handling, reconciliation, renewal and refunds live in the
// private product repository behind these same interfaces.
package payment

import (
	"errors"
	"math"
	"strings"
)

// USDCDecimals is the number of decimal places of USDC.
const USDCDecimals = 6

// Money is an integer amount in atomic units of an asset (1 USDC =
// 1,000,000 atomic units). Binary floating point is never used for money.
type Money struct {
	Atomic int64
	Asset  string
}

// ErrAmount is returned for malformed decimal amounts.
var ErrAmount = errors.New("payment: invalid decimal amount")

// ParseAmount converts a non-negative decimal string ("1", "2.5", "0.000001")
// to atomic units, rejecting anything with more than `decimals` fraction
// digits, signs, exponents or whitespace.
func ParseAmount(s string, decimals int) (int64, error) {
	if s == "" || len(s) > 24 {
		return 0, ErrAmount
	}
	whole, frac, hasDot := strings.Cut(s, ".")
	if whole == "" || (hasDot && (frac == "" || len(frac) > decimals)) {
		return 0, ErrAmount
	}
	for _, part := range []string{whole, frac} {
		for i := 0; i < len(part); i++ {
			if part[i] < '0' || part[i] > '9' {
				return 0, ErrAmount
			}
		}
	}
	// scale = 10^decimals; the result must fit in int64 *after* scaling. An
	// earlier version bounded only the whole part and let the multiplication
	// overflow into a negative amount (found by FuzzAmountRoundTrip).
	scale := int64(1)
	for i := 0; i < decimals; i++ {
		scale *= 10
	}
	var n int64
	for i := 0; i < len(whole); i++ {
		d := int64(whole[i] - '0')
		if n > (math.MaxInt64/scale-d)/10 {
			return 0, ErrAmount
		}
		n = n*10 + d
	}
	n *= scale // cannot overflow: n <= MaxInt64/scale
	for i := 0; i < decimals && i < len(frac); i++ {
		n += int64(frac[i]-'0') * pow10(decimals-1-i)
	}
	return n, nil
}

// FormatAmount renders atomic units as the shortest exact decimal string.
func FormatAmount(atomic int64, decimals int) string {
	if atomic < 0 {
		return "-" + FormatAmount(-atomic, decimals)
	}
	div := int64(1)
	for i := 0; i < decimals; i++ {
		div *= 10
	}
	whole, frac := atomic/div, atomic%div
	if frac == 0 {
		return itoa(whole)
	}
	f := itoa(frac)
	f = strings.Repeat("0", decimals-len(f)) + f
	return itoa(whole) + "." + strings.TrimRight(f, "0")
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func pow10(n int) int64 {
	v := int64(1)
	for i := 0; i < n; i++ {
		v *= 10
	}
	return v
}
