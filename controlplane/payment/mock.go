package payment

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/127ohoh1/core/internal/config"
)

// MockProofPrefix makes every development proof unmistakable. The format is
// intentionally trivial and is never accepted by a production verifier.
const MockProofPrefix = "devpay-proof:v0-NOT-FOR-PRODUCTION:"

// ErrMockInProduction is returned when a mock component is requested in a
// production profile.
var ErrMockInProduction = errors.New("payment: mock payment components cannot be created when app_env=production")

// MockVerifier (Development adapter) accepts proofs of the form
//
//	devpay-proof:v0-NOT-FOR-PRODUCTION:<payment_id>:<amount_atomic>:<asset>
//
// and reports them as settled on the "development" network. It performs no
// cryptographic or on-chain verification whatsoever.
type MockVerifier struct{}

// NewMockVerifier creates the development verifier, refusing production.
func NewMockVerifier(appEnv string) (*MockVerifier, error) {
	if appEnv == config.EnvProduction {
		return nil, ErrMockInProduction
	}
	return &MockVerifier{}, nil
}

// MockProof builds a development proof string.
func MockProof(paymentID string, atomic int64, asset string) string {
	return fmt.Sprintf("%s%s:%d:%s", MockProofPrefix, paymentID, atomic, asset)
}

func (MockVerifier) Verify(_ context.Context, proof PaymentProof) (PaymentResult, error) {
	if proof.Provider != DevProvider || !strings.HasPrefix(proof.Raw, MockProofPrefix) {
		return PaymentResult{}, errors.New("payment: not a development proof")
	}
	parts := strings.Split(strings.TrimPrefix(proof.Raw, MockProofPrefix), ":")
	if len(parts) != 3 || parts[0] == "" {
		return PaymentResult{}, errors.New("payment: malformed development proof")
	}
	var atomic int64
	if _, err := fmt.Sscanf(parts[1], "%d", &atomic); err != nil || atomic <= 0 {
		return PaymentResult{}, errors.New("payment: malformed amount")
	}
	return PaymentResult{Settled: true, EventID: "devevt-" + parts[0], PaymentID: parts[0],
		Amount: Money{Atomic: atomic, Asset: parts[2]}, Network: DevNetwork}, nil
}
