package payment

import "fmt"

// State is the payment lifecycle (spec section 11.1).
//
//	CREATED -> AWAITING_PAYMENT -> SEEN -> CONFIRMING -> SETTLED -> ENTITLEMENT_GRANTED
//	                |               |          |
//	                +-> EXPIRED <---+          +-> FAILED
//
// The development adapter walks the middle states in one step but every
// transition is still validated, so a production adapter can move through
// them over time without changing the domain model.
type State string

const (
	StateCreated            State = "CREATED"
	StateAwaitingPayment    State = "AWAITING_PAYMENT"
	StateSeen               State = "SEEN"
	StateConfirming         State = "CONFIRMING"
	StateSettled            State = "SETTLED"
	StateEntitlementGranted State = "ENTITLEMENT_GRANTED"
	StateExpired            State = "EXPIRED"
	StateFailed             State = "FAILED"
)

var transitions = map[State][]State{
	StateCreated:            {StateAwaitingPayment, StateExpired, StateFailed},
	StateAwaitingPayment:    {StateSeen, StateExpired, StateFailed},
	StateSeen:               {StateConfirming, StateExpired, StateFailed},
	StateConfirming:         {StateSettled, StateFailed},
	StateSettled:            {StateEntitlementGranted},
	StateEntitlementGranted: nil,
	StateExpired:            nil,
	StateFailed:             nil,
}

// CanTransition reports whether from -> to is allowed.
func CanTransition(from, to State) bool {
	for _, s := range transitions[from] {
		if s == to {
			return true
		}
	}
	return false
}

// Terminal reports whether no further transition is possible.
func (s State) Terminal() bool { return len(transitions[s]) == 0 }

// Settled reports whether money is considered received (final states after settlement).
func (s State) Settled() bool { return s == StateSettled || s == StateEntitlementGranted }

// TransitionError is returned for an illegal transition.
type TransitionError struct{ From, To State }

func (e *TransitionError) Error() string {
	return fmt.Sprintf("payment: invalid transition %s -> %s", e.From, e.To)
}
