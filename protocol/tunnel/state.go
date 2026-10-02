package tunnel

import (
	"errors"
	"fmt"
)

// State is a stream's lifecycle state.
//
//	idle --OPEN--> open --HALF_CLOSE(local)--> half-closed(local) --HALF_CLOSE(remote)--> closed
//	                 |--HALF_CLOSE(remote)--> half-closed(remote) --HALF_CLOSE(local)---> closed
//	any non-idle --CLOSE / RESET--> closed
type State uint8

const (
	StateIdle State = iota
	StateOpen
	StateHalfClosedLocal  // we finished sending; may still receive
	StateHalfClosedRemote // peer finished sending; we may still send
	StateClosed
)

func (s State) String() string {
	return [...]string{"idle", "open", "half-closed(local)", "half-closed(remote)", "closed"}[s]
}

// Event is something that happens to a stream, from either side.
type Event uint8

const (
	EvOpen Event = iota
	EvOpenOK
	EvData
	EvHalfClose
	EvClose
	EvReset
)

func (e Event) String() string {
	return [...]string{"OPEN", "OPEN_OK", "DATA", "HALF_CLOSE", "CLOSE", "RESET"}[e]
}

// ErrStreamState marks an event that is illegal in the current state. It is a
// *stream* error: it resets that stream and never tears down the connection.
var ErrStreamState = errors.New("tunnel: invalid stream state transition")

func stateErr(s State, dir string, e Event) error {
	return fmt.Errorf("%w: %s %s in %s", ErrStreamState, dir, e, s)
}

// Send applies a locally generated event and returns the new state.
func (s State) Send(e Event) (State, error) {
	switch e {
	case EvOpen:
		if s == StateIdle {
			return StateOpen, nil
		}
	case EvOpenOK: // only the acceptor sends OPEN_OK, while the stream is live
		if s == StateOpen || s == StateHalfClosedRemote || s == StateHalfClosedLocal {
			return s, nil
		}
	case EvData:
		if s == StateOpen || s == StateHalfClosedRemote {
			return s, nil
		}
	case EvHalfClose:
		switch s {
		case StateOpen:
			return StateHalfClosedLocal, nil
		case StateHalfClosedRemote:
			return StateClosed, nil
		}
	case EvClose, EvReset:
		if s != StateIdle {
			return StateClosed, nil
		}
	}
	return s, stateErr(s, "send", e)
}

// Recv applies an event received from the peer.
func (s State) Recv(e Event) (State, error) {
	switch e {
	case EvOpen:
		if s == StateIdle {
			return StateOpen, nil
		}
	case EvOpenOK:
		if s == StateOpen || s == StateHalfClosedRemote || s == StateHalfClosedLocal {
			return s, nil
		}
	case EvData:
		if s == StateOpen || s == StateHalfClosedLocal {
			return s, nil
		}
	case EvHalfClose:
		switch s {
		case StateOpen:
			return StateHalfClosedRemote, nil
		case StateHalfClosedLocal:
			return StateClosed, nil
		}
	case EvClose, EvReset:
		if s != StateIdle {
			return StateClosed, nil
		}
	}
	return s, stateErr(s, "recv", e)
}
