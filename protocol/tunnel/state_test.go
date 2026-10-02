package tunnel

import "testing"

func TestStateTable(t *testing.T) {
	type step struct {
		send  bool
		ev    Event
		want  State
		legal bool
	}
	cases := []struct {
		name  string
		start State
		steps []step
	}{
		{"normal exchange (opener)", StateIdle, []step{
			{true, EvOpen, StateOpen, true}, {false, EvOpenOK, StateOpen, true}, {true, EvData, StateOpen, true},
			{true, EvHalfClose, StateHalfClosedLocal, true}, {false, EvData, StateHalfClosedLocal, true},
			{false, EvHalfClose, StateClosed, true},
		}},
		{"remote finishes first", StateOpen, []step{
			{false, EvHalfClose, StateHalfClosedRemote, true}, {true, EvData, StateHalfClosedRemote, true},
			{true, EvHalfClose, StateClosed, true},
		}},
		{"data after remote half-close is illegal", StateHalfClosedRemote, []step{{false, EvData, StateHalfClosedRemote, false}}},
		{"send after local half-close is illegal", StateHalfClosedLocal, []step{{true, EvData, StateHalfClosedLocal, false}}},
		{"double half-close", StateHalfClosedLocal, []step{{true, EvHalfClose, StateHalfClosedLocal, false}}},
		{"reset closes", StateOpen, []step{{false, EvReset, StateClosed, true}}},
		{"close closes", StateHalfClosedRemote, []step{{true, EvClose, StateClosed, true}}},
		{"anything on closed is illegal", StateClosed, []step{
			{true, EvData, StateClosed, false}, {false, EvData, StateClosed, false}, {true, EvHalfClose, StateClosed, false},
		}},
		{"open twice", StateOpen, []step{{false, EvOpen, StateOpen, false}, {true, EvOpen, StateOpen, false}}},
		{"data on idle", StateIdle, []step{{false, EvData, StateIdle, false}, {true, EvData, StateIdle, false}}},
		{"reset on idle", StateIdle, []step{{false, EvReset, StateIdle, false}}},
	}
	for _, c := range cases {
		s := c.start
		for i, st := range c.steps {
			var ns State
			var err error
			if st.send {
				ns, err = s.Send(st.ev)
			} else {
				ns, err = s.Recv(st.ev)
			}
			if (err == nil) != st.legal || ns != st.want {
				t.Errorf("%s step %d (%v %v from %v): got %v,%v want %v legal=%v", c.name, i, st.send, st.ev, s, ns, err, st.want, st.legal)
			}
			s = ns
		}
	}
}

// Whatever the event sequence, the machine must stay in a valid state, and
// Closed must be absorbing.
func FuzzStateMachine(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3, 4, 5, 6, 7})
	f.Fuzz(func(t *testing.T, seq []byte) {
		s := StateIdle
		for _, b := range seq {
			ev := Event(b % 6)
			var ns State
			var err error
			if b&0x80 != 0 {
				ns, err = s.Send(ev)
			} else {
				ns, err = s.Recv(ev)
			}
			if ns > StateClosed {
				t.Fatalf("invalid state %d", ns)
			}
			if err != nil && ns != s {
				t.Fatal("illegal event changed the state")
			}
			if s == StateClosed && ns != StateClosed {
				t.Fatal("closed is not absorbing")
			}
			s = ns
		}
	})
}
