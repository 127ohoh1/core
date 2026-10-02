package failure

import (
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/127ohoh1/core/client/session"
	"github.com/127ohoh1/core/internal/testenv"
)

var fastBackoff = session.Backoff{Base: 20 * time.Millisecond, Max: 200 * time.Millisecond}

func TestClientReconnectsAfterServerSideDisconnect(t *testing.T) {
	env := testenv.New(t, testenv.Options{})
	origin := env.Origin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "alive") }))
	r := env.RunClient(env.NewIdentity(), origin.URL, "", fastBackoff)
	env.WaitRegistered(r.Endpoint.Hostname)

	live, _ := env.Edge.Registry.ByHostname(r.Endpoint.Hostname)
	first := live.SessionID
	live.Session.Close() // edge drops the connection abruptly
	eventually(t, "reconnect", 10*time.Second, func() bool {
		l, ok := env.Edge.Registry.ByHostname(r.Endpoint.Hostname)
		return ok && l.SessionID != first
	})
	if _, body := env.Get(r.Endpoint.Hostname, "/"); body != "alive" {
		t.Fatalf("%q", body)
	}
	if r.Connects() < 2 {
		t.Fatalf("connects = %d", r.Connects())
	}
}

// Edge restart and client reconnect: the same name comes back.
func TestEdgeRestartClientReconnects(t *testing.T) {
	env := testenv.New(t, testenv.Options{})
	origin := env.Origin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "after-restart") }))
	r := env.RunClient(env.NewIdentity(), origin.URL, "", fastBackoff)
	env.WaitRegistered(r.Endpoint.Hostname)

	env.StopEdge(3 * time.Second)
	env.StartEdge()
	env.WaitRegistered(r.Endpoint.Hostname)
	resp, body := env.Get(r.Endpoint.Hostname, "/")
	if resp.StatusCode != 200 || body != "after-restart" {
		t.Fatalf("%d %q", resp.StatusCode, body)
	}
	sawReconnecting := false
	for _, s := range r.States() {
		if s == string(session.StateReconnecting) {
			sawReconnecting = true
		}
	}
	if !sawReconnecting {
		t.Fatalf("states: %v", r.States())
	}
}

func TestRunStopsPromptlyOnCancel(t *testing.T) {
	env := testenv.New(t, testenv.Options{})
	origin := env.Origin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	r := env.RunClient(env.NewIdentity(), origin.URL, "", session.Backoff{Base: time.Hour, Max: time.Hour})
	env.WaitRegistered(r.Endpoint.Hostname)
	start := time.Now()
	r.Cancel()
	select {
	case err := <-r.Done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop after cancellation")
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("slow stop: %v", time.Since(start))
	}
	eventually(t, "edge notices disconnect", 5*time.Second, func() bool { _, ok := env.Edge.Registry.ByHostname(r.Endpoint.Hostname); return !ok })
}

func TestRunStopsOnNonRetryableCredentialError(t *testing.T) {
	env := testenv.New(t, testenv.Options{})
	origin := env.Origin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	id := env.NewIdentity()
	r := env.RunClient(id, origin.URL, "", fastBackoff)
	env.WaitRegistered(r.Endpoint.Hostname)
	// Releasing the endpoint makes credentials unobtainable (410): retrying is pointless.
	if _, err := env.API(id).DeleteEndpoint(bg, r.Endpoint.ID); err != nil {
		t.Fatal(err)
	}
	live, _ := env.Edge.Registry.ByHostname(r.Endpoint.Hostname)
	live.Session.Close()
	select {
	case err := <-r.Done:
		var fe *session.FatalError
		if !errors.As(err, &fe) {
			t.Fatalf("want FatalError, got %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("client kept retrying a released endpoint")
	}
}

// After GOAWAY (superseded by another instance) the old client must not
// stampede: it backs off rather than hammering the edge.
func TestGoAwayTriggersReplacementBeforeOldDrainsFully(t *testing.T) {
	env := testenv.New(t, testenv.Options{})
	origin := env.Origin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }))
	r := env.RunClient(env.NewIdentity(), origin.URL, "", fastBackoff)
	env.WaitRegistered(r.Endpoint.Hostname)
	live, _ := env.Edge.Registry.ByHostname(r.Endpoint.Hostname)
	first := live.SessionID
	live.Session.GoAway(11) // edge announces a drain (as on shutdown)
	eventually(t, "replacement session", 10*time.Second, func() bool {
		l, ok := env.Edge.Registry.ByHostname(r.Endpoint.Hostname)
		return ok && l.SessionID != first
	})
	if _, body := env.Get(r.Endpoint.Hostname, "/"); body != "ok" {
		t.Fatalf("%q", body)
	}
}
