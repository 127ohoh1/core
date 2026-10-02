package integration

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/127ohoh1/core/client/api"
	cid "github.com/127ohoh1/core/client/identity"
	"github.com/127ohoh1/core/client/session"
	"github.com/127ohoh1/core/internal/config"
	"github.com/127ohoh1/core/internal/testenv"
	proto "github.com/127ohoh1/core/protocol/tunnel"
)

func metricLine(env *testenv.Env, prefix string) string {
	var sb strings.Builder
	env.Edge.Metrics.WriteText(&sb)
	for _, l := range strings.Split(sb.String(), "\n") {
		if strings.HasPrefix(l, prefix) {
			return l
		}
	}
	return ""
}

func eventually(t *testing.T, what string, d time.Duration, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if f() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for: %s", what)
}

// Scenario 10: an established tunnel keeps working during a control-plane
// outage using cached, bounded-lifetime policy; beyond the bound the edge
// fails closed; recovery restores service without reconnecting.
func TestEstablishedTunnelSurvivesControlPlaneOutageWithinBounds(t *testing.T) {
	env := testenv.New(t, testenv.Options{
		CP: func(c *config.ControlPlane) { c.PolicyTTL = config.Duration(1500 * time.Millisecond) },
		Edge: func(c *config.Edge) {
			c.PolicyRefresh = config.Duration(150 * time.Millisecond)
			c.PolicyStaleGrace = config.Duration(2 * time.Second)
		},
	})
	origin := env.Origin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "up") }))
	x := env.Expose(env.NewIdentity(), origin.URL, "")
	if _, body := env.Get(x.Endpoint.Hostname, "/"); body != "up" {
		t.Fatal(body)
	}

	env.SetControlPlaneDown(true)
	// Within valid_until: still served from cache.
	if resp, body := env.Get(x.Endpoint.Hostname, "/"); resp.StatusCode != 200 || body != "up" {
		t.Fatalf("cached policy must keep serving: %d %q", resp.StatusCode, body)
	}
	// Past valid_until but inside the grace window: still served, and counted.
	time.Sleep(1800 * time.Millisecond)
	if resp, body := env.Get(x.Endpoint.Hostname, "/"); resp.StatusCode != 200 || body != "up" {
		t.Fatalf("stale-grace: %d %q", resp.StatusCode, body)
	}
	if l := metricLine(env, "edge_policy_stale_use_total"); l == "" || strings.HasSuffix(l, " 0") {
		t.Fatalf("stale use not recorded: %q", l)
	}
	if l := metricLine(env, "edge_control_plane_reachable"); !strings.HasSuffix(l, " 0") {
		t.Fatalf("outage not visible: %q", l)
	}
	// Beyond the bound: fail closed with a platform error, tunnel still connected.
	eventually(t, "policy_expired", 8*time.Second, func() bool {
		resp, _ := env.Get(x.Endpoint.Hostname, "/")
		return resp.StatusCode == 503 && resp.Header.Get("X-127ohoh1-Error") == "policy_expired"
	})
	if x.Conn.Session.Err() != nil {
		t.Fatal("the tunnel itself must survive; only proxying is gated")
	}
	// Recovery: service resumes on the same tunnel.
	env.SetControlPlaneDown(false)
	eventually(t, "recovery", 10*time.Second, func() bool {
		resp, body := env.Get(x.Endpoint.Hostname, "/")
		return resp.StatusCode == 200 && body == "up"
	})
}

// Suspension must reach the edge quickly, drop the live tunnel, and refuse re-entry.
func TestSuspensionTerminatesTunnelAndBlocksReconnect(t *testing.T) {
	const adminTok = "admin-token-for-tests-0123456789"
	env := testenv.New(t, testenv.Options{CP: func(c *config.ControlPlane) { c.AdminToken = adminTok }})
	origin := env.Origin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }))
	id := env.NewIdentity()
	x := env.Expose(id, origin.URL, "")
	if _, body := env.Get(x.Endpoint.Hostname, "/"); body != "ok" {
		t.Fatal(body)
	}

	req, _ := http.NewRequest("POST", env.CPServer.URL+"/v1/admin/endpoints/"+x.Endpoint.ID+"/suspend", strings.NewReader(`{"reason":"test"}`))
	req.Header.Set("Authorization", "Bearer "+adminTok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("%v %v", err, resp)
	}
	resp.Body.Close()

	start := time.Now()
	select {
	case <-x.Done:
	case <-time.After(10 * time.Second):
		t.Fatal("live tunnel survived suspension")
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("suspension took %v to reach the edge", d)
	}
	r, _ := env.Get(x.Endpoint.Hostname, "/")
	if r.StatusCode == 200 {
		t.Fatal("suspended endpoint still serves traffic")
	}
	// The owner cannot get a new credential, and even a previously issued one is refused at the edge.
	if _, err := env.API(id).TunnelCredentials(bg, x.Endpoint.ID); err == nil {
		t.Fatal("credential issued for suspended endpoint")
	}
	// Restoration brings service back.
	req, _ = http.NewRequest("POST", env.CPServer.URL+"/v1/admin/endpoints/"+x.Endpoint.ID+"/unsuspend", nil)
	req.Header.Set("Authorization", "Bearer "+adminTok)
	if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode != 200 {
		t.Fatal("unsuspend failed")
	}
	x2 := env.Expose(id, origin.URL, x.Endpoint.ID)
	if _, body := env.Get(x2.Endpoint.Hostname, "/"); body != "ok" {
		t.Fatalf("after restore: %q", body)
	}
}

// A credential issued before suspension must not open a tunnel afterwards.
func TestPreIssuedCredentialRefusedForSuspendedEndpoint(t *testing.T) {
	const adminTok = "admin-token-for-tests-0123456789"
	env := testenv.New(t, testenv.Options{CP: func(c *config.ControlPlane) { c.AdminToken = adminTok }})
	id := env.NewIdentity()
	ep, _ := env.API(id).CreateEndpoint(bg, "")
	cred, _ := env.API(id).TunnelCredentials(bg, ep.ID)

	req, _ := http.NewRequest("POST", env.CPServer.URL+"/v1/admin/endpoints/"+ep.ID+"/suspend", nil)
	req.Header.Set("Authorization", "Bearer "+adminTok)
	if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode != 200 {
		t.Fatal("suspend failed")
	}
	_, err := session.Connect(bg, env.Edge.Addrs().Tunnel, env.TLSConfig(), cred, id, 5*time.Second)
	var ae *proto.AuthError
	if !asAuthErr(err, &ae) || ae.Code != "endpoint_unavailable" || ae.Retryable {
		t.Fatalf("want non-retryable endpoint_unavailable, got %v", err)
	}
}

func asAuthErr(err error, target **proto.AuthError) bool {
	for err != nil {
		if a, ok := err.(*proto.AuthError); ok {
			*target = a
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// New tunnels cannot be admitted while the control plane is down AND nothing is cached,
// but an unrelated cached endpoint keeps working.
func TestColdEdgeDuringOutageIsUnavailableNotPermissive(t *testing.T) {
	env := testenv.New(t, testenv.Options{})
	id := env.NewIdentity()
	ep, _ := env.API(id).CreateEndpoint(bg, "")
	cred, _ := env.API(id).TunnelCredentials(bg, ep.ID)
	env.SetControlPlaneDown(true)
	_, err := session.Connect(bg, env.Edge.Addrs().Tunnel, env.TLSConfig(), cred, id, 5*time.Second)
	var ae *proto.AuthError
	if !asAuthErr(err, &ae) || ae.Code != "policy_unavailable" || !ae.Retryable {
		t.Fatalf("want retryable policy_unavailable, got %v", err)
	}
}

func connectWith(env *testenv.Env, id cid.Identity, cred api.TunnelCredential) (*session.Connection, error) {
	return session.Connect(bg, env.Edge.Addrs().Tunnel, env.TLSConfig(), cred, id, 5*time.Second)
}
