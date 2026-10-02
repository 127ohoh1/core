package integration

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/127ohoh1/core/internal/config"
	"github.com/127ohoh1/core/internal/devtls"
	"github.com/127ohoh1/core/internal/testenv"
)

func httpsEnv(t *testing.T, mut func(*config.Edge)) *testenv.Env {
	return testenv.New(t, testenv.Options{Edge: func(c *config.Edge) {
		c.IngressPlainHTTP = false
		if mut != nil {
			mut(c)
		}
	}})
}

func TestHTTPSIngressServesHTTP2(t *testing.T) {
	env := httpsEnv(t, nil)
	origin := env.Origin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "proto=%s xfp=%s", r.Proto, r.Header.Get("X-Forwarded-Proto"))
	}))
	x := env.Expose(env.NewIdentity(), origin.URL, "")
	host := x.Endpoint.Hostname + "." + testenv.BaseDomain
	c := env.HTTPSClient(host)
	resp, err := c.Get("https://" + host + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.ProtoMajor != 2 {
		t.Fatalf("expected HTTP/2 to the public caller, got %s", resp.Proto)
	}
	if string(b) != "proto=HTTP/1.1 xfp=https" { // the origin leg is HTTP/1.1 by design
		t.Fatalf("%q", b)
	}
	if resp.TLS == nil || resp.TLS.Version < tls.VersionTLS12 {
		t.Fatal("weak TLS")
	}
}

// SNI and Host must name the same tenant; otherwise one tenant's TLS session
// could be used to address another's traffic.
func TestSNIHostMismatchIsRejected(t *testing.T) {
	env := httpsEnv(t, nil)
	origin := env.Origin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "secret of "+r.Host) }))
	victim := env.Expose(env.NewIdentity(), origin.URL, "")
	attacker := env.Expose(env.NewIdentity(), origin.URL, "")
	vhost := victim.Endpoint.Hostname + "." + testenv.BaseDomain
	ahost := attacker.Endpoint.Hostname + "." + testenv.BaseDomain

	get := func(sni, host string) (int, string) {
		c := env.HTTPSClient(sni)
		req, _ := http.NewRequest("GET", "https://"+sni+"/", nil)
		req.Host = host
		resp, err := c.Do(req)
		if err != nil {
			t.Fatalf("sni=%s host=%s: %v", sni, host, err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, resp.Header.Get("X-127ohoh1-Error") + "|" + string(b)
	}
	if code, body := get(ahost, ahost); code != 200 || !strings.Contains(body, "secret of "+ahost) {
		t.Fatalf("legitimate: %d %s", code, body)
	}
	// TLS session for the attacker's name, Host header of the victim (domain fronting).
	if code, body := get(ahost, vhost); code != 421 || !strings.HasPrefix(body, "misdirected_request") || strings.Contains(body, "secret") {
		t.Fatalf("SNI/Host mismatch not rejected: %d %s", code, body)
	}
	// Certificates cover the wildcard, so a bare-domain SNI verifies but must not route.
	if code, _ := get(testenv.BaseDomain, vhost); code != 421 {
		t.Fatalf("apex SNI with tenant Host: %d", code)
	}
	// No SNI at all (IP literal).
	c := env.HTTPSClient("127.0.0.1")
	req, _ := http.NewRequest("GET", "https://127.0.0.1/", nil)
	req.Host = vhost
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 421 {
		t.Fatalf("empty SNI: %d", resp.StatusCode)
	}
}

func servedSerial(t *testing.T, env *testenv.Env, addr, sni string) string {
	t.Helper()
	c, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: env.Edge.TLS.CAPool(), ServerName: sni})
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	defer c.Close()
	return c.ConnectionState().PeerCertificates[0].SerialNumber.Text(16)
}

// Certificate rotation: atomic, validated, and invisible to established tunnels.
func TestCertificateRotationWithoutDroppingTunnels(t *testing.T) {
	env := httpsEnv(t, func(c *config.Edge) { c.CertReloadInterval = config.Duration(100 * time.Millisecond) })
	origin := env.Origin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "still here") }))
	x := env.Expose(env.NewIdentity(), origin.URL, "")
	host := x.Endpoint.Hostname + "." + testenv.BaseDomain
	dir := env.Edge.Cfg.DevTLSDir
	names := []string{testenv.BaseDomain, "*." + testenv.BaseDomain, "localhost", "127.0.0.1", "::1"}

	before := servedSerial(t, env, env.Edge.Addrs().Ingress, host)
	tunnelBefore := servedSerial(t, env, env.Edge.Addrs().Tunnel, "127.0.0.1")
	if before != tunnelBefore {
		t.Fatal("ingress and tunnel must serve the same wildcard certificate")
	}

	// A bad replacement (right CA, wrong names) is rejected; the old one keeps serving.
	bad, err := devtls.Reissue(env.Edge.TLS, []string{"other.example.org"}, time.Now(), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	bad.WriteLeaf(dir)
	eventually(t, "rejected reload counted", 5*time.Second, func() bool {
		return strings.Contains(metricLine(env, `edge_certificate_reloads_total{result="error"}`), " 1")
	})
	if servedSerial(t, env, env.Edge.Addrs().Ingress, host) != before {
		t.Fatal("a certificate that does not cover the base domain was activated")
	}
	// Garbage is rejected too.
	os.WriteFile(filepath.Join(dir, "cert.pem"), []byte("not a certificate"), 0o644)
	time.Sleep(300 * time.Millisecond)
	if servedSerial(t, env, env.Edge.Addrs().Ingress, host) != before {
		t.Fatal("garbage replaced the certificate")
	}

	// A proper renewal is picked up atomically.
	good, err := devtls.Reissue(env.Edge.TLS, names, time.Now(), 90*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	good.WriteLeaf(dir)
	eventually(t, "rotation", 5*time.Second, func() bool { return servedSerial(t, env, env.Edge.Addrs().Ingress, host) != before })
	after := servedSerial(t, env, env.Edge.Addrs().Ingress, host)
	if servedSerial(t, env, env.Edge.Addrs().Tunnel, "127.0.0.1") != after {
		t.Fatal("tunnel listener did not rotate with ingress")
	}

	// The tunnel that was established *before* the rotation is untouched and serving.
	c := env.HTTPSClient(host)
	resp, err := c.Get("https://" + host + "/")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "still here" || x.Conn.Session.Err() != nil {
		t.Fatalf("rotation disturbed the tunnel: %q %v", b, x.Conn.Session.Err())
	}
	// New tunnels can be established against the rotated certificate too.
	y := env.Expose(env.NewIdentity(), origin.URL, "")
	if _, ok := env.Edge.Registry.ByHostname(y.Endpoint.Hostname); !ok {
		t.Fatal("new tunnel after rotation")
	}
}

func TestSIGHUPPathReloadsImmediately(t *testing.T) {
	env := httpsEnv(t, func(c *config.Edge) { c.CertReloadInterval = config.Duration(time.Hour) }) // no polling
	host := "x." + testenv.BaseDomain
	before := servedSerial(t, env, env.Edge.Addrs().Ingress, host)
	good, _ := devtls.Reissue(env.Edge.TLS, []string{testenv.BaseDomain, "*." + testenv.BaseDomain, "127.0.0.1"}, time.Now(), 24*time.Hour)
	good.WriteLeaf(env.Edge.Cfg.DevTLSDir)
	if err := env.Edge.ReloadCertificates(); err != nil {
		t.Fatal(err)
	}
	if servedSerial(t, env, env.Edge.Addrs().Ingress, host) == before {
		t.Fatal("reload did not swap the certificate")
	}
}

func adminGet(t *testing.T, env *testenv.Env, path string) (int, string) {
	t.Helper()
	resp, err := http.Get("http://" + env.Edge.Addrs().Admin + path)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// Liveness must not depend on dependencies; readiness must drop before draining.
func TestLivenessReadinessSemantics(t *testing.T) {
	env := testenv.New(t, testenv.Options{})
	if c, _ := adminGet(t, env, "/healthz"); c != 200 {
		t.Fatalf("healthz %d", c)
	}
	eventually(t, "ready", 5*time.Second, func() bool { c, _ := adminGet(t, env, "/readyz"); return c == 200 })

	env.SetControlPlaneDown(true) // a dependency outage
	time.Sleep(300 * time.Millisecond)
	if c, _ := adminGet(t, env, "/healthz"); c != 200 {
		t.Fatal("liveness failed because the control plane is down: a restart would not help and would drop tunnels")
	}
	env.SetControlPlaneDown(false)

	// Draining: readiness fails first while an in-flight request still completes.
	release := make(chan struct{})
	started := make(chan struct{})
	origin := env.Origin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(started); <-release; fmt.Fprint(w, "finished") }))
	x := env.Expose(env.NewIdentity(), origin.URL, "")
	res := make(chan string, 1)
	go func() { _, b := env.Get(x.Endpoint.Hostname, "/"); res <- b }()
	<-started
	go env.StopEdge(10 * time.Second)
	eventually(t, "readiness drops", 5*time.Second, func() bool {
		resp, err := http.Get("http://" + env.Edge.Addrs().Admin + "/readyz")
		if err != nil {
			return true // admin already gone also means "not ready"
		}
		resp.Body.Close()
		return resp.StatusCode == 503
	})
	close(release)
	select {
	case b := <-res:
		if b != "finished" {
			t.Fatalf("in-flight request was cut off during drain: %q", b)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("in-flight request never completed")
	}
}

// One proxied request must be diagnosable end to end without leaking secrets.
func TestRequestIsDiagnosableAndLogsAreRedacted(t *testing.T) {
	logs := &testenv.LogBuffer{}
	env := testenv.New(t, testenv.Options{LogWriter: logs})
	var originTP string
	origin := env.Origin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originTP = r.Header.Get("Traceparent")
		fmt.Fprint(w, "diag")
	}))
	x := env.Expose(env.NewIdentity(), origin.URL, "")

	const trace = "0af7651916cd43dd8448eb211c80319c"
	resp, err := env.Request(x.Endpoint.Hostname, "GET", "/private/path?token=SUPERSECRET&x=1", nil, map[string]string{
		"Traceparent": "00-" + trace + "-b7ad6b7169203331-01", "Authorization": "Bearer TOPSECRETBEARER", "Cookie": "sid=COOKIESECRET",
	})
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	reqID := resp.Header.Get("X-Request-Id")

	if !strings.Contains(originTP, trace) {
		t.Fatalf("trace id lost on the way to the origin: %q", originTP)
	}
	// The request log line is written after the response completes: wait for it.
	var out, line string
	eventually(t, "request log line", 5*time.Second, func() bool {
		out = logs.String()
		for _, l := range strings.Split(out, "\n") {
			if strings.Contains(l, `"ingress.request"`) && strings.Contains(l, reqID) {
				line = l
				return true
			}
		}
		return false
	})
	for _, want := range []string{trace, x.Endpoint.ID, `"status":200`, `"bytes_out":4`, `"edge_id"`} {
		if !strings.Contains(line, want) {
			t.Errorf("log line lacks %s: %s", want, line)
		}
	}
	for _, secret := range []string{"SUPERSECRET", "TOPSECRETBEARER", "COOKIESECRET", "/private/path"} {
		if strings.Contains(out, secret) {
			t.Errorf("logs leak %q", secret)
		}
	}
	// Metrics tell the same story.
	for _, want := range []string{`edge_ingress_requests_total{status_class="2xx",platform_error=""}`, `edge_proxied_bytes_total{direction="out"} 4`, "edge_ingress_request_duration_seconds_count", "edge_tunnel_sessions_active 1", "process_goroutines"} {
		var sb strings.Builder
		env.Edge.Metrics.WriteText(&sb)
		if !strings.Contains(sb.String(), want) {
			t.Errorf("metrics lack %s", want)
		}
	}
}
