package cli

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/127ohoh1/core/client/api"
	cid "github.com/127ohoh1/core/client/identity"
)

// ADR 0011: "Payment confirmed" waits for the new name's HTTPS certificate,
// and a certificate that doesn't come never turns a final payment into an error.
func TestWaitPaidWaitsForTheCertificate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "id")
	id, _, err := cid.LoadOrGenerate(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		states []string // offer responses, in order (the last one repeats)
		polls  int
		say    string
	}{
		{"no certificate to wait for", []string{`"payment":{"state":"ENTITLEMENT_GRANTED"}`}, 1, ""},
		{"pending then ready", []string{`"payment":{"state":"SETTLED"}`, `"payment":{"state":"ENTITLEMENT_GRANTED"},"certificate":{"hostname":"myname.example","state":"pending"}`,
			`"payment":{"state":"ENTITLEMENT_GRANTED"},"certificate":{"hostname":"myname.example","state":"ready"}`}, 3, "certificate for myname.example"},
		{"failed", []string{`"payment":{"state":"ENTITLEMENT_GRANTED"},"certificate":{"hostname":"myname.example","state":"failed"}`}, 1, "issued on the first visit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			polls := 0
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if stubAuth(w, r) {
					return
				}
				body := tc.states[min(polls, len(tc.states)-1)]
				polls++
				_, _ = w.Write([]byte(`{"offer":{"id":"off_1","status":"open"},` + body + `}`))
			}))
			defer ts.Close()
			var out bytes.Buffer
			env := Env{Stdout: &out, Stderr: &out, Getenv: func(string) string { return "" }}
			if err := waitPaid(context.Background(), api.New(ts.URL, id, nil), env, "off_1", time.Minute); err != nil {
				t.Fatal(err)
			}
			if polls != tc.polls || !strings.Contains(out.String(), tc.say) {
				t.Fatalf("polls %d, output %q", polls, out.String())
			}
		})
	}
}
