package cli

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/127ohoh1/core/client/api"
)

func checkoutOffer() api.Offer {
	var o api.Offer
	o.ID, o.CheckoutURL, o.ExpiresAt = "off_1", "https://127ohoh1.example/app/pay/off_1#t=abc", time.Now().Add(20*time.Minute)
	o.Scope.Name = "myproject"
	return o
}

func TestBrowserCheckoutNeedsConsentToWaitAndNeverPays(t *testing.T) {
	var out, errb bytes.Buffer
	opened := ""
	env := Env{Stdout: &out, Stderr: &errb, OpenURL: func(u string) error { opened = u; return nil }}

	// Non-interactive without --yes: the link and the key are printed, nothing is opened, exit 4.
	err := browserCheckout(env, checkoutOffer(), "SHA256:fp", false)
	var ee *exitError
	if !errors.As(err, &ee) || ee.code != ExitPayment {
		t.Fatalf("want payment exit, got %v", err)
	}
	for _, want := range []string{"Pay in your browser: https://127ohoh1.example/app/pay/off_1#t=abc", "SHA256:fp", "Nothing is paid until you sign"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out.String())
		}
	}
	if opened != "" {
		t.Fatal("opened a browser without a person at the terminal")
	}

	// --yes in a script: waits, still opens nothing.
	out.Reset()
	if err := browserCheckout(env, checkoutOffer(), "SHA256:fp", true); err != nil || opened != "" || !strings.Contains(out.String(), "Waiting for payment") {
		t.Fatalf("--yes: %v opened=%q\n%s", err, opened, out.String())
	}

	// A person at the terminal: the page is opened for them.
	env.Interactive = true
	if err := browserCheckout(env, checkoutOffer(), "SHA256:fp", false); err != nil || opened != checkoutOffer().CheckoutURL {
		t.Fatalf("interactive: %v opened=%q", err, opened)
	}
	env.OpenURL = func(string) error { return errors.New("no display") }
	out.Reset()
	if err := browserCheckout(env, checkoutOffer(), "SHA256:fp", false); err != nil || !strings.Contains(out.String(), "open the link above yourself") {
		t.Fatalf("opener failure: %v\n%s", err, out.String())
	}
}

func TestOpenBrowserRefusesAnythingButHTTPS(t *testing.T) {
	for _, u := range []string{"", "http://127ohoh1.example/x", "file:///etc/passwd", "javascript:alert(1)", "https://", "-a Calculator"} {
		if err := openBrowser(u); err == nil {
			t.Errorf("opened %q", u)
		}
	}
}
