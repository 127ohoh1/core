package cli

import (
	"bufio"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/127ohoh1/core/client/api"
)

// reserveFlow obtains a reserved endpoint, walking through the 402 offer and
// payment if needed. It never pays implicitly: consent is either an explicit
// --yes or an interactive confirmation; without either it stops with the
// payment exit code and the offer printed.
func reserveFlow(ctx context.Context, c *api.Client, env Env, name, plan string, yes, simulate bool, wait time.Duration) (api.Endpoint, error) {
	idem := fmt.Sprintf("reserve-%s-%s-%s", c.Identity.Fingerprint()[:12], name, plan)
	ep, pr, err := c.Reserve(ctx, name, plan, idem)
	if err != nil {
		return api.Endpoint{}, err
	}
	if pr == nil {
		return ep, nil // already entitled
	}
	o := pr.Offers[0]
	if len(o.PaymentMethods) == 0 {
		return api.Endpoint{}, fail(ExitFailure, "the server offered no payment method")
	}
	pm := o.PaymentMethods[0]

	fmt.Fprintf(env.Stdout, "Premium feature: reserved hostname\n")
	fmt.Fprintf(env.Stdout, "Price: %s\n", formatPrice(o.Price.Amount, o.Price.Asset, o.Price.Interval, o.Price.Unit))
	fmt.Fprintf(env.Stdout, "Bandwidth: %s/name\n", formatRate(o.Limits.BandwidthBytesPerSecond))
	fmt.Fprintf(env.Stdout, "Monthly transfer: %s/name\n\n", formatBytes(o.Limits.MonthlyTransferBytes))
	if o.CheckoutURL != "" && !pm.Simulated {
		if simulate {
			return api.Endpoint{}, fail(ExitUsage, "--simulate-settlement only works with simulated payment methods")
		}
		if err := browserCheckout(env, o, c.Identity.Fingerprint(), yes); err != nil {
			return api.Endpoint{}, err
		}
		// The link stays payable until the offer expires; allow --wait on top
		// for the confirmations of a payment signed at the last minute.
		if left := time.Until(o.ExpiresAt); left > 0 {
			wait += left
		}
		return settleAndReserve(ctx, c, env, name, plan, idem, o, wait)
	}
	label := ""
	if pm.Simulated {
		label = " (SIMULATED: no real money moves)"
	}
	fmt.Fprintf(env.Stdout, "Payment required: %s%s\n", pm.PaymentRequest, label)

	if !yes {
		if !env.Interactive {
			fmt.Fprintf(env.Stderr, "Not paying: re-run with --yes to accept this offer%s.\n", map[bool]string{true: " and --simulate-settlement to settle it against a development server", false: ""}[pm.Simulated])
			return api.Endpoint{}, fail(ExitPayment, "payment required for %q (%s)", name, o.ID)
		}
		fmt.Fprintf(env.Stdout, "Proceed with this %spayment? [y/N] ", map[bool]string{true: "SIMULATED ", false: ""}[pm.Simulated])
		line, _ := bufio.NewReader(env.Stdin).ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(line)); a != "y" && a != "yes" {
			return api.Endpoint{}, fail(ExitPayment, "payment declined")
		}
	}

	if simulate {
		if !pm.Simulated {
			return api.Endpoint{}, fail(ExitUsage, "--simulate-settlement only works with simulated payment methods")
		}
		fmt.Fprintln(env.Stdout, "Requesting simulated settlement (development mode)...")
		if _, err := c.SimulateSettlement(ctx, o.PaymentID); err != nil {
			return api.Endpoint{}, fmt.Errorf("simulated settlement failed: %w", err)
		}
	}
	fmt.Fprintln(env.Stdout, "Waiting for settlement...")
	return settleAndReserve(ctx, c, env, name, plan, idem, o, wait)
}

func settleAndReserve(ctx context.Context, c *api.Client, env Env, name, plan, idem string, o api.Offer, wait time.Duration) (api.Endpoint, error) {
	if err := waitPaid(ctx, c, env, o.ID, wait); err != nil {
		return api.Endpoint{}, err
	}
	fmt.Fprintln(env.Stdout, "Payment confirmed.")

	ep, pr, err := c.Reserve(ctx, name, plan, idem) // same request, same key: now returns the resource
	if err != nil {
		return api.Endpoint{}, err
	}
	if pr != nil {
		return api.Endpoint{}, fail(ExitFailure, "payment confirmed but the name is still not entitled; contact support with offer %s", o.ID)
	}
	return ep, nil
}

// browserCheckout hands the offer to the server's checkout page. The CLI never
// signs or pays: the person does, in their own wallet, on that page. Waiting
// for them needs consent like any payment: a terminal a human is at, or --yes.
func browserCheckout(env Env, o api.Offer, fingerprint string, yes bool) error {
	fmt.Fprintf(env.Stdout, "Pay in your browser: %s\n", o.CheckoutURL)
	fmt.Fprintf(env.Stdout, "The page shows this exact offer. Check that it names your key: %s\n", fingerprint)
	fmt.Fprintln(env.Stdout, "Nothing is paid until you sign in your own wallet. Anyone with the link can pay it, so share it only with whoever pays.")
	if !yes && !env.Interactive {
		fmt.Fprintln(env.Stderr, "Not waiting: open the link to pay, then run this again, or re-run with --yes to wait for the payment.")
		return fail(ExitPayment, "payment required for %q (%s)", o.Scope.Name, o.ID)
	}
	if env.Interactive && env.OpenURL != nil {
		if err := env.OpenURL(o.CheckoutURL); err != nil {
			fmt.Fprintln(env.Stdout, "Could not open a browser; open the link above yourself.")
		} else {
			fmt.Fprintln(env.Stdout, "Opened it in your browser.")
		}
	}
	fmt.Fprintf(env.Stdout, "Waiting for payment (the link is valid until %s; Ctrl-C stops waiting, not the offer)...\n", o.ExpiresAt.Local().Format("15:04"))
	return nil
}

// certWait bounds how long a settled payment waits for its HTTPS
// certificate. The payment is final either way; past this the certificate is
// simply issued on the first visit instead.
const certWait = 3 * time.Minute

// waitPaid polls until the payment is granted and, where the server warms a
// certificate for the new name (ADR 0011), until that certificate is ready,
// so "Payment confirmed" means the name works over HTTPS straight away.
func waitPaid(ctx context.Context, c *api.Client, env Env, offerID string, wait time.Duration) error {
	deadline := time.Now().Add(wait)
	var certDeadline time.Time
	for {
		st, err := c.GetOffer(ctx, offerID)
		if err != nil {
			return err
		}
		paid := st.Offer.Status == "paid" || st.Payment.State == "ENTITLEMENT_GRANTED"
		switch {
		case paid && (st.Certificate == nil || st.Certificate.State == "ready"):
			return nil
		case paid && st.Certificate.State != "pending":
			fmt.Fprintln(env.Stdout, "The HTTPS certificate isn't ready yet; it is issued on the first visit instead (a few seconds).")
			return nil
		case paid:
			if certDeadline.IsZero() {
				certDeadline = time.Now().Add(certWait)
				fmt.Fprintf(env.Stdout, "Finishing setup: getting the HTTPS certificate for %s ready...\n", st.Certificate.Hostname)
			}
			if time.Now().After(certDeadline) {
				fmt.Fprintln(env.Stdout, "The HTTPS certificate is taking longer than usual; it is issued on the first visit instead.")
				return nil
			}
		case st.Offer.Status == "expired" || st.Payment.State == "EXPIRED":
			return fail(ExitPayment, "the offer expired before payment was confirmed")
		case st.Payment.State == "FAILED":
			return fail(ExitPayment, "the payment failed (%s)", st.Payment.Reason)
		case st.Payment.State == "SETTLED":
			// money received, entitlement being granted: keep polling
		}
		if !paid && time.Now().After(deadline) {
			return fail(ExitPayment, "timed out waiting for settlement")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func cmdPlans(ctx context.Context, args []string, env Env) error {
	if len(args) == 0 || args[0] != "list" {
		return fail(ExitUsage, "plans: expected `list`")
	}
	var g global
	fs := newFlagSet("plans list", env)
	g.register(fs, env)
	if _, err := parseInterleaved(fs, args[1:]); err != nil {
		return fail(ExitUsage, "%v", err)
	}
	c, _, err := g.client()
	if err != nil {
		return err
	}
	plans, err := c.Plans(ctx)
	if err != nil {
		return err
	}
	if g.json {
		return printJSON(env.Stdout, plans)
	}
	fmt.Fprintf(env.Stdout, "%-8s %-22s %-12s %-14s %s\n", "PLAN", "PRICE", "BANDWIDTH", "TRANSFER/MONTH", "HOSTNAME")
	for _, p := range plans {
		fmt.Fprintf(env.Stdout, "%-8s %-22s %-12s %-14s %s\n", p.ID, formatPrice(p.Price.Amount, p.Price.Asset, p.Price.Interval, p.Price.Unit),
			formatRate(p.BandwidthBytesPerSecond), formatBytes(p.MonthlyTransferBytes), p.Hostname)
	}
	fmt.Fprintln(env.Stdout, "\nUnits are decimal SI (1 kB = 1,000 bytes). Prices are per month per name.")
	return nil
}

func cmdPayments(ctx context.Context, args []string, env Env) error {
	if len(args) == 0 || args[0] != "simulate" {
		return fail(ExitUsage, "payments: expected `simulate PAYMENT_ID`")
	}
	var g global
	fs := newFlagSet("payments simulate", env)
	g.register(fs, env)
	pos, err := parseInterleaved(fs, args[1:])
	if err != nil || len(pos) != 1 {
		return fail(ExitUsage, "payments simulate: expected exactly one PAYMENT_ID")
	}
	c, _, err := g.client()
	if err != nil {
		return err
	}
	p, err := c.SimulateSettlement(ctx, pos[0])
	if err != nil {
		if api.IsCode(err, "not_found") {
			return fail(ExitFailure, "not found (or simulated payments are not enabled on this server)")
		}
		return err
	}
	if g.json {
		return printJSON(env.Stdout, p)
	}
	fmt.Fprintf(env.Stdout, "SIMULATED payment %s: %s\n", p.ID, p.State)
	return nil
}
