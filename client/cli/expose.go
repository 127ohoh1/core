package cli

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/127ohoh1/core/client/api"
	cid "github.com/127ohoh1/core/client/identity"
	"github.com/127ohoh1/core/client/origin"
	"github.com/127ohoh1/core/client/session"
	"github.com/127ohoh1/core/internal/observability"
)

// cmdExpose implements: 127ohoh1 expose URL [flags]
func cmdExpose(ctx context.Context, args []string, env Env) error {
	var g global
	var edgeAddr, caFile string
	var unsafeOrigin, rewriteHost, verbose, yes, simulate bool
	var name, plan string
	var wait time.Duration
	fs := newFlagSet("expose", env)
	g.register(fs, env)
	fs.StringVar(&edgeAddr, "edge", env.Getenv("OHOH_EDGE"), "edge tunnel address host:port (default: from the control plane)")
	fs.StringVar(&caFile, "ca", env.Getenv("OHOH_CA_FILE"), "extra CA certificate (PEM) to trust; for development deployments")
	fs.BoolVar(&unsafeOrigin, "unsafe-allow-non-loopback-origin", false, "allow proxying to a non-loopback origin host")
	fs.BoolVar(&rewriteHost, "rewrite-host", false, "send the origin's own Host header instead of the public one")
	fs.BoolVar(&verbose, "verbose", false, "log connection events to stderr")
	fs.StringVar(&name, "name", "", "reserve this hostname (paid; requires --plan, default tier_1)")
	fs.StringVar(&plan, "plan", "", "plan for a reserved name: tier_1, tier_2 or tier_3")
	fs.BoolVar(&yes, "yes", false, "accept the offered payment without prompting (never implicit otherwise)")
	fs.BoolVar(&simulate, "simulate-settlement", false, "settle the payment against a development server (SIMULATED; no real money)")
	fs.DurationVar(&wait, "wait", 5*time.Minute, "how long to wait for payment settlement")
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return fail(ExitUsage, "%v", err)
	}
	if len(pos) != 1 {
		return fail(ExitUsage, "expose: expected exactly one origin URL, e.g. http://localhost:3000")
	}
	target, err := origin.ParseTarget(pos[0], unsafeOrigin)
	if err != nil {
		return fail(ExitUsage, "%v", err)
	}

	path, err := g.identityPath()
	if err != nil {
		return err
	}
	id, created, err := cid.LoadOrGenerate(path)
	if err != nil {
		return err
	}
	if created {
		fmt.Fprintf(env.Stdout, "Generating identity: %s\n", path)
	}
	c := api.New(strings.TrimRight(g.api, "/"), id, nil)

	if plan != "" && name == "" {
		return fail(ExitUsage, "--plan requires --name")
	}
	var ep api.Endpoint
	if name != "" {
		if plan == "" {
			plan = "tier_1"
		}
		if ep, err = reserveFlow(ctx, c, env, name, plan, yes, simulate, wait); err != nil {
			return err
		}
	} else if ep, err = pickEndpoint(ctx, c); err != nil {
		return err
	}
	plans, _ := c.Plans(ctx) // best effort: used only for the summary lines

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return err
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return fail(ExitUsage, "--ca: no certificates found in %s", caFile)
		}
		tlsCfg.RootCAs = pool
	}

	var log *slog.Logger
	if verbose {
		log = observability.NewLogger(env.Stderr, "info", "client")
	}
	h := origin.New(target, origin.Options{AllowNonLoopback: unsafeOrigin, RewriteHost: rewriteHost, Log: log})

	printed := false
	err = session.Run(ctx, session.RunOptions{
		Credential: func(ctx context.Context) (api.TunnelCredential, error) { return c.TunnelCredentials(ctx, ep.ID) },
		EdgeAddr:   edgeAddr, TLS: tlsCfg, Identity: id, Handler: h,
		Backoff: session.Backoff{Base: 500 * time.Millisecond, Max: 30 * time.Second},
		OnConnected: func(conn *session.Connection) {
			if printed {
				return
			}
			printed = true
			if g.json {
				_ = printJSON(env.Stdout, map[string]string{"url": ep.URL, "endpoint_id": ep.ID, "hostname": ep.Hostname, "plan": ep.Plan})
				return
			}
			fmt.Fprintf(env.Stdout, "Public URL: %s\nPlan: %s\n", ep.URL, planName(plans, ep.Plan))
			for _, p := range plans {
				if p.ID == ep.Plan {
					fmt.Fprintf(env.Stdout, "Bandwidth: %s\nMonthly transfer: %s\n", formatRate(p.BandwidthBytesPerSecond), formatBytes(p.MonthlyTransferBytes))
				}
			}
			fmt.Fprintf(env.Stdout, "Forwarding to: %s\n", target.String())
		},
		OnState: func(s session.State, info string) {
			if verbose || s == session.StateReconnecting {
				if info != "" {
					fmt.Fprintf(env.Stderr, "tunnel %s: %s\n", s, info)
				} else if verbose {
					fmt.Fprintf(env.Stderr, "tunnel %s\n", s)
				}
			}
		},
	})
	var fe *session.FatalError
	if errors.As(err, &fe) {
		return fail(classify(fe.Err), "%v", fe.Err)
	}
	return err
}

func planName(plans []api.Plan, id string) string {
	for _, p := range plans {
		if p.ID == id {
			return p.Name
		}
	}
	if id == "" {
		return "Free"
	}
	return id
}

// pickEndpoint reuses the caller's active random endpoint (stable name across
// restarts) or creates one. The idempotency key makes a retried create safe.
func pickEndpoint(ctx context.Context, c *api.Client) (api.Endpoint, error) {
	es, err := c.ListEndpoints(ctx)
	if err != nil {
		return api.Endpoint{}, err
	}
	for _, e := range es {
		if e.Kind == "random" && e.State == "ACTIVE" {
			return e, nil
		}
	}
	return c.CreateEndpoint(ctx, "expose-"+c.Identity.Fingerprint()[:16]+"-"+fmt.Sprint(time.Now().UnixNano()))
}
