// Package cli implements the 127ohoh1 command line. Output for humans goes to
// stdout; diagnostics go to stderr. Exit codes are stable (see Exit*).
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"github.com/127ohoh1/core/client/api"
	cid "github.com/127ohoh1/core/client/identity"
)

// Stable exit codes for scripting.
const (
	ExitOK      = 0
	ExitFailure = 1 // unexpected/internal error
	ExitUsage   = 2 // bad flags or arguments
	ExitAuth    = 3 // authentication/identity problem
	ExitPayment = 4 // payment required and not accepted
	ExitNetwork = 5 // could not reach the service
)

// Version is set at build time via -ldflags.
var Version = "0.1.0-dev"

// DefaultAPI is the control-plane URL when none is configured.
const DefaultAPI = "https://api.127ohoh1.com"

// Env abstracts process environment for testing.
type Env struct {
	Stdout, Stderr io.Writer
	Stdin          io.Reader
	Getenv         func(string) string
	// Interactive reports whether Stdin is a terminal a human can answer on.
	// Payment prompts are only shown when true; otherwise consent must be
	// given explicitly with --yes.
	Interactive bool
	// OpenURL shows an https page to the user (nil: never open anything).
	OpenURL func(url string) error
}

// OSEnv is the real process environment.
func OSEnv() Env {
	fi, err := os.Stdin.Stat()
	interactive := err == nil && fi.Mode()&os.ModeCharDevice != 0
	return Env{Stdout: os.Stdout, Stderr: os.Stderr, Stdin: os.Stdin, Getenv: os.Getenv, Interactive: interactive, OpenURL: openBrowser}
}

type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string { return e.err.Error() }
func (e *exitError) Unwrap() error { return e.err }

func fail(code int, format string, a ...any) error { return &exitError{code, fmt.Errorf(format, a...)} }

// global holds flags shared by all commands.
type global struct {
	api      string
	identity string
	json     bool
}

func (g *global) register(fs *flag.FlagSet, env Env) {
	def := env.Getenv("OHOH_API")
	if def == "" {
		def = DefaultAPI
	}
	fs.StringVar(&g.api, "api", def, "control-plane URL (env OHOH_API)")
	fs.StringVar(&g.identity, "identity", env.Getenv("OHOH_IDENTITY"), "identity file (default ~/.config/127ohoh1/id_ed25519)")
	fs.BoolVar(&g.json, "json", false, "machine-readable JSON output")
}

func (g *global) identityPath() (string, error) {
	if g.identity != "" {
		return g.identity, nil
	}
	return cid.DefaultPath()
}

// parseInterleaved parses flags that may appear before, between or after
// positional arguments (flag.Parse alone stops at the first positional).
func parseInterleaved(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return pos, nil
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

func newFlagSet(name string, env Env) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	return fs
}

const usage = `127ohoh1 - public HTTPS, private origin, zero inbound ports

Usage:
  127ohoh1 <command> [flags]

Commands:
  expose URL [--name NAME --plan PLAN]   expose a local HTTP origin at a public HTTPS URL
  plans list                             show plans and prices
  payments simulate PAYMENT_ID           settle a SIMULATED payment (development servers only)
  endpoints list|create|inspect|delete   manage endpoints
  dashboard [--no-open]                  sign in to the web dashboard with this key
  link                                   link this key to an account you already have
  identity show|import PATH              manage the local Ed25519 identity
  version                                print version

Common flags: --api URL  --identity FILE  --json
`

// Run executes the CLI and returns the process exit code.
func Run(ctx context.Context, args []string, env Env) int {
	err := dispatch(ctx, args, env)
	if err == nil {
		return ExitOK
	}
	var ee *exitError
	if errors.As(err, &ee) {
		if ee.code != ExitUsage || ee.err.Error() != "" {
			fmt.Fprintln(env.Stderr, "error:", ee.err)
		}
		return ee.code
	}
	if errors.Is(err, flag.ErrHelp) {
		return ExitOK
	}
	fmt.Fprintln(env.Stderr, "error:", err)
	return classify(err)
}

// classify maps unstructured errors to exit codes.
func classify(err error) int {
	var ae *api.Error
	if errors.As(err, &ae) {
		switch {
		case ae.Status == 401 || ae.Status == 403:
			return ExitAuth
		case ae.Status == 402:
			return ExitPayment
		}
		return ExitFailure
	}
	var ne net.Error
	var oe *net.OpError
	if errors.As(err, &ne) || errors.As(err, &oe) {
		return ExitNetwork
	}
	if errors.Is(err, cid.ErrPermissions) || errors.Is(err, cid.ErrFormat) {
		return ExitAuth
	}
	return ExitFailure
}

func dispatch(ctx context.Context, args []string, env Env) error {
	if len(args) == 0 {
		fmt.Fprint(env.Stderr, usage)
		return fail(ExitUsage, "")
	}
	switch args[0] {
	case "version", "--version":
		fmt.Fprintln(env.Stdout, "127ohoh1", Version)
		return nil
	case "help", "-h", "--help":
		fmt.Fprint(env.Stdout, usage)
		return nil
	case "expose":
		return cmdExpose(ctx, args[1:], env)
	case "plans":
		return cmdPlans(ctx, args[1:], env)
	case "payments":
		return cmdPayments(ctx, args[1:], env)
	case "identity":
		return cmdIdentity(ctx, args[1:], env)
	case "endpoints":
		return cmdEndpoints(ctx, args[1:], env)
	case "dashboard":
		return cmdDashboard(ctx, args[1:], env)
	case "link":
		return cmdLink(ctx, args[1:], env)
	}
	fmt.Fprint(env.Stderr, usage)
	return fail(ExitUsage, "unknown command %q", args[0])
}

func printJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// ---- identity --------------------------------------------------------------

func cmdIdentity(ctx context.Context, args []string, env Env) error {
	if len(args) == 0 {
		return fail(ExitUsage, "identity: expected show or import")
	}
	var g global
	fs := newFlagSet("identity "+args[0], env)
	g.register(fs, env)
	pos, err := parseInterleaved(fs, args[1:])
	if err != nil {
		return fail(ExitUsage, "%v", err)
	}
	path, err := g.identityPath()
	if err != nil {
		return err
	}
	switch args[0] {
	case "show":
		id, err := cid.Load(path)
		if err != nil {
			if errors.Is(err, cid.ErrNotFound) {
				return fail(ExitAuth, "no identity at %s (it is created on first `expose`)", path)
			}
			return err
		}
		out := map[string]string{"path": path, "public_key": id.PublicKeyString(), "fingerprint": id.Fingerprint()}
		if g.json {
			return printJSON(env.Stdout, out)
		}
		fmt.Fprintf(env.Stdout, "Identity:    %s\nFingerprint: %s\nPublic key:  %s\n", path, out["fingerprint"], out["public_key"])
		return nil
	case "import":
		if len(pos) != 1 {
			return fail(ExitUsage, "identity import: expected exactly one PATH")
		}
		id, err := cid.Import(pos[0], path)
		if err != nil {
			if errors.Is(err, cid.ErrExists) {
				return fail(ExitFailure, "an identity already exists at %s; refusing to overwrite", path)
			}
			return err
		}
		fmt.Fprintf(env.Stdout, "Imported identity %s\n", id.Fingerprint())
		return nil
	}
	return fail(ExitUsage, "identity: unknown subcommand %q", args[0])
}

// ---- endpoints -------------------------------------------------------------

func (g *global) client() (*api.Client, bool, error) {
	path, err := g.identityPath()
	if err != nil {
		return nil, false, err
	}
	id, created, err := cid.LoadOrGenerate(path)
	if err != nil {
		return nil, false, err
	}
	return api.New(strings.TrimRight(g.api, "/"), id, nil), created, nil
}

func printEndpoint(env Env, e api.Endpoint) {
	fmt.Fprintf(env.Stdout, "%s  %-9s %-6s %s\n", e.ID, e.State, e.Plan, e.URL)
}

func cmdEndpoints(ctx context.Context, args []string, env Env) error {
	if len(args) == 0 {
		return fail(ExitUsage, "endpoints: expected list, create, inspect or delete")
	}
	var g global
	fs := newFlagSet("endpoints "+args[0], env)
	g.register(fs, env)
	pos, err := parseInterleaved(fs, args[1:])
	if err != nil {
		return fail(ExitUsage, "%v", err)
	}
	c, created, err := g.client()
	if err != nil {
		return err
	}
	if created {
		p, _ := g.identityPath()
		fmt.Fprintf(env.Stderr, "Generated identity: %s\n", p)
	}
	switch args[0] {
	case "list":
		es, err := c.ListEndpoints(ctx)
		if err != nil {
			return err
		}
		if g.json {
			return printJSON(env.Stdout, es)
		}
		for _, e := range es {
			printEndpoint(env, e)
		}
		return nil
	case "create":
		e, err := c.CreateEndpoint(ctx, "")
		if err != nil {
			return err
		}
		if g.json {
			return printJSON(env.Stdout, e)
		}
		printEndpoint(env, e)
		return nil
	case "inspect", "delete":
		if len(pos) != 1 {
			return fail(ExitUsage, "endpoints %s: expected exactly one ID", args[0])
		}
		var e api.Endpoint
		if args[0] == "inspect" {
			e, err = c.GetEndpoint(ctx, pos[0])
		} else {
			e, err = c.DeleteEndpoint(ctx, pos[0])
		}
		if err != nil {
			return err
		}
		if g.json {
			return printJSON(env.Stdout, e)
		}
		printEndpoint(env, e)
		return nil
	}
	return fail(ExitUsage, "endpoints: unknown subcommand %q", args[0])
}
