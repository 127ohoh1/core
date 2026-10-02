package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/127ohoh1/core/client/api"
	cid "github.com/127ohoh1/core/client/identity"
)

// existingClient is like global.client but never generates an identity: a
// key that has never been used has nothing to manage or link.
func (g *global) existingClient() (*api.Client, error) {
	path, err := g.identityPath()
	if err != nil {
		return nil, err
	}
	id, err := cid.Load(path)
	if err != nil {
		if errors.Is(err, cid.ErrNotFound) {
			return nil, fail(ExitAuth, "no identity at %s (it is created on first `expose`)", path)
		}
		return nil, err
	}
	return api.New(strings.TrimRight(g.api, "/"), id, nil), nil
}

// cmdDashboard prints (and opens) a one-time link that signs in to the web
// dashboard as the account this key belongs to; the first use creates it.
func cmdDashboard(ctx context.Context, args []string, env Env) error {
	var g global
	fs := newFlagSet("dashboard", env)
	g.register(fs, env)
	noOpen := fs.Bool("no-open", false, "print the link without opening a browser")
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return fail(ExitUsage, "%v", err)
	}
	if len(pos) != 0 {
		return fail(ExitUsage, "dashboard: takes no arguments")
	}
	c, err := g.existingClient()
	if err != nil {
		return err
	}
	l, err := c.CreateDashboardLink(ctx)
	if err != nil {
		return err
	}
	if g.json {
		return printJSON(env.Stdout, l)
	}
	fmt.Fprintf(env.Stdout, "Dashboard sign-in link (works once, until %s):\n  %s\n", l.ExpiresAt.Local().Format("15:04"), l.URL)
	fmt.Fprintln(env.Stdout, "Anyone with this link can open your dashboard, so don't share it.")
	if env.Interactive && env.OpenURL != nil && !*noOpen {
		if err := env.OpenURL(l.URL); err != nil {
			fmt.Fprintln(env.Stdout, "Could not open a browser; open the link above yourself.")
		} else {
			fmt.Fprintln(env.Stdout, "Opened it in your browser.")
		}
	}
	return nil
}

// cmdLink prints a code that links this key to an account the user already
// has (for example one they signed in to by email, or with another key).
func cmdLink(ctx context.Context, args []string, env Env) error {
	var g global
	fs := newFlagSet("link", env)
	g.register(fs, env)
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return fail(ExitUsage, "%v", err)
	}
	if len(pos) != 0 {
		return fail(ExitUsage, "link: takes no arguments")
	}
	c, err := g.existingClient()
	if err != nil {
		return err
	}
	l, err := c.CreateLinkCode(ctx)
	if err != nil {
		if api.IsCode(err, "conflict") {
			return fail(ExitFailure, "this key is already linked to an account; run `127ohoh1 dashboard` to open it")
		}
		return err
	}
	if g.json {
		return printJSON(env.Stdout, l)
	}
	fmt.Fprintf(env.Stdout, "Link code: %s (valid until %s)\n", l.Code, l.ExpiresAt.Local().Format("15:04"))
	fmt.Fprintln(env.Stdout, "Enter it in the dashboard of the account you want, under Devices > Link a device.")
	return nil
}
