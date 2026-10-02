// Command edge runs the 127ohoh1 data plane: public ingress plus tunnel listener.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/127ohoh1/core/dataplane/app"
	"github.com/127ohoh1/core/internal/config"
	"github.com/127ohoh1/core/internal/observability"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "edge:", err)
		os.Exit(1)
	}
}

func run() error {
	cfgPath := flag.String("config", "", "path to JSON config file (optional)")
	flag.Parse()
	cfg := config.DefaultEdge()
	if err := config.Load(&cfg, *cfgPath, "OHOH_"); err != nil {
		return err
	}
	log := observability.NewLogger(os.Stderr, cfg.LogLevel, "edge")
	a, err := app.New(cfg, app.Options{Log: log})
	if err != nil {
		return err
	}
	if err := a.Start(); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	for done := false; !done; {
		select {
		case <-hup: // certificate rotation: reload without dropping tunnels
			if err := a.ReloadCertificates(); err != nil {
				log.Error("cert.reload_failed", observability.FieldEvent, "cert.reload_failed", "err", err.Error())
			}
		case <-ctx.Done():
			done = true
		}
	}
	sctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownGrace.D())
	defer cancel()
	return a.Shutdown(sctx)
}
