// Command control-plane runs the 127ohoh1 control-plane API.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/127ohoh1/core/controlplane/app"
	"github.com/127ohoh1/core/internal/config"
	"github.com/127ohoh1/core/internal/observability"
	"github.com/127ohoh1/core/protocol/auth"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "control-plane:", err)
		os.Exit(1) // fatal startup/config failure exits nonzero
	}
}

func run() error {
	cfgPath := flag.String("config", "", "path to JSON config file (optional)")
	keygen := flag.String("keygen", "", "generate a signing key seed into FILE (mode 0600, refuses to overwrite), print its kid and public key, and exit")
	pubkey := flag.String("pubkey", "", "print the kid and public key of the signing key in FILE (for previous_verify_keys during rotation) and exit")
	flag.Parse()
	if *keygen != "" || *pubkey != "" {
		return keyTool(*keygen, *pubkey)
	}

	cfg := config.DefaultControlPlane()
	if err := config.Load(&cfg, *cfgPath, "OHOH_"); err != nil {
		return err
	}
	log := observability.NewLogger(os.Stderr, cfg.LogLevel, "control-plane")
	a, err := app.New(cfg, app.Options{Log: log})
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	srv := &http.Server{Addr: cfg.ListenAddr, Handler: a.Handler(),
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 120 * time.Second}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); a.Run(ctx) }()

	// Metrics are served on their own listener so they can be firewalled
	// separately from the public API.
	var msrv *http.Server
	if cfg.MetricsAddr != "" {
		mux := http.NewServeMux()
		mux.Handle("GET /metrics", a.Metrics.Handler())
		msrv = &http.Server{Addr: cfg.MetricsAddr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
		go func() {
			if err := msrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("metrics.listen_failed", observability.FieldEvent, "metrics.listen_failed", "err", err.Error())
			}
		}()
	}

	errc := make(chan error, 1)
	go func() {
		log.Info("control-plane.listening", observability.FieldEvent, "listening", "addr", cfg.ListenAddr, "env", cfg.AppEnv)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- err
		}
	}()

	select {
	case err := <-errc:
		stop()
		wg.Wait()
		return err
	case <-ctx.Done():
	}
	log.Info("control-plane.shutdown", observability.FieldEvent, "shutdown")
	sctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownGrace.D())
	defer cancel()
	err = srv.Shutdown(sctx)
	if msrv != nil {
		_ = msrv.Shutdown(sctx)
	}
	wg.Wait()
	return err
}

// keyTool implements the key rotation helpers. The private seed is written to a
// file and never printed.
func keyTool(gen, show string) error {
	var seed []byte
	path := show
	if gen != "" {
		path = gen
		seed = make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(seed); err != nil {
			return err
		}
		f, err := os.OpenFile(gen, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		if _, err := f.WriteString(base64.StdEncoding.EncodeToString(seed) + "\n"); err != nil {
			f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
	}
	priv, err := app.LoadSigningKey(config.ControlPlane{AppEnv: config.EnvProduction, SigningKeyFile: path}, nil)
	if err != nil {
		return err
	}
	pub := priv.Public().(ed25519.PublicKey)
	fmt.Printf("kid=%s\npublic_key=%s\nprevious_verify_keys_entry=%s=%s\n", app.KeyID(pub), auth.EncodeKey(pub), app.KeyID(pub), auth.EncodeKey(pub))
	return nil
}
