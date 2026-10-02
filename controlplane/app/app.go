// Package app assembles the control plane from configuration. It is shared
// by cmd/control-plane and by integration tests so both exercise the same wiring.
package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/127ohoh1/core/controlplane/abuse"
	"github.com/127ohoh1/core/controlplane/api"
	"github.com/127ohoh1/core/controlplane/audit"
	"github.com/127ohoh1/core/controlplane/endpoint"
	"github.com/127ohoh1/core/controlplane/entitlement"
	"github.com/127ohoh1/core/controlplane/identity"
	"github.com/127ohoh1/core/controlplane/offer"
	"github.com/127ohoh1/core/controlplane/payment"
	"github.com/127ohoh1/core/controlplane/policy"
	"github.com/127ohoh1/core/controlplane/usage"
	"github.com/127ohoh1/core/internal/apperr"
	"github.com/127ohoh1/core/internal/clock"
	"github.com/127ohoh1/core/internal/config"
	"github.com/127ohoh1/core/internal/ids"
	"github.com/127ohoh1/core/internal/observability"
	"github.com/127ohoh1/core/protocol/auth"
)

// Options carries injectable dependencies.
type Options struct {
	Log   *slog.Logger
	Clock clock.Clock
	// SigningKey overrides key loading (tests).
	SigningKey ed25519.PrivateKey
	// Catalog overrides the canonical plans (reduced-scale test fixtures only).
	Catalog *policy.Catalog
}

// App is an assembled control plane.
type App struct {
	Cfg          config.ControlPlane
	Log          *slog.Logger
	Clock        clock.Clock
	Metrics      *observability.Registry
	API          *api.Server
	Identity     *identity.Service
	Endpoints    *endpoint.Service
	Audit        *audit.InMemory
	Catalog      *policy.Catalog
	Resolver     *policy.Resolver
	Publisher    *policy.Publisher
	Usage        *usage.Service
	Entitlements *entitlement.Service
	Offers       *offer.Service
	Abuse        *abuse.Service
	Payments     *payment.Service
	Signer       *auth.Signer
	Keys         auth.KeySet
}

// LoadSigningKey reads a base64 Ed25519 seed from path. If path is empty a
// key is generated, which is only permitted outside production; tokens then
// do not survive a restart.
func LoadSigningKey(cfg config.ControlPlane, log *slog.Logger) (ed25519.PrivateKey, error) {
	if cfg.SigningKeyFile == "" {
		if cfg.AppEnv == config.EnvProduction {
			return nil, fmt.Errorf("signing_key_file is required in production")
		}
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if log != nil {
			log.Warn("using ephemeral development signing key; issued credentials will not survive a restart", observability.FieldEvent, "signing_key.ephemeral")
		}
		return priv, err
	}
	b, err := os.ReadFile(cfg.SigningKeyFile)
	if err != nil {
		return nil, fmt.Errorf("read signing key: %w", err)
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("signing key file must contain a base64 %d-byte Ed25519 seed", ed25519.SeedSize)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// KeyID derives the key id under which tokens signed by pub are published.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "k-" + hex.EncodeToString(sum[:4])
}

// New validates cfg and assembles the control plane.
func New(cfg config.ControlPlane, o Options) (*App, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if o.Clock == nil {
		o.Clock = clock.Real{}
	}
	if o.Log == nil {
		o.Log = observability.NewLogger(os.Stderr, cfg.LogLevel, "control-plane")
	}
	if cfg.DevelopmentPayments {
		o.Log.Warn("DEVELOPMENT PAYMENTS ENABLED: simulated settlement is reachable; never use in production", observability.FieldEvent, "dev.payments_enabled")
	}
	priv := o.SigningKey
	if priv == nil {
		var err error
		if priv, err = LoadSigningKey(cfg, o.Log); err != nil {
			return nil, err
		}
	}
	pub := priv.Public().(ed25519.PublicKey)
	kid := KeyID(pub)
	signer := auth.NewSigner(kid, priv)
	keys := auth.KeySet{kid: pub}
	// Rotation overlap: retired keys keep verifying (and are published to
	// edges) until an operator removes them after the credential TTLs elapsed.
	prev, err := config.ParseVerifyKeys(cfg.PreviousVerifyKeys)
	if err != nil {
		return nil, err
	}
	for _, pk := range prev {
		k, err := auth.ParsePublicKey(pk.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("previous_verify_keys[%s]: %w", pk.KID, err)
		}
		if pk.KID == kid {
			return nil, fmt.Errorf("previous_verify_keys[%s] duplicates the current signing key id", pk.KID)
		}
		keys[pk.KID] = k
	}

	metrics := observability.NewRegistry()
	metrics.RegisterRuntime()
	gen := ids.New(o.Clock)
	aud := audit.NewInMemory(o.Log, 10000)

	a := &App{Cfg: cfg, Log: o.Log, Clock: o.Clock, Metrics: metrics, Audit: aud, Signer: signer, Keys: keys}

	reaped := metrics.Counter("cp_free_endpoints_reaped_total", "Free endpoints released after the inactivity window.")
	idStore := identity.NewInMemory(0)
	a.Endpoints = endpoint.NewService(endpoint.Config{
		MaxRandomPerPrincipal: cfg.MaxEndpointsPerPrincipal, Tombstone: cfg.NameTombstone.D(), FreeInactivity: cfg.FreeInactivity.D(),
	}, endpoint.NewInMemory(), endpoint.NewRandomAllocator(nil), endpoint.DefaultNameValidator{}, o.Clock, gen)
	a.Endpoints.OnReap = func(n int) { reaped.Add(float64(n)) }

	var srv *api.Server
	a.Catalog = o.Catalog
	if a.Catalog == nil {
		a.Catalog = policy.DefaultCatalog()
	}
	a.Identity = identity.NewService(identity.Config{
		Audience: cfg.ControlAudience, SessionAud: cfg.ControlAudience,
		ChallengeTTL: cfg.ChallengeTTL.D(), SessionTTL: cfg.SessionTTL.D(),
		OnFailure: func(r string) { srv.AuthFailure(r) },
	}, idStore, idStore, signer, keys, o.Clock, gen)

	a.Usage = &usage.Service{Ledger: usage.NewInMemory(0), Clock: o.Clock}
	a.Usage.Known = func(ctx context.Context, id string) bool {
		e, err := a.Endpoints.GetByID(ctx, id)
		return err == nil && e.State != endpoint.StateReleased
	}
	a.Resolver = &policy.Resolver{Catalog: a.Catalog, Endpoints: a.Endpoints, Principals: a.Identity, Usage: a.Usage,
		Clock: o.Clock, TTL: cfg.PolicyTTL.D(), FreeInactive: cfg.FreeInactivity.D()}
	a.Publisher = policy.NewPublisher(a.Resolver, o.Clock)
	// Crossing the quota must reach every edge, not just the reporting one.
	a.Usage.Updated = func(ctx context.Context, id string) { a.Publisher.Recompute(ctx, id) }
	a.Abuse = abuse.NewService(o.Clock, gen, func(ctx context.Context, host string) (string, bool) {
		e, err := a.Endpoints.ByHostname(ctx, host)
		return e.ID, err == nil
	}, 10000)
	// Commercial chain (development implementations): offer -> payment ->
	// settlement -> entitlement -> policy. The edge only ever sees the policy.
	a.Entitlements = entitlement.NewService(o.Clock, gen)
	a.Resolver.Entitlements = a.Entitlements
	a.Offers = offer.NewService(offer.NewInMemory(), a.Catalog, a.Endpoints, o.Clock, gen, cfg.OfferTTL.D())
	a.Offers.Available = func(_ context.Context, principalID, name string) error {
		if a.Entitlements.HeldByOther(principalID, name, o.Clock.Now()) {
			return apperr.ErrConflict.WithDetails(map[string]any{"reason": "hostname_unavailable"})
		}
		return nil
	}
	a.Payments = payment.NewService(payment.NewInMemory(), a.Offers, entitlement.Granter{S: a.Entitlements}, o.Clock, gen, aud)
	a.Entitlements.OnChange = func(ctx context.Context, name string) { a.syncReserved(ctx, name) }
	a.Payments.OnGranted = func(ctx context.Context, name string) { a.syncReserved(ctx, name) }
	var verifier payment.PaymentVerifier
	if cfg.DevelopmentPayments {
		v, err := payment.NewMockVerifier(cfg.AppEnv) // refuses production
		if err != nil {
			return nil, err
		}
		verifier = v
	}

	// Any endpoint lifecycle change re-resolves and, if enforcement-relevant, publishes a new version.
	a.Endpoints.OnChange = func(ctx context.Context, id string) { a.Publisher.Recompute(ctx, id) }

	srv = api.New(api.Deps{Cfg: cfg, Clock: o.Clock, IDs: gen, Log: o.Log, Metrics: metrics,
		Identity: a.Identity, Endpoints: a.Endpoints, Signer: signer, Keys: keys, Audit: aud,
		Catalog: a.Catalog, Resolver: a.Resolver, Publisher: a.Publisher, Usage: a.Usage,
		Offers: a.Offers, Payments: a.Payments, Verifier: verifier, Entitlements: a.Entitlements, Abuse: a.Abuse})
	a.API = srv
	return a, nil
}

// syncReserved reconciles a reserved name's endpoint lifecycle with its
// entitlement: lapsed -> EXPIRED (policy becomes "expired"), renewed ->
// ACTIVE again, and always republishes policy.
func (a *App) syncReserved(ctx context.Context, name string) {
	e, err := a.Endpoints.ByHostname(ctx, name)
	if err != nil || e.Kind != endpoint.KindReserved {
		return
	}
	_, entitled, _ := a.Entitlements.ActivePlan(ctx, e.PrincipalID, name, a.Clock.Now())
	switch {
	case !entitled && e.State == endpoint.StateActive:
		_, _ = a.Endpoints.Expire(ctx, e.ID)
	case entitled && e.State == endpoint.StateExpired:
		_, _ = a.Endpoints.Reactivate(ctx, e.ID)
	}
	a.Publisher.Recompute(ctx, e.ID)
}

// Handler is the HTTP handler to serve.
func (a *App) Handler() http.Handler { return a.API.Handler() }

// Run executes background workers until ctx is done.
func (a *App) Run(ctx context.Context) {
	a.loop(ctx, "reaper", a.Cfg.ReaperInterval.D(), func(ctx context.Context) {
		a.Entitlements.Sweep(ctx, a.Clock.Now())
		a.Abuse.PurgeExpired()
		a.Payments.ExpireStale(ctx)
		if n, err := a.Endpoints.ReapExpiredReserved(ctx, a.Cfg.ExpiredReservedRelease.D()); err == nil && n > 0 {
			a.Log.Info("reaper.released_expired_reserved", observability.FieldEvent, "reaper.released_expired_reserved", "count", n)
		}
		if n, err := a.Endpoints.Reap(ctx); err != nil {
			a.Log.Error("reaper.error", observability.FieldEvent, "reaper.error", "err", err.Error())
		} else if n > 0 {
			a.Log.Info("reaper.released", observability.FieldEvent, "reaper.released", "count", n)
		}
	})
}

func (a *App) loop(ctx context.Context, name string, every time.Duration, fn func(context.Context)) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-a.Clock.After(every):
			fn(ctx)
		}
	}
}
