// Command app is the composition root. It is the only place that knows about
// every adapter at once: it constructs the concrete Postgres, Redis, JWT,
// bcrypt and Google adapters, injects them into the core through their
// ports, and hands the core to the Gin driving adapter.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	nethttp "net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/avinas1209/day-journal/internal/adapter/driven/crypto"
	"github.com/avinas1209/day-journal/internal/adapter/driven/google"
	"github.com/avinas1209/day-journal/internal/adapter/driven/jwt"
	"github.com/avinas1209/day-journal/internal/adapter/driven/postgres"
	redisadapter "github.com/avinas1209/day-journal/internal/adapter/driven/redis"
	httpadapter "github.com/avinas1209/day-journal/internal/adapter/driving/http"
	"github.com/avinas1209/day-journal/internal/config"
	"github.com/avinas1209/day-journal/internal/core/port"
	"github.com/avinas1209/day-journal/internal/core/service"
	"github.com/avinas1209/day-journal/internal/platform/logger"
	"github.com/avinas1209/day-journal/migrations"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	log := logger.New(cfg.App.Name, cfg.App.LogLevel, cfg.App.Debug)
	if cfg.UsesDevSecret() {
		log.Warn("using the public development JWT secret — set JWT_SECRET before deploying")
	}

	// Cancelled on SIGINT/SIGTERM; drives graceful shutdown.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// --- driven adapters (infrastructure) ---
	pool, err := postgres.NewPool(ctx, postgres.Config{
		DSN:             cfg.Postgres.DSN,
		MaxConns:        cfg.Postgres.MaxConns,
		MinConns:        cfg.Postgres.MinConns,
		MaxConnLifetime: cfg.Postgres.MaxConnLifetime,
		ConnectTimeout:  cfg.Postgres.ConnectTimeout,
	})
	if err != nil {
		return err
	}
	defer pool.Close()
	log.Info("connected to postgres")

	// Every replica runs this; an advisory lock serialises them.
	if err := postgres.Migrate(ctx, pool, migrations.FS, log); err != nil {
		return err
	}

	redisClient, err := redisadapter.NewClient(ctx, redisadapter.Config{
		Addr:           cfg.Redis.Addr,
		Password:       cfg.Redis.Password,
		DB:             cfg.Redis.DB,
		ConnectTimeout: cfg.Redis.ConnectTimeout,
	})
	if err != nil {
		return err
	}
	defer redisClient.Close()
	log.Info("connected to redis")

	// NATS is parked until messaging is switched on. To restore it:
	// uncomment internal/adapter/driven/nats/publisher.go, restore the block
	// below, and pass nats.NewEventPublisher(js, ...) to the entry service
	// instead of service.NewNopPublisher. Nothing in the core changes.
	//
	// natsConn, js, err := nats.Connect(ctx, nats.Config{
	// 	URL:            cfg.NATS.URL,
	// 	StreamName:     cfg.NATS.StreamName,
	// 	SubjectPrefix:  cfg.NATS.SubjectPrefix,
	// 	ConnectTimeout: cfg.NATS.ConnectTimeout,
	// })
	// if err != nil {
	// 	return err
	// }
	// defer natsConn.Close()
	// log.Info("connected to nats", "stream", cfg.NATS.StreamName)

	tokens, err := jwt.NewIssuer(jwt.Config{
		Secret:          cfg.Auth.JWTSecret,
		PreviousSecrets: cfg.Auth.JWTPreviousSecrets,
		Issuer:          cfg.Auth.JWTIssuer,
		Audience:        cfg.Auth.JWTAudience,
		TTL:             cfg.Auth.AccessTokenTTL,
	})
	if err != nil {
		return err
	}

	// Google sign-in is optional: with no client ids configured the endpoint
	// answers 501 and password sign-in keeps working.
	var googleVerifier port.GoogleVerifier
	if len(cfg.Auth.GoogleClientIDs) > 0 {
		v, err := google.NewVerifier(ctx, cfg.Auth.GoogleClientIDs)
		if err != nil {
			return err
		}
		googleVerifier = v
		log.Info("google sign-in enabled", "client_ids", len(cfg.Auth.GoogleClientIDs))
	} else {
		log.Warn("google sign-in disabled — set GOOGLE_CLIENT_IDS to enable it")
	}

	// --- core: ports satisfied by the adapters above ---
	authCfg := service.DefaultAuthConfig()
	authCfg.RefreshTTL = cfg.Auth.RefreshTokenTTL

	authService, err := service.NewAuthService(service.AuthDeps{
		Users:    postgres.NewUserRepository(pool),
		Sessions: postgres.NewSessionRepository(pool),
		Audit:    postgres.NewAuditLog(pool),
		Hasher:   crypto.NewBcryptHasher(cfg.Auth.BcryptCost),
		Tokens:   tokens,
		Google:   googleVerifier,
		Denylist: redisadapter.NewSessionDenylist(redisClient, cfg.Redis.KeyPrefix),
		Limiter:  redisadapter.NewRateLimiter(redisClient, cfg.Redis.KeyPrefix),
	}, authCfg, log)
	if err != nil {
		return err
	}

	entryService := service.NewEntryService(
		postgres.NewEntryRepository(pool),
		redisadapter.NewEntryCache(redisClient, cfg.Redis.KeyPrefix),
		service.NewNopPublisher(log),
		log,
	)

	// --- driving adapter ---
	router, err := httpadapter.NewRouter(httpadapter.RouterConfig{
		Entries:     httpadapter.NewEntryHandler(entryService),
		Auth:        httpadapter.NewAuthHandler(authService),
		AuthService: authService,
		Health: httpadapter.NewHealthHandler(
			httpadapter.Checker{Name: "postgres", Probe: pool.Ping},
			httpadapter.Checker{Name: "redis", Probe: func(ctx context.Context) error {
				return redisClient.Ping(ctx).Err()
			}},
		),
		Logger:         log,
		Debug:          cfg.App.Debug,
		TrustedProxies: cfg.HTTP.TrustedProxies,
		MaxBodyBytes:   cfg.HTTP.MaxBodyBytes,
	})
	if err != nil {
		return fmt.Errorf("http router: %w", err)
	}

	srv := &nethttp.Server{
		Addr:              cfg.HTTP.Addr,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second, // slowloris guard
		ReadTimeout:       cfg.HTTP.ReadTimeout,
		WriteTimeout:      cfg.HTTP.WriteTimeout,
		IdleTimeout:       cfg.HTTP.IdleTimeout,
	}

	serverErr := make(chan error, 1)
	go func() {
		log.Info("http server listening", "addr", cfg.HTTP.Addr, "env", cfg.App.Env)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, nethttp.ErrServerClosed) {
			serverErr <- err
		}
	}()

	select {
	case err := <-serverErr:
		return fmt.Errorf("http server: %w", err)
	case <-ctx.Done():
		log.Info("shutdown signal received")
	}

	return shutdown(srv, log, cfg.HTTP.ShutdownTimeout)
}

func shutdown(srv *nethttp.Server, log *slog.Logger, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		return fmt.Errorf("http shutdown: %w", err)
	}
	log.Info("shutdown complete")
	return nil
}
