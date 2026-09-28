// Package config loads settings from the environment. It is the only place
// that reads os.Getenv, so every other package receives plain values.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	App      App
	HTTP     HTTP
	Postgres Postgres
	Redis    Redis
	NATS     NATS
	Auth     Auth
}

type App struct {
	Name     string
	Env      string
	LogLevel string
	Debug    bool
}

type HTTP struct {
	Addr string
	// TrustedProxies are the load balancers allowed to set X-Forwarded-For.
	// Empty means the connecting address is the client, which is right when
	// the API is exposed directly and stops clients spoofing their IP in the
	// audit log.
	TrustedProxies  []string
	MaxBodyBytes    int64
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	IdleTimeout     time.Duration
	ShutdownTimeout time.Duration
}

type Postgres struct {
	DSN             string
	MaxConns        int32
	MinConns        int32
	MaxConnLifetime time.Duration
	ConnectTimeout  time.Duration
}

type Redis struct {
	Addr           string
	Password       string
	DB             int
	KeyPrefix      string
	CacheTTL       time.Duration
	ConnectTimeout time.Duration
}

type Auth struct {
	JWTSecret          string
	JWTPreviousSecrets []string
	JWTIssuer          string
	JWTAudience        string
	AccessTokenTTL     time.Duration
	RefreshTokenTTL    time.Duration
	BcryptCost         int
	// GoogleClientIDs are the OAuth client ids whose ID tokens are accepted.
	// Empty disables Google sign-in.
	GoogleClientIDs []string
}

// devJWTSecret lets the API boot with zero configuration on a laptop. It is
// public, so validate() refuses it anywhere but development.
const devJWTSecret = "dev-only-insecure-jwt-secret-change-me-0123456789"

type NATS struct {
	URL            string
	StreamName     string
	SubjectPrefix  string
	ConnectTimeout time.Duration
}

// Load reads the environment and applies defaults suited to local development.
func Load() (Config, error) {
	cfg := Config{
		App: App{
			Name:     env("APP_NAME", "day-journal"),
			Env:      env("APP_ENV", "development"),
			LogLevel: env("LOG_LEVEL", "info"),
			Debug:    envBool("APP_DEBUG", true),
		},
		HTTP: HTTP{
			Addr:            env("HTTP_ADDR", ":8080"),
			TrustedProxies:  envList("HTTP_TRUSTED_PROXIES"),
			MaxBodyBytes:    int64(envInt("HTTP_MAX_BODY_BYTES", 1<<20)),
			ReadTimeout:     envDuration("HTTP_READ_TIMEOUT", 10*time.Second),
			WriteTimeout:    envDuration("HTTP_WRITE_TIMEOUT", 15*time.Second),
			IdleTimeout:     envDuration("HTTP_IDLE_TIMEOUT", 60*time.Second),
			ShutdownTimeout: envDuration("HTTP_SHUTDOWN_TIMEOUT", 15*time.Second),
		},
		Postgres: Postgres{
			DSN:             env("POSTGRES_DSN", "postgres://postgres:root@localhost:5432/day-journal?sslmode=disable"),
			MaxConns:        int32(envInt("POSTGRES_MAX_CONNS", 10)),
			MinConns:        int32(envInt("POSTGRES_MIN_CONNS", 2)),
			MaxConnLifetime: envDuration("POSTGRES_CONN_LIFETIME", time.Hour),
			ConnectTimeout:  envDuration("POSTGRES_CONNECT_TIMEOUT", 10*time.Second),
		},
		Redis: Redis{
			Addr:           env("REDIS_ADDR", "localhost:6379"),
			Password:       env("REDIS_PASSWORD", ""),
			DB:             envInt("REDIS_DB", 0),
			KeyPrefix:      env("REDIS_PREFIX", "day-journal"),
			CacheTTL:       envDuration("REDIS_CACHE_TTL", 10*time.Minute),
			ConnectTimeout: envDuration("REDIS_CONNECT_TIMEOUT", 5*time.Second),
		},
		Auth: Auth{
			JWTSecret:          env("JWT_SECRET", devJWTSecret),
			JWTPreviousSecrets: envList("JWT_PREVIOUS_SECRETS"),
			JWTIssuer:          env("JWT_ISSUER", "day-journal"),
			JWTAudience:        env("JWT_AUDIENCE", "day-journal-api"),
			AccessTokenTTL:     envDuration("ACCESS_TOKEN_TTL", 15*time.Minute),
			RefreshTokenTTL:    envDuration("REFRESH_TOKEN_TTL", 30*24*time.Hour),
			BcryptCost:         envInt("BCRYPT_COST", 12),
			GoogleClientIDs:    envList("GOOGLE_CLIENT_IDS"),
		},
		NATS: NATS{
			URL:            env("NATS_URL", "nats://localhost:4222"),
			StreamName:     env("NATS_STREAM", "DAY_JOURNAL"),
			SubjectPrefix:  env("NATS_SUBJECT_PREFIX", "day-journal"),
			ConnectTimeout: envDuration("NATS_CONNECT_TIMEOUT", 5*time.Second),
		},
	}
	return cfg, cfg.validate()
}

func (c Config) validate() error {
	if c.Postgres.DSN == "" {
		return fmt.Errorf("config: POSTGRES_DSN is required")
	}
	if c.Redis.Addr == "" {
		return fmt.Errorf("config: REDIS_ADDR is required")
	}
	if c.NATS.URL == "" {
		return fmt.Errorf("config: NATS_URL is required")
	}
	if c.Postgres.MaxConns < c.Postgres.MinConns {
		return fmt.Errorf("config: POSTGRES_MAX_CONNS must be >= POSTGRES_MIN_CONNS")
	}
	if len(c.Auth.JWTSecret) < 32 {
		return fmt.Errorf("config: JWT_SECRET must be at least 32 bytes")
	}
	if c.App.Env != "development" && c.Auth.JWTSecret == devJWTSecret {
		return fmt.Errorf("config: JWT_SECRET must be set outside development (APP_ENV=%s)", c.App.Env)
	}
	if c.Auth.AccessTokenTTL <= 0 || c.Auth.RefreshTokenTTL <= c.Auth.AccessTokenTTL {
		return fmt.Errorf("config: REFRESH_TOKEN_TTL must exceed ACCESS_TOKEN_TTL, both positive")
	}
	return nil
}

// UsesDevSecret reports whether the public development JWT secret is active,
// so main can warn about it loudly.
func (c Config) UsesDevSecret() bool { return c.Auth.JWTSecret == devJWTSecret }

func env(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}

// envList reads a comma-separated list, dropping blanks.
func envList(key string) []string {
	raw, ok := os.LookupEnv(key)
	if !ok {
		return nil
	}
	var out []string
	for _, part := range strings.Split(raw, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func envInt(key string, fallback int) int {
	if v, ok := os.LookupEnv(key); ok {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

func envBool(key string, fallback bool) bool {
	if v, ok := os.LookupEnv(key); ok {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return fallback
}

func envDuration(key string, fallback time.Duration) time.Duration {
	if v, ok := os.LookupEnv(key); ok {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return fallback
}
