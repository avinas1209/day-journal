package http

import (
	"log/slog"

	"github.com/gin-gonic/gin"

	"github.com/avinas1209/day-journal/internal/core/port"
)

// RouterConfig groups everything the transport needs, all of it supplied by
// main — the composition root.
type RouterConfig struct {
	Entries        *EntryHandler
	Auth           *AuthHandler
	Health         *HealthHandler
	AuthService    port.AuthService
	Logger         *slog.Logger
	Debug          bool
	TrustedProxies []string
	MaxBodyBytes   int64
}

// NewRouter builds the Gin engine and mounts the routes.
func NewRouter(cfg RouterConfig) (*gin.Engine, error) {
	if !cfg.Debug {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.New()
	// Without this Gin trusts X-Forwarded-For from anyone, letting a client
	// choose the IP recorded in the audit log and dodge per-IP rate limits.
	if err := r.SetTrustedProxies(cfg.TrustedProxies); err != nil {
		return nil, err
	}
	r.Use(requestID(), requestLogger(cfg.Logger), recovery(cfg.Logger),
		securityHeaders(), limitBody(cfg.MaxBodyBytes))

	r.GET("/healthz", cfg.Health.Live)
	r.GET("/readyz", cfg.Health.Ready)

	v1 := r.Group("/api/v1")

	// Public: these are how a client obtains a token in the first place.
	auth := v1.Group("/auth", noStore())
	{
		auth.POST("/register", cfg.Auth.Register)
		auth.POST("/login", cfg.Auth.Login)
		auth.POST("/google", cfg.Auth.Google)
		auth.POST("/refresh", cfg.Auth.Refresh)
	}

	// Everything below requires a valid, un-revoked access token.
	private := v1.Group("", authenticate(cfg.AuthService), noStore())
	{
		private.POST("/auth/logout", cfg.Auth.Logout)
		private.POST("/auth/logout-all", cfg.Auth.LogoutAll)

		private.GET("/me", cfg.Auth.Me)
		private.PATCH("/me", cfg.Auth.UpdateMe)
		private.DELETE("/me", cfg.Auth.DeleteMe)
		private.GET("/me/sessions", cfg.Auth.Sessions)
		private.GET("/me/audit-events", cfg.Auth.AuditEvents)

		entries := private.Group("/entries")
		entries.POST("", cfg.Entries.Create)
		entries.GET("", cfg.Entries.List)
		entries.GET("/:id", cfg.Entries.Get)
		entries.PATCH("/:id", cfg.Entries.Update)
		entries.DELETE("/:id", cfg.Entries.Delete)
	}
	return r, nil
}
