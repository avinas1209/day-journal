package http

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/avinas1209/day-journal/internal/core/domain"
	"github.com/avinas1209/day-journal/internal/core/port"
)

const (
	ctxTraceID   = "trace_id"
	ctxPrincipal = "principal"
	headerTrace  = "X-Request-Id"
)

// requestID assigns (or adopts) a correlation id for every request.
func requestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.GetHeader(headerTrace)
		// Only adopt a well-formed id: a client must not be able to inject
		// arbitrary text into every log line.
		if _, err := uuid.Parse(id); err != nil {
			id = uuid.NewString()
		}
		c.Set(ctxTraceID, id)
		c.Header(headerTrace, id)
		c.Next()
	}
}

func traceID(c *gin.Context) string {
	if v, ok := c.Get(ctxTraceID); ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// requestLogger emits one structured line per request. It never logs bodies
// or the Authorization header, so tokens and passwords stay out of logs.
func requestLogger(log *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()

		attrs := []any{
			"method", c.Request.Method,
			"path", c.FullPath(),
			"status", c.Writer.Status(),
			"duration_ms", time.Since(start).Milliseconds(),
			"ip", c.ClientIP(),
			"trace_id", traceID(c),
		}
		if p, ok := principalFrom(c); ok {
			attrs = append(attrs, "user_id", p.UserID)
		}
		if len(c.Errors) > 0 {
			log.Error("request failed", append(attrs, "error", c.Errors.String())...)
			return
		}
		log.Info("request", attrs...)
	}
}

// recovery turns a panic into a 500 instead of killing the process.
func recovery(log *slog.Logger) gin.HandlerFunc {
	return gin.CustomRecoveryWithWriter(nil, func(c *gin.Context, recovered any) {
		log.Error("panic recovered", "panic", recovered, "trace_id", traceID(c))
		c.AbortWithStatusJSON(http.StatusInternalServerError, errorResponse{
			Error: "internal server error", TraceID: traceID(c),
		})
	})
}

// limitBody caps request bodies so one client cannot exhaust memory.
func limitBody(max int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, max)
		c.Next()
	}
}

// securityHeaders applies to every response.
func securityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.Writer.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		c.Next()
	}
}

// noStore keeps responses carrying tokens or personal data out of every
// cache between the server and the client.
func noStore() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		c.Header("Pragma", "no-cache")
		c.Next()
	}
}

// authenticate requires a valid bearer access token and attaches the
// Principal. Everything past it can trust principalFrom.
func authenticate(auth port.AuthService) gin.HandlerFunc {
	return func(c *gin.Context) {
		token, ok := bearerToken(c.GetHeader("Authorization"))
		if !ok {
			unauthorized(c, "missing bearer token")
			return
		}
		p, err := auth.Authenticate(c.Request.Context(), token)
		if err != nil {
			if !errors.Is(err, domain.ErrUnauthenticated) {
				_ = c.Error(err)
			}
			unauthorized(c, "invalid or expired token")
			return
		}
		c.Set(ctxPrincipal, p)
		c.Next()
	}
}

func bearerToken(header string) (string, bool) {
	scheme, token, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	token = strings.TrimSpace(token)
	return token, token != ""
}

// unauthorized answers 401 with the RFC 6750 challenge header, which tells a
// client its token is the problem and a refresh is worth trying.
func unauthorized(c *gin.Context, msg string) {
	c.Header("WWW-Authenticate", `Bearer realm="day-journal", error="invalid_token"`)
	c.AbortWithStatusJSON(http.StatusUnauthorized, errorResponse{Error: msg, TraceID: traceID(c)})
}

func principalFrom(c *gin.Context) (port.Principal, bool) {
	v, ok := c.Get(ctxPrincipal)
	if !ok {
		return port.Principal{}, false
	}
	p, ok := v.(port.Principal)
	return p, ok
}

// authorID is the signed-in user; only called behind authenticate().
func authorID(c *gin.Context) uuid.UUID {
	p, _ := principalFrom(c)
	return p.UserID
}

func clientInfo(c *gin.Context) domain.ClientInfo {
	return domain.ClientInfo{IP: c.ClientIP(), UserAgent: c.Request.UserAgent()}
}
