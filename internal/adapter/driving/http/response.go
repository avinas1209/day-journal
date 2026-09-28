package http

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/avinas1209/day-journal/internal/core/domain"
)

type errorResponse struct {
	Error   string `json:"error"`
	Field   string `json:"field,omitempty"`
	TraceID string `json:"trace_id,omitempty"`
}

// respondError is the single place where domain errors become HTTP status
// codes. The core stays free of net/http.
func respondError(c *gin.Context, err error) {
	var vErr domain.ValidationError
	switch {
	case errors.As(err, &vErr):
		c.AbortWithStatusJSON(http.StatusBadRequest, errorResponse{
			Error: vErr.Reason, Field: vErr.Field, TraceID: traceID(c),
		})
	case errors.Is(err, domain.ErrValidation):
		c.AbortWithStatusJSON(http.StatusBadRequest, errorResponse{Error: err.Error(), TraceID: traceID(c)})
	case errors.Is(err, domain.ErrEntryNotFound):
		c.AbortWithStatusJSON(http.StatusNotFound, errorResponse{Error: "entry not found", TraceID: traceID(c)})
	case errors.Is(err, domain.ErrReauthRequired):
		c.AbortWithStatusJSON(http.StatusBadRequest, errorResponse{Error: err.Error(), Field: "password", TraceID: traceID(c)})
	case errors.Is(err, domain.ErrReauthFailed):
		// 403, never 401: the token is fine, the password isn't. A 401 would
		// send the client off to refresh and, failing that, sign out.
		c.AbortWithStatusJSON(http.StatusForbidden, errorResponse{Error: err.Error(), Field: "password", TraceID: traceID(c)})
	case errors.Is(err, domain.ErrInvalidCredentials):
		c.AbortWithStatusJSON(http.StatusUnauthorized, errorResponse{Error: err.Error(), TraceID: traceID(c)})
	case errors.Is(err, domain.ErrUnauthenticated), errors.Is(err, domain.ErrSessionNotFound):
		unauthorized(c, "invalid or expired token")
	case errors.Is(err, domain.ErrGoogleTokenInvalid):
		c.AbortWithStatusJSON(http.StatusUnauthorized, errorResponse{Error: err.Error(), TraceID: traceID(c)})
	case errors.Is(err, domain.ErrGoogleEmailUnverified):
		c.AbortWithStatusJSON(http.StatusForbidden, errorResponse{Error: err.Error(), TraceID: traceID(c)})
	case errors.Is(err, domain.ErrGoogleNotConfigured):
		c.AbortWithStatusJSON(http.StatusNotImplemented, errorResponse{Error: err.Error(), TraceID: traceID(c)})
	case errors.Is(err, domain.ErrEmailTaken):
		c.AbortWithStatusJSON(http.StatusConflict, errorResponse{Error: err.Error(), Field: "email", TraceID: traceID(c)})
	case errors.Is(err, domain.ErrTooManyAttempts):
		// The window is 15 minutes; telling the client when to come back
		// saves it hammering the endpoint.
		c.Header("Retry-After", "900")
		c.AbortWithStatusJSON(http.StatusTooManyRequests, errorResponse{Error: err.Error(), TraceID: traceID(c)})
	case errors.Is(err, domain.ErrUserNotFound):
		c.AbortWithStatusJSON(http.StatusNotFound, errorResponse{Error: "user not found", TraceID: traceID(c)})
	case errors.Is(err, domain.ErrForbidden):
		// Deliberately reported as 404: confirming existence would leak that
		// another author has an entry with this id.
		c.AbortWithStatusJSON(http.StatusNotFound, errorResponse{Error: "entry not found", TraceID: traceID(c)})
	default:
		_ = c.Error(err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, errorResponse{
			Error: "internal server error", TraceID: traceID(c),
		})
	}
}
