package http

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// Checker is one named dependency probe. main wires in Postgres, Redis and
// NATS without this package importing any of their drivers.
type Checker struct {
	Name  string
	Probe func(ctx context.Context) error
}

type HealthHandler struct {
	checks []Checker
}

func NewHealthHandler(checks ...Checker) *HealthHandler {
	return &HealthHandler{checks: checks}
}

// Live answers "is the process up" — no dependencies touched.
func (h *HealthHandler) Live(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// Ready answers "can it serve traffic" — every dependency is probed.
func (h *HealthHandler) Ready(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
	defer cancel()

	results := make(gin.H, len(h.checks))
	status := http.StatusOK
	for _, check := range h.checks {
		if err := check.Probe(ctx); err != nil {
			results[check.Name] = "down: " + err.Error()
			status = http.StatusServiceUnavailable
			continue
		}
		results[check.Name] = "ok"
	}
	c.JSON(status, gin.H{"status": statusText(status), "dependencies": results})
}

func statusText(code int) string {
	if code == http.StatusOK {
		return "ok"
	}
	return "degraded"
}
