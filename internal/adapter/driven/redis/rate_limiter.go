package redis

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/avinas1209/day-journal/internal/core/port"
)

// RateLimiter implements port.RateLimiter as a fixed-window counter shared by
// every API instance, so limits hold however many replicas are running.
type RateLimiter struct {
	client *redis.Client
	prefix string
}

var _ port.RateLimiter = (*RateLimiter)(nil)

func NewRateLimiter(client *redis.Client, prefix string) *RateLimiter {
	return &RateLimiter{client: client, prefix: prefix + ":ratelimit:"}
}

func (l *RateLimiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error) {
	k := l.prefix + key

	// INCR and EXPIRE NX in one round trip. NX sets the TTL only when the
	// window opens, so steady traffic cannot keep extending it forever.
	pipe := l.client.TxPipeline()
	incr := pipe.Incr(ctx, k)
	pipe.ExpireNX(ctx, k, window)
	if _, err := pipe.Exec(ctx); err != nil {
		return false, fmt.Errorf("redis: rate limit: %w", err)
	}
	return incr.Val() <= int64(limit), nil
}
