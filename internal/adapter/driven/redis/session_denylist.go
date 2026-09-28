package redis

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/avinas1209/day-journal/internal/core/port"
)

// SessionDenylist implements port.SessionDenylist. Each logged-out session is
// one small key that expires with the last access token issued for it, so
// the set never grows beyond the sessions ended in one token lifetime.
type SessionDenylist struct {
	client *redis.Client
	prefix string
}

var _ port.SessionDenylist = (*SessionDenylist)(nil)

func NewSessionDenylist(client *redis.Client, prefix string) *SessionDenylist {
	return &SessionDenylist{client: client, prefix: prefix + ":denied-session:"}
}

func (d *SessionDenylist) Deny(ctx context.Context, sessionID uuid.UUID, ttl time.Duration) error {
	if err := d.client.Set(ctx, d.prefix+sessionID.String(), 1, ttl).Err(); err != nil {
		return fmt.Errorf("redis: deny session: %w", err)
	}
	return nil
}

func (d *SessionDenylist) IsDenied(ctx context.Context, sessionID uuid.UUID) (bool, error) {
	n, err := d.client.Exists(ctx, d.prefix+sessionID.String()).Result()
	if err != nil {
		return false, fmt.Errorf("redis: check session: %w", err)
	}
	return n > 0, nil
}
