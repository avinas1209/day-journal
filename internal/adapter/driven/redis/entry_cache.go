package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/avinas1209/day-journal/internal/core/domain"
	"github.com/avinas1209/day-journal/internal/core/port"
)

// EntryCache implements port.EntryCache.
type EntryCache struct {
	client *redis.Client
	prefix string
}

var _ port.EntryCache = (*EntryCache)(nil)

func NewEntryCache(client *redis.Client, prefix string) *EntryCache {
	if prefix == "" {
		prefix = "day-journal"
	}
	return &EntryCache{client: client, prefix: prefix}
}

func (c *EntryCache) key(id uuid.UUID) string {
	return fmt.Sprintf("%s:entry:%s", c.prefix, id)
}

// cachedEntry is the wire shape. It is deliberately separate from domain.Entry
// so a domain change cannot silently break stored payloads.
type cachedEntry struct {
	ID         uuid.UUID `json:"id"`
	AuthorID   uuid.UUID `json:"author_id"`
	OccurredAt time.Time `json:"occurred_at"`
	Title      string    `json:"title"`
	Body       string    `json:"body"`
	Mood       string    `json:"mood"`
	Tags       []string  `json:"tags"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

func (c *EntryCache) Get(ctx context.Context, id uuid.UUID) (*domain.Entry, error) {
	raw, err := c.client.Get(ctx, c.key(id)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, port.ErrCacheMiss
	}
	if err != nil {
		return nil, fmt.Errorf("redis: get entry: %w", err)
	}

	var ce cachedEntry
	if err := json.Unmarshal(raw, &ce); err != nil {
		// A corrupt payload is treated as a miss so the caller falls back to
		// the repository instead of failing the request.
		return nil, port.ErrCacheMiss
	}
	return &domain.Entry{
		ID:         ce.ID,
		AuthorID:   ce.AuthorID,
		OccurredAt: ce.OccurredAt,
		Title:      ce.Title,
		Body:       ce.Body,
		Mood:       domain.Mood(ce.Mood),
		Tags:       ce.Tags,
		CreatedAt:  ce.CreatedAt,
		UpdatedAt:  ce.UpdatedAt,
	}, nil
}

func (c *EntryCache) Set(ctx context.Context, e *domain.Entry, ttl time.Duration) error {
	payload, err := json.Marshal(cachedEntry{
		ID:         e.ID,
		AuthorID:   e.AuthorID,
		OccurredAt: e.OccurredAt,
		Title:      e.Title,
		Body:       e.Body,
		Mood:       string(e.Mood),
		Tags:       e.Tags,
		CreatedAt:  e.CreatedAt,
		UpdatedAt:  e.UpdatedAt,
	})
	if err != nil {
		return fmt.Errorf("redis: encode entry: %w", err)
	}
	if err := c.client.Set(ctx, c.key(e.ID), payload, ttl).Err(); err != nil {
		return fmt.Errorf("redis: set entry: %w", err)
	}
	return nil
}

func (c *EntryCache) Delete(ctx context.Context, id uuid.UUID) error {
	if err := c.client.Del(ctx, c.key(id)).Err(); err != nil {
		return fmt.Errorf("redis: delete entry: %w", err)
	}
	return nil
}
