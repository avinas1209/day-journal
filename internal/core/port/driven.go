// Package port declares the boundaries of the hexagon.
//
// Driven (outbound, right-hand) ports are interfaces the core *needs*;
// infrastructure adapters implement them. Driving (inbound, left-hand) ports
// are interfaces the core *offers*; transport adapters call them.
package port

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/avinas1209/day-journal/internal/core/domain"
)

// EntryQuery describes a filtered listing. It lives in the core so neither SQL
// nor HTTP dictates what the application can ask for.
type EntryQuery struct {
	AuthorID uuid.UUID
	// From and To bound the listing as a half-open instant range: [From, To).
	// Instants rather than calendar days, because "a day" depends on the
	// caller's timezone and only the caller knows it.
	From   *time.Time
	To     *time.Time
	Mood   *domain.Mood
	Search string
	Tag    string
	Limit  int
	Offset int
}

// EntryRepository is the persistence port. Implemented by the Postgres adapter.
type EntryRepository interface {
	Create(ctx context.Context, e *domain.Entry) error
	Update(ctx context.Context, e *domain.Entry) error
	Delete(ctx context.Context, id uuid.UUID) error
	FindByID(ctx context.Context, id uuid.UUID) (*domain.Entry, error)
	List(ctx context.Context, q EntryQuery) ([]*domain.Entry, error)
	Count(ctx context.Context, q EntryQuery) (int, error)
}

// EntryCache is the read-through cache port. Implemented by the Redis adapter.
// A cache is an optimisation: every method may fail without failing the
// use case, so services log and continue rather than propagating errors.
type EntryCache interface {
	Get(ctx context.Context, id uuid.UUID) (*domain.Entry, error)
	Set(ctx context.Context, e *domain.Entry, ttl time.Duration) error
	Delete(ctx context.Context, id uuid.UUID) error
}

// ErrCacheMiss is returned by EntryCache.Get when the key is absent. It lives
// here, not in the Redis adapter, because the core branches on it.
var ErrCacheMiss = cacheMiss{}

type cacheMiss struct{}

func (cacheMiss) Error() string { return "cache miss" }

// EventPublisher is the messaging port. Currently satisfied by a no-op
// adapter; the NATS implementation is parked until messaging is switched on.
type EventPublisher interface {
	Publish(ctx context.Context, evt domain.Event) error
}

// Clock is injected so time-dependent rules stay testable.
type Clock interface {
	Now() time.Time
}

// SystemClock is the production Clock.
type SystemClock struct{}

func (SystemClock) Now() time.Time { return time.Now().UTC() }
