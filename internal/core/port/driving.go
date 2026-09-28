package port

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/avinas1209/day-journal/internal/core/domain"
)

// CreateEntryCommand is the input to the create use case.
type CreateEntryCommand struct {
	AuthorID   uuid.UUID
	OccurredAt time.Time
	Title      string
	Body       string
	Mood       domain.Mood
	Tags       []string
}

// UpdateEntryCommand carries a partial update; nil fields are left alone.
type UpdateEntryCommand struct {
	ID         uuid.UUID
	AuthorID   uuid.UUID
	Title      *string
	Body       *string
	Mood       *domain.Mood
	OccurredAt *time.Time
	Tags       []string
}

// Page is a slice of results plus the total matching count.
type Page struct {
	Entries []*domain.Entry
	Total   int
	Limit   int
	Offset  int
}

// EntryService is the driving port: the whole application API, as the HTTP
// adapter (or a CLI, or a worker) sees it.
type EntryService interface {
	Create(ctx context.Context, cmd CreateEntryCommand) (*domain.Entry, error)
	Update(ctx context.Context, cmd UpdateEntryCommand) (*domain.Entry, error)
	Delete(ctx context.Context, id, authorID uuid.UUID) error
	Get(ctx context.Context, id, authorID uuid.UUID) (*domain.Entry, error)
	List(ctx context.Context, q EntryQuery) (Page, error)
}
