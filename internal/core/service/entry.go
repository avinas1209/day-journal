// Package service holds the use cases. It depends only on domain and port —
// never on Gin, pgx, go-redis or nats.go.
package service

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/avinas1209/day-journal/internal/core/domain"
	"github.com/avinas1209/day-journal/internal/core/port"
)

const (
	defaultCacheTTL = 10 * time.Minute
	defaultLimit    = 20
	maxLimit        = 100
)

// EntryService implements port.EntryService using the driven ports.
type EntryService struct {
	repo   port.EntryRepository
	cache  port.EntryCache
	events port.EventPublisher
	log    *slog.Logger
	ttl    time.Duration
}

// compile-time proof that the service satisfies its driving port.
var _ port.EntryService = (*EntryService)(nil)

func NewEntryService(
	repo port.EntryRepository,
	cache port.EntryCache,
	events port.EventPublisher,
	log *slog.Logger,
) *EntryService {
	return &EntryService{repo: repo, cache: cache, events: events, log: log, ttl: defaultCacheTTL}
}

func (s *EntryService) Create(ctx context.Context, cmd port.CreateEntryCommand) (*domain.Entry, error) {
	entry, err := domain.NewEntry(cmd.AuthorID, cmd.OccurredAt, cmd.Title, cmd.Body, cmd.Mood, cmd.Tags)
	if err != nil {
		return nil, err
	}
	if err := s.repo.Create(ctx, entry); err != nil {
		return nil, err
	}

	s.cacheEntry(ctx, entry)
	s.emit(ctx, domain.EventEntryCreated, entry)
	return entry, nil
}

func (s *EntryService) Update(ctx context.Context, cmd port.UpdateEntryCommand) (*domain.Entry, error) {
	entry, err := s.repo.FindByID(ctx, cmd.ID)
	if err != nil {
		return nil, err
	}
	if !entry.OwnedBy(cmd.AuthorID) {
		return nil, domain.ErrForbidden
	}
	if err := entry.Edit(cmd.Title, cmd.Body, cmd.Mood, cmd.OccurredAt, cmd.Tags); err != nil {
		return nil, err
	}
	if err := s.repo.Update(ctx, entry); err != nil {
		return nil, err
	}

	s.cacheEntry(ctx, entry)
	s.emit(ctx, domain.EventEntryUpdated, entry)
	return entry, nil
}

func (s *EntryService) Delete(ctx context.Context, id, authorID uuid.UUID) error {
	entry, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return err
	}
	if !entry.OwnedBy(authorID) {
		return domain.ErrForbidden
	}
	if err := s.repo.Delete(ctx, id); err != nil {
		return err
	}

	s.evict(ctx, id)
	s.emit(ctx, domain.EventEntryDeleted, entry)
	return nil
}

func (s *EntryService) Get(ctx context.Context, id, authorID uuid.UUID) (*domain.Entry, error) {
	if cached, err := s.cache.Get(ctx, id); err == nil {
		if !cached.OwnedBy(authorID) {
			return nil, domain.ErrForbidden
		}
		return cached, nil
	} else if !errors.Is(err, port.ErrCacheMiss) {
		s.log.WarnContext(ctx, "cache read failed", "entry_id", id, "error", err)
	}

	entry, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if !entry.OwnedBy(authorID) {
		return nil, domain.ErrForbidden
	}
	s.cacheEntry(ctx, entry)
	return entry, nil
}

func (s *EntryService) List(ctx context.Context, q port.EntryQuery) (port.Page, error) {
	if q.Limit <= 0 {
		q.Limit = defaultLimit
	}
	if q.Limit > maxLimit {
		q.Limit = maxLimit
	}
	if q.Offset < 0 {
		q.Offset = 0
	}
	if q.From != nil && q.To != nil && !q.From.Before(*q.To) {
		return port.Page{}, domain.ValidationError{Field: "from", Reason: "must be before to"}
	}

	entries, err := s.repo.List(ctx, q)
	if err != nil {
		return port.Page{}, err
	}
	total, err := s.repo.Count(ctx, q)
	if err != nil {
		return port.Page{}, err
	}
	return port.Page{Entries: entries, Total: total, Limit: q.Limit, Offset: q.Offset}, nil
}

// --- side effects that must never fail a use case ---

func (s *EntryService) cacheEntry(ctx context.Context, e *domain.Entry) {
	if err := s.cache.Set(ctx, e, s.ttl); err != nil {
		s.log.WarnContext(ctx, "cache write failed", "entry_id", e.ID, "error", err)
	}
}

func (s *EntryService) evict(ctx context.Context, id uuid.UUID) {
	if err := s.cache.Delete(ctx, id); err != nil {
		s.log.WarnContext(ctx, "cache evict failed", "entry_id", id, "error", err)
	}
}

func (s *EntryService) emit(ctx context.Context, name string, e *domain.Entry) {
	if err := s.events.Publish(ctx, domain.NewEntryEvent(name, e)); err != nil {
		s.log.ErrorContext(ctx, "event publish failed", "event", name, "entry_id", e.ID, "error", err)
	}
}
