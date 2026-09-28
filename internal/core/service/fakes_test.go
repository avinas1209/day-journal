package service_test

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/avinas1209/day-journal/internal/core/domain"
	"github.com/avinas1209/day-journal/internal/core/port"
)

// In-memory stand-ins for the driven ports. Their existence is the payoff of
// the hexagon: the use cases are exercised with no Postgres, Redis or NATS.

type fakeRepo struct {
	mu      sync.Mutex
	entries map[uuid.UUID]*domain.Entry
	failOn  string
	err     error
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{entries: map[uuid.UUID]*domain.Entry{}}
}

func (r *fakeRepo) fail(op string, err error) { r.failOn, r.err = op, err }

func (r *fakeRepo) check(op string) error {
	if r.failOn == op {
		return r.err
	}
	return nil
}

func (r *fakeRepo) Create(_ context.Context, e *domain.Entry) error {
	if err := r.check("Create"); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	clone := *e
	r.entries[e.ID] = &clone
	return nil
}

func (r *fakeRepo) Update(_ context.Context, e *domain.Entry) error {
	if err := r.check("Update"); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.entries[e.ID]; !ok {
		return domain.ErrEntryNotFound
	}
	clone := *e
	r.entries[e.ID] = &clone
	return nil
}

func (r *fakeRepo) Delete(_ context.Context, id uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.entries[id]; !ok {
		return domain.ErrEntryNotFound
	}
	delete(r.entries, id)
	return nil
}

func (r *fakeRepo) FindByID(_ context.Context, id uuid.UUID) (*domain.Entry, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.entries[id]
	if !ok {
		return nil, domain.ErrEntryNotFound
	}
	clone := *e
	return &clone, nil
}

func (r *fakeRepo) List(_ context.Context, q port.EntryQuery) ([]*domain.Entry, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []*domain.Entry
	for _, e := range r.entries {
		if e.AuthorID == q.AuthorID && matchesDay(e, q) {
			clone := *e
			out = append(out, &clone)
		}
	}
	return out, nil
}

func (r *fakeRepo) Count(ctx context.Context, q port.EntryQuery) (int, error) {
	out, err := r.List(ctx, q)
	return len(out), err
}

// matchesDay mirrors the repository's half-open [From, To) range filter.
func matchesDay(e *domain.Entry, q port.EntryQuery) bool {
	if q.From != nil && e.OccurredAt.Before(*q.From) {
		return false
	}
	if q.To != nil && !e.OccurredAt.Before(*q.To) {
		return false
	}
	return true
}

type fakeCache struct {
	mu      sync.Mutex
	items   map[uuid.UUID]*domain.Entry
	sets    int
	deletes int
}

func newFakeCache() *fakeCache { return &fakeCache{items: map[uuid.UUID]*domain.Entry{}} }

func (c *fakeCache) Get(_ context.Context, id uuid.UUID) (*domain.Entry, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.items[id]
	if !ok {
		return nil, port.ErrCacheMiss
	}
	clone := *e
	return &clone, nil
}

func (c *fakeCache) Set(_ context.Context, e *domain.Entry, _ time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	clone := *e
	c.items[e.ID] = &clone
	c.sets++
	return nil
}

func (c *fakeCache) Delete(_ context.Context, id uuid.UUID) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.items, id)
	c.deletes++
	return nil
}

type fakePublisher struct {
	mu        sync.Mutex
	published []domain.Event
	err       error
}

func newFakePublisher() *fakePublisher { return &fakePublisher{} }

func (p *fakePublisher) Publish(_ context.Context, evt domain.Event) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil {
		return p.err
	}
	p.published = append(p.published, evt)
	return nil
}

func (p *fakePublisher) names() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]string, 0, len(p.published))
	for _, e := range p.published {
		out = append(out, e.Name)
	}
	return out
}
