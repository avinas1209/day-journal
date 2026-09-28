package service_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/avinas1209/day-journal/internal/core/domain"
	"github.com/avinas1209/day-journal/internal/core/port"
	"github.com/avinas1209/day-journal/internal/core/service"
)

type fixture struct {
	svc    *service.EntryService
	repo   *fakeRepo
	cache  *fakeCache
	events *fakePublisher
	author uuid.UUID
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	repo, cache, events := newFakeRepo(), newFakeCache(), newFakePublisher()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return &fixture{
		svc:    service.NewEntryService(repo, cache, events, log),
		repo:   repo,
		cache:  cache,
		events: events,
		author: uuid.New(),
	}
}

// hoursAgo keeps test timestamps safely in the past regardless of when the
// suite runs.
func hoursAgo(n int) time.Time { return time.Now().UTC().Add(-time.Duration(n) * time.Hour) }

func (f *fixture) create(t *testing.T, at time.Time) *domain.Entry {
	t.Helper()
	e, err := f.svc.Create(context.Background(), port.CreateEntryCommand{
		AuthorID:   f.author,
		OccurredAt: at,
		Title:      "A day",
		Body:       "Something happened.",
		Mood:       domain.MoodHappy,
		Tags:       []string{"work", "Work", " rest "},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	return e
}

func TestCreatePersistsCachesAndPublishes(t *testing.T) {
	f := newFixture(t)
	entry := f.create(t, hoursAgo(2))

	if _, err := f.repo.FindByID(context.Background(), entry.ID); err != nil {
		t.Fatalf("entry not persisted: %v", err)
	}
	if f.cache.sets != 1 {
		t.Errorf("cache sets = %d, want 1", f.cache.sets)
	}
	if got := f.events.names(); len(got) != 1 || got[0] != domain.EventEntryCreated {
		t.Errorf("published = %v, want [%s]", got, domain.EventEntryCreated)
	}
	if want := []string{"work", "rest"}; len(entry.Tags) != 2 || entry.Tags[0] != want[0] || entry.Tags[1] != want[1] {
		t.Errorf("tags = %v, want %v", entry.Tags, want)
	}
}

// The iOS client writes several entries a day, so this must not conflict.
func TestCreateAllowsSeveralEntriesOnTheSameDay(t *testing.T) {
	f := newFixture(t)
	first := f.create(t, hoursAgo(3))
	second := f.create(t, hoursAgo(1))

	if first.Day() != second.Day() {
		t.Fatalf("test setup: entries landed on different days")
	}
	page, err := f.svc.List(context.Background(), port.EntryQuery{AuthorID: f.author})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if page.Total != 2 {
		t.Errorf("total = %d, want 2 entries on one day", page.Total)
	}
}

func TestCreateAllowsEmptyBody(t *testing.T) {
	f := newFixture(t)
	entry, err := f.svc.Create(context.Background(), port.CreateEntryCommand{
		AuthorID: f.author, OccurredAt: hoursAgo(1), Title: "Title only", Mood: domain.MoodNeutral,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if entry.Body != "" {
		t.Errorf("body = %q, want empty", entry.Body)
	}
}

func TestCreateRejectsBlankTitle(t *testing.T) {
	f := newFixture(t)
	_, err := f.svc.Create(context.Background(), port.CreateEntryCommand{
		AuthorID: f.author, OccurredAt: hoursAgo(1), Title: "   ", Body: "x", Mood: domain.MoodNeutral,
	})
	var vErr domain.ValidationError
	if !errors.As(err, &vErr) || vErr.Field != "title" {
		t.Fatalf("err = %v, want a validation error on title", err)
	}
}

func TestCreateRejectsFutureTimestamp(t *testing.T) {
	f := newFixture(t)
	_, err := f.svc.Create(context.Background(), port.CreateEntryCommand{
		AuthorID: f.author, OccurredAt: time.Now().UTC().Add(time.Hour),
		Title: "Tomorrow", Body: "Not yet.", Mood: domain.MoodHappy,
	})
	if !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("err = %v, want a validation error", err)
	}
}

// A phone whose clock runs slightly fast must not have its entry rejected.
func TestCreateToleratesSmallClockSkew(t *testing.T) {
	f := newFixture(t)
	_, err := f.svc.Create(context.Background(), port.CreateEntryCommand{
		AuthorID: f.author, OccurredAt: time.Now().UTC().Add(20 * time.Second),
		Title: "Just now", Body: "Slightly fast clock.", Mood: domain.MoodHappy,
	})
	if err != nil {
		t.Fatalf("create: %v, want the skew tolerated", err)
	}
}

func TestCreateRejectsUnknownMood(t *testing.T) {
	f := newFixture(t)
	_, err := f.svc.Create(context.Background(), port.CreateEntryCommand{
		AuthorID: f.author, OccurredAt: hoursAgo(1), Title: "Hm", Body: "Body.", Mood: domain.Mood("ecstatic"),
	})
	var vErr domain.ValidationError
	if !errors.As(err, &vErr) || vErr.Field != "mood" {
		t.Fatalf("err = %v, want a validation error on mood", err)
	}
}

func TestGetServesFromCacheWithoutTouchingRepository(t *testing.T) {
	f := newFixture(t)
	entry := f.create(t, hoursAgo(2))

	f.repo.mu.Lock()
	delete(f.repo.entries, entry.ID)
	f.repo.mu.Unlock()

	got, err := f.svc.Get(context.Background(), entry.ID, f.author)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.ID != entry.ID {
		t.Errorf("id = %s, want %s", got.ID, entry.ID)
	}
}

func TestGetRefusesAnotherAuthorsEntry(t *testing.T) {
	f := newFixture(t)
	entry := f.create(t, hoursAgo(2))

	_, err := f.svc.Get(context.Background(), entry.ID, uuid.New())
	if !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("err = %v, want ErrForbidden", err)
	}
}

func TestUpdateAppliesPartialChange(t *testing.T) {
	f := newFixture(t)
	entry := f.create(t, hoursAgo(2))
	newBody := "Revised."

	updated, err := f.svc.Update(context.Background(), port.UpdateEntryCommand{
		ID: entry.ID, AuthorID: f.author, Body: &newBody,
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.Body != newBody {
		t.Errorf("body = %q, want %q", updated.Body, newBody)
	}
	if updated.Title != entry.Title {
		t.Errorf("title changed to %q, want it untouched", updated.Title)
	}
	if !updated.OccurredAt.Equal(entry.OccurredAt) {
		t.Errorf("occurred_at changed, want it untouched")
	}
	if got := f.events.names(); len(got) != 2 || got[1] != domain.EventEntryUpdated {
		t.Errorf("published = %v, want a trailing %s", got, domain.EventEntryUpdated)
	}
}

func TestUpdateCanMoveAnEntryInTime(t *testing.T) {
	f := newFixture(t)
	entry := f.create(t, hoursAgo(2))
	moved := hoursAgo(50)

	updated, err := f.svc.Update(context.Background(), port.UpdateEntryCommand{
		ID: entry.ID, AuthorID: f.author, OccurredAt: &moved,
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if !updated.OccurredAt.Equal(moved.UTC()) {
		t.Errorf("occurred_at = %s, want %s", updated.OccurredAt, moved.UTC())
	}
}

func TestUpdateRefusesAnotherAuthor(t *testing.T) {
	f := newFixture(t)
	entry := f.create(t, hoursAgo(2))
	title := "Hijacked"

	_, err := f.svc.Update(context.Background(), port.UpdateEntryCommand{
		ID: entry.ID, AuthorID: uuid.New(), Title: &title,
	})
	if !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("err = %v, want ErrForbidden", err)
	}
}

func TestDeleteEvictsCacheAndPublishes(t *testing.T) {
	f := newFixture(t)
	entry := f.create(t, hoursAgo(2))

	if err := f.svc.Delete(context.Background(), entry.ID, f.author); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if f.cache.deletes != 1 {
		t.Errorf("cache deletes = %d, want 1", f.cache.deletes)
	}
	if got := f.events.names(); len(got) != 2 || got[1] != domain.EventEntryDeleted {
		t.Errorf("published = %v, want a trailing %s", got, domain.EventEntryDeleted)
	}
	if _, err := f.svc.Get(context.Background(), entry.ID, f.author); !errors.Is(err, domain.ErrEntryNotFound) {
		t.Errorf("err = %v, want ErrEntryNotFound", err)
	}
}

func TestBrokenPublisherDoesNotFailTheUseCase(t *testing.T) {
	f := newFixture(t)
	f.events.err = errors.New("messaging down")

	entry := f.create(t, hoursAgo(2))
	if _, err := f.repo.FindByID(context.Background(), entry.ID); err != nil {
		t.Fatalf("entry not persisted despite publisher failure: %v", err)
	}
}

func TestListFiltersToASingleDay(t *testing.T) {
	f := newFixture(t)
	today := f.create(t, hoursAgo(1))
	f.create(t, hoursAgo(72))

	day := domain.DayFromTime(today.OccurredAt)
	start, end := day.Start(), day.End()
	page, err := f.svc.List(context.Background(), port.EntryQuery{AuthorID: f.author, From: &start, To: &end})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if page.Total != 1 || len(page.Entries) != 1 || page.Entries[0].ID != today.ID {
		t.Errorf("got %d entries, want only today's", page.Total)
	}
}

func TestListClampsPaging(t *testing.T) {
	f := newFixture(t)
	f.create(t, hoursAgo(2))

	page, err := f.svc.List(context.Background(), port.EntryQuery{AuthorID: f.author, Limit: 5000, Offset: -3})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if page.Limit != 100 {
		t.Errorf("limit = %d, want it clamped to 100", page.Limit)
	}
	if page.Offset != 0 {
		t.Errorf("offset = %d, want it clamped to 0", page.Offset)
	}
	if page.Total != 1 {
		t.Errorf("total = %d, want 1", page.Total)
	}
}

func TestListRejectsInvertedRange(t *testing.T) {
	f := newFixture(t)
	from := time.Date(2025, 3, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	_, err := f.svc.List(context.Background(), port.EntryQuery{AuthorID: f.author, From: &from, To: &to})
	if !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("err = %v, want a validation error", err)
	}
}

// A user east of UTC writing late at night must see the entry under their own
// day, not the UTC one. The client sends its local day as instants.
func TestListUsesCallerSuppliedInstantsNotUTCDays(t *testing.T) {
	f := newFixture(t)
	// 01:30 on 2 Jan in UTC+5:30 is still 20:00 on 1 Jan in UTC.
	ist := time.FixedZone("IST", 5*60*60+30*60)
	lateNight := time.Date(2025, 1, 2, 1, 30, 0, 0, ist)

	entry, err := f.svc.Create(context.Background(), port.CreateEntryCommand{
		AuthorID: f.author, OccurredAt: lateNight,
		Title: "Late night", Body: "Past midnight locally.", Mood: domain.MoodTired,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	localStart := time.Date(2025, 1, 2, 0, 0, 0, 0, ist)
	localEnd := localStart.AddDate(0, 0, 1)
	page, err := f.svc.List(context.Background(), port.EntryQuery{
		AuthorID: f.author, From: &localStart, To: &localEnd,
	})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if page.Total != 1 || page.Entries[0].ID != entry.ID {
		t.Errorf("got %d entries for the caller's local day, want the late-night one", page.Total)
	}
}
