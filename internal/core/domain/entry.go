package domain

import (
	"strings"
	"time"

	"github.com/google/uuid"
)

// Mood is a constrained vocabulary rather than free text so that aggregates
// (weekly mood trends) stay meaningful. The values mirror the iOS client's
// Mood enum one-for-one, so no lossy translation happens at the boundary.
type Mood string

const (
	MoodHappy   Mood = "happy"
	MoodNeutral Mood = "neutral"
	MoodSad     Mood = "sad"
	MoodAngry   Mood = "angry"
	MoodTired   Mood = "tired"
)

func (m Mood) Valid() bool {
	switch m {
	case MoodHappy, MoodNeutral, MoodSad, MoodAngry, MoodTired:
		return true
	}
	return false
}

const (
	maxTitleLen = 200
	maxBodyLen  = 20000
	maxTags     = 10

	// clockSkew is how far ahead of the server a client's timestamp may be
	// before it is rejected. Phones drift; a minute of slack avoids spurious
	// 400s without letting entries be dated into next week.
	clockSkew = time.Minute
)

// Entry is the aggregate root: one journal entry written by one author at one
// moment. Several entries may share a calendar day.
type Entry struct {
	ID         uuid.UUID
	AuthorID   uuid.UUID
	OccurredAt time.Time
	Title      string
	Body       string
	Mood       Mood
	Tags       []string
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// NewEntry builds a valid Entry or fails. Construction is the only way an
// Entry enters the system, so an Entry value is always well-formed.
func NewEntry(authorID uuid.UUID, occurredAt time.Time, title, body string, mood Mood, tags []string) (*Entry, error) {
	e := &Entry{
		ID:         uuid.New(),
		AuthorID:   authorID,
		OccurredAt: occurredAt.UTC(),
		Title:      strings.TrimSpace(title),
		Body:       strings.TrimSpace(body),
		Mood:       mood,
		Tags:       normalizeTags(tags),
	}
	if err := e.validate(); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	e.CreatedAt, e.UpdatedAt = now, now
	return e, nil
}

// Edit applies a partial update. Nil fields are left untouched.
func (e *Entry) Edit(title, body *string, mood *Mood, occurredAt *time.Time, tags []string) error {
	if title != nil {
		e.Title = strings.TrimSpace(*title)
	}
	if body != nil {
		e.Body = strings.TrimSpace(*body)
	}
	if mood != nil {
		e.Mood = *mood
	}
	if occurredAt != nil {
		e.OccurredAt = occurredAt.UTC()
	}
	if tags != nil {
		e.Tags = normalizeTags(tags)
	}
	if err := e.validate(); err != nil {
		return err
	}
	e.UpdatedAt = time.Now().UTC()
	return nil
}

// OwnedBy reports whether the entry may be read or changed by authorID.
func (e *Entry) OwnedBy(authorID uuid.UUID) bool { return e.AuthorID == authorID }

// Day is the calendar day the entry belongs to, used for grouping and filtering.
func (e *Entry) Day() Day { return DayFromTime(e.OccurredAt) }

func (e *Entry) validate() error {
	if e.AuthorID == uuid.Nil {
		return ValidationError{Field: "author_id", Reason: "must be set"}
	}
	if e.Title == "" {
		return ValidationError{Field: "title", Reason: "must not be empty"}
	}
	if len(e.Title) > maxTitleLen {
		return ValidationError{Field: "title", Reason: "is too long"}
	}
	// Body is optional: the client allows a title-only entry.
	if len(e.Body) > maxBodyLen {
		return ValidationError{Field: "body", Reason: "is too long"}
	}
	if !e.Mood.Valid() {
		return ValidationError{Field: "mood", Reason: "is not a recognised mood"}
	}
	if len(e.Tags) > maxTags {
		return ValidationError{Field: "tags", Reason: "too many tags"}
	}
	if e.OccurredAt.IsZero() {
		return ValidationError{Field: "occurred_at", Reason: "must be set"}
	}
	if e.OccurredAt.After(time.Now().UTC().Add(clockSkew)) {
		return ValidationError{Field: "occurred_at", Reason: "must not be in the future"}
	}
	return nil
}

// normalizeTags lowercases, trims, and de-duplicates while keeping order.
func normalizeTags(tags []string) []string {
	if len(tags) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(tags))
	out := make([]string, 0, len(tags))
	for _, t := range tags {
		t = strings.ToLower(strings.TrimSpace(t))
		if t == "" {
			continue
		}
		if _, dup := seen[t]; dup {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
