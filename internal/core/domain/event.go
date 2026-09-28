package domain

import (
	"time"

	"github.com/google/uuid"
)

// Event subjects. Driven adapters map these onto their own transport naming
// (a NATS subject, a Kafka topic) without the core caring which.
const (
	EventEntryCreated = "entry.created"
	EventEntryUpdated = "entry.updated"
	EventEntryDeleted = "entry.deleted"
)

// Event is the envelope the core hands to an EventPublisher port.
type Event struct {
	ID         uuid.UUID `json:"id"`
	Name       string    `json:"name"`
	EntryID    uuid.UUID `json:"entry_id"`
	AuthorID   uuid.UUID `json:"author_id"`
	Day        string    `json:"day"`
	OccurredAt time.Time `json:"occurred_at"`
}

func NewEntryEvent(name string, e *Entry) Event {
	return Event{
		ID:         uuid.New(),
		Name:       name,
		EntryID:    e.ID,
		AuthorID:   e.AuthorID,
		Day:        e.Day().String(),
		OccurredAt: time.Now().UTC(),
	}
}
