// Package http is the driving adapter: it translates HTTP/JSON into calls on
// the port.EntryService and back. Domain types never leave this boundary.
package http

import (
	"time"

	"github.com/google/uuid"

	"github.com/avinas1209/day-journal/internal/core/domain"
	"github.com/avinas1209/day-journal/internal/core/port"
)

type createEntryRequest struct {
	OccurredAt time.Time `json:"occurred_at" binding:"required"`
	Title      string    `json:"title" binding:"required"`
	Body       string    `json:"body"`
	Mood       string    `json:"mood" binding:"required"`
	Tags       []string  `json:"tags"`
}

func (r createEntryRequest) toCommand(authorID uuid.UUID) port.CreateEntryCommand {
	return port.CreateEntryCommand{
		AuthorID:   authorID,
		OccurredAt: r.OccurredAt,
		Title:      r.Title,
		Body:       r.Body,
		Mood:       domain.Mood(r.Mood),
		Tags:       r.Tags,
	}
}

type updateEntryRequest struct {
	Title      *string    `json:"title"`
	Body       *string    `json:"body"`
	Mood       *string    `json:"mood"`
	OccurredAt *time.Time `json:"occurred_at"`
	Tags       []string   `json:"tags"`
}

func (r updateEntryRequest) toCommand(id, authorID uuid.UUID) port.UpdateEntryCommand {
	cmd := port.UpdateEntryCommand{
		ID:         id,
		AuthorID:   authorID,
		Title:      r.Title,
		Body:       r.Body,
		OccurredAt: r.OccurredAt,
		Tags:       r.Tags,
	}
	if r.Mood != nil {
		m := domain.Mood(*r.Mood)
		cmd.Mood = &m
	}
	return cmd
}

type entryResponse struct {
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

func toEntryResponse(e *domain.Entry) entryResponse {
	tags := e.Tags
	if tags == nil {
		tags = []string{}
	}
	return entryResponse{
		ID:         e.ID,
		AuthorID:   e.AuthorID,
		OccurredAt: e.OccurredAt,
		Title:      e.Title,
		Body:       e.Body,
		Mood:       string(e.Mood),
		Tags:       tags,
		CreatedAt:  e.CreatedAt,
		UpdatedAt:  e.UpdatedAt,
	}
}

type pageResponse struct {
	Entries []entryResponse `json:"entries"`
	Total   int             `json:"total"`
	Limit   int             `json:"limit"`
	Offset  int             `json:"offset"`
}

func toPageResponse(p port.Page) pageResponse {
	entries := make([]entryResponse, 0, len(p.Entries))
	for _, e := range p.Entries {
		entries = append(entries, toEntryResponse(e))
	}
	return pageResponse{Entries: entries, Total: p.Total, Limit: p.Limit, Offset: p.Offset}
}
