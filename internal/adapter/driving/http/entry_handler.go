package http

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/avinas1209/day-journal/internal/core/domain"
	"github.com/avinas1209/day-journal/internal/core/port"
)

// EntryHandler holds the driving port, not a concrete service, so the
// transport can be tested against a fake application.
type EntryHandler struct {
	entries port.EntryService
}

func NewEntryHandler(entries port.EntryService) *EntryHandler {
	return &EntryHandler{entries: entries}
}

func (h *EntryHandler) Create(c *gin.Context) {
	var req createEntryRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, domain.ValidationError{Field: "body", Reason: err.Error()})
		return
	}
	entry, err := h.entries.Create(c.Request.Context(), req.toCommand(authorID(c)))
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusCreated, toEntryResponse(entry))
}

func (h *EntryHandler) Update(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		respondError(c, domain.ValidationError{Field: "id", Reason: "must be a uuid"})
		return
	}
	var req updateEntryRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, domain.ValidationError{Field: "body", Reason: err.Error()})
		return
	}
	entry, err := h.entries.Update(c.Request.Context(), req.toCommand(id, authorID(c)))
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, toEntryResponse(entry))
}

func (h *EntryHandler) Delete(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		respondError(c, domain.ValidationError{Field: "id", Reason: "must be a uuid"})
		return
	}
	if err := h.entries.Delete(c.Request.Context(), id, authorID(c)); err != nil {
		respondError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *EntryHandler) Get(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		respondError(c, domain.ValidationError{Field: "id", Reason: "must be a uuid"})
		return
	}
	entry, err := h.entries.Get(c.Request.Context(), id, authorID(c))
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, toEntryResponse(entry))
}

func (h *EntryHandler) List(c *gin.Context) {
	q, err := parseListQuery(c)
	if err != nil {
		respondError(c, err)
		return
	}
	page, err := h.entries.List(c.Request.Context(), q)
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, toPageResponse(page))
}

func parseListQuery(c *gin.Context) (port.EntryQuery, error) {
	q := port.EntryQuery{AuthorID: authorID(c), Tag: c.Query("tag"), Search: c.Query("search")}

	if s := c.Query("from"); s != "" {
		t, err := parseBound(s, boundStart)
		if err != nil {
			return q, domain.ValidationError{Field: "from", Reason: err.Error()}
		}
		q.From = &t
	}
	if s := c.Query("to"); s != "" {
		t, err := parseBound(s, boundEnd)
		if err != nil {
			return q, domain.ValidationError{Field: "to", Reason: err.Error()}
		}
		q.To = &t
	}
	if s := c.Query("mood"); s != "" {
		m := domain.Mood(s)
		if !m.Valid() {
			return q, domain.ValidationError{Field: "mood", Reason: "is not a recognised mood"}
		}
		q.Mood = &m
	}
	return q, parsePaging(c, &q)
}

type boundKind int

const (
	boundStart boundKind = iota
	boundEnd
)

// parseBound accepts either an RFC-3339 instant or a bare YYYY-MM-DD.
//
// Clients that know their user's timezone (the iOS app does) send instants, so
// "today" means the user's today rather than UTC's. A bare date is a
// convenience for humans and scripts and is read as a UTC calendar day.
//
// The resulting range is half-open — [from, to) — so an end bound given as a
// date covers that whole day.
func parseBound(raw string, kind boundKind) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t.UTC(), nil
	}
	day, err := domain.ParseDay(raw)
	if err != nil {
		return time.Time{}, errors.New("must be an RFC-3339 timestamp or a YYYY-MM-DD date")
	}
	if kind == boundEnd {
		return day.End(), nil
	}
	return day.Start(), nil
}

func parsePaging(c *gin.Context, q *port.EntryQuery) error {
	if s := c.Query("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil {
			return domain.ValidationError{Field: "limit", Reason: "must be a number"}
		}
		q.Limit = n
	}
	if s := c.Query("offset"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil {
			return domain.ValidationError{Field: "offset", Reason: "must be a number"}
		}
		q.Offset = n
	}
	return nil
}
