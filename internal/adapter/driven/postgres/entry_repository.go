package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/avinas1209/day-journal/internal/core/domain"
	"github.com/avinas1209/day-journal/internal/core/port"
)

// EntryRepository implements port.EntryRepository.
type EntryRepository struct {
	pool *pgxpool.Pool
}

var _ port.EntryRepository = (*EntryRepository)(nil)

func NewEntryRepository(pool *pgxpool.Pool) *EntryRepository {
	return &EntryRepository{pool: pool}
}

const entryColumns = `id, author_id, occurred_at, title, body, mood, tags, created_at, updated_at`

func (r *EntryRepository) Create(ctx context.Context, e *domain.Entry) error {
	const q = `
		INSERT INTO entries (` + entryColumns + `)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`
	_, err := r.pool.Exec(ctx, q,
		e.ID, e.AuthorID, e.OccurredAt, e.Title, e.Body, string(e.Mood), tagsParam(e.Tags), e.CreatedAt, e.UpdatedAt)
	if err != nil {
		return fmt.Errorf("postgres: create entry: %w", err)
	}
	return nil
}

func (r *EntryRepository) Update(ctx context.Context, e *domain.Entry) error {
	const q = `
		UPDATE entries
		   SET title = $2, body = $3, mood = $4, tags = $5, occurred_at = $6, updated_at = $7
		 WHERE id = $1`
	tag, err := r.pool.Exec(ctx, q, e.ID, e.Title, e.Body, string(e.Mood), tagsParam(e.Tags), e.OccurredAt, e.UpdatedAt)
	if err != nil {
		return fmt.Errorf("postgres: update entry: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrEntryNotFound
	}
	return nil
}

func (r *EntryRepository) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, `DELETE FROM entries WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("postgres: delete entry: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrEntryNotFound
	}
	return nil
}

func (r *EntryRepository) FindByID(ctx context.Context, id uuid.UUID) (*domain.Entry, error) {
	const q = `SELECT ` + entryColumns + ` FROM entries WHERE id = $1`
	e, err := scanEntry(r.pool.QueryRow(ctx, q, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrEntryNotFound
	}
	return e, err
}

func (r *EntryRepository) List(ctx context.Context, q port.EntryQuery) ([]*domain.Entry, error) {
	where, args := buildFilter(q)
	sql := `SELECT ` + entryColumns + ` FROM entries ` + where +
		fmt.Sprintf(` ORDER BY occurred_at DESC, id DESC LIMIT $%d OFFSET $%d`, len(args)+1, len(args)+2)
	args = append(args, q.Limit, q.Offset)

	rows, err := r.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("postgres: list entries: %w", err)
	}
	defer rows.Close()

	out := make([]*domain.Entry, 0, q.Limit)
	for rows.Next() {
		e, err := scanEntry(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: list entries: %w", err)
	}
	return out, nil
}

func (r *EntryRepository) Count(ctx context.Context, q port.EntryQuery) (int, error) {
	where, args := buildFilter(q)
	var n int
	if err := r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM entries `+where, args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("postgres: count entries: %w", err)
	}
	return n, nil
}

// buildFilter turns the port-level query into a WHERE clause. Keeping this in
// the adapter is the point of the port: the core never writes SQL.
//
// The range is compared against the raw timestamp column rather than a cast
// such as occurred_at::date, so the (author_id, occurred_at) index is used.
func buildFilter(q port.EntryQuery) (string, []any) {
	clauses := []string{"author_id = $1"}
	args := []any{q.AuthorID}

	if q.From != nil {
		args = append(args, *q.From)
		clauses = append(clauses, fmt.Sprintf("occurred_at >= $%d", len(args)))
	}
	if q.To != nil {
		args = append(args, *q.To)
		clauses = append(clauses, fmt.Sprintf("occurred_at < $%d", len(args)))
	}
	if q.Mood != nil {
		args = append(args, string(*q.Mood))
		clauses = append(clauses, fmt.Sprintf("mood = $%d", len(args)))
	}
	if q.Tag != "" {
		args = append(args, q.Tag)
		clauses = append(clauses, fmt.Sprintf("$%d = ANY(tags)", len(args)))
	}
	if q.Search != "" {
		// ILIKE with a leading wildcard cannot use a btree index; the trigram
		// index in the migration covers it.
		args = append(args, "%"+q.Search+"%")
		clauses = append(clauses, fmt.Sprintf("(title ILIKE $%d OR body ILIKE $%d)", len(args), len(args)))
	}
	return "WHERE " + strings.Join(clauses, " AND "), args
}

// tagsParam turns a nil slice into an empty one. pgx encodes nil as SQL NULL,
// which the NOT NULL tags column rejects — the column DEFAULT only applies
// when the column is omitted, not when NULL is sent explicitly. Entries with
// no tags (every entry the iOS app writes) depend on this.
func tagsParam(tags []string) []string {
	if tags == nil {
		return []string{}
	}
	return tags
}

type scanner interface {
	Scan(dest ...any) error
}

func scanEntry(s scanner) (*domain.Entry, error) {
	var (
		e          domain.Entry
		mood       string
		occurredAt time.Time
		createdAt  time.Time
		updatedAt  time.Time
	)
	if err := s.Scan(&e.ID, &e.AuthorID, &occurredAt, &e.Title, &e.Body, &mood, &e.Tags, &createdAt, &updatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
		return nil, fmt.Errorf("postgres: scan entry: %w", err)
	}
	e.Mood = domain.Mood(mood)
	e.OccurredAt = occurredAt.UTC()
	e.CreatedAt = createdAt.UTC()
	e.UpdatedAt = updatedAt.UTC()
	return &e, nil
}
