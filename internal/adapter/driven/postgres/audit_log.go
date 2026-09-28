package postgres

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/avinas1209/day-journal/internal/core/domain"
	"github.com/avinas1209/day-journal/internal/core/port"
)

// AuditLog implements port.AuditLog. It only ever inserts and reads: audit
// rows are never updated or deleted by the application.
type AuditLog struct {
	pool *pgxpool.Pool
}

var _ port.AuditLog = (*AuditLog)(nil)

func NewAuditLog(pool *pgxpool.Pool) *AuditLog {
	return &AuditLog{pool: pool}
}

func (a *AuditLog) Record(ctx context.Context, e domain.AuthEvent) error {
	const q = `INSERT INTO auth_events
		(id, event, user_id, session_id, method, email, ip, user_agent, detail, occurred_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`
	_, err := a.pool.Exec(ctx, q,
		e.ID, string(e.Type), e.UserID, e.SessionID, string(e.Method),
		e.Email, e.IP, truncateText(e.UserAgent, 512), e.Detail, e.OccurredAt)
	if err != nil {
		return fmt.Errorf("postgres: record auth event: %w", err)
	}
	return nil
}

func (a *AuditLog) ListForUser(ctx context.Context, userID uuid.UUID, limit int) ([]domain.AuthEvent, error) {
	const q = `SELECT id, event, user_id, session_id, method, email, ip, user_agent, detail, occurred_at
		FROM auth_events WHERE user_id = $1 ORDER BY occurred_at DESC LIMIT $2`
	rows, err := a.pool.Query(ctx, q, userID, limit)
	if err != nil {
		return nil, fmt.Errorf("postgres: list auth events: %w", err)
	}
	defer rows.Close()

	out := make([]domain.AuthEvent, 0, limit)
	for rows.Next() {
		var (
			e           domain.AuthEvent
			event, meth string
		)
		if err := rows.Scan(&e.ID, &event, &e.UserID, &e.SessionID, &meth,
			&e.Email, &e.IP, &e.UserAgent, &e.Detail, &e.OccurredAt); err != nil {
			return nil, fmt.Errorf("postgres: scan auth event: %w", err)
		}
		e.Type = domain.AuthEventType(event)
		e.Method = domain.AuthMethod(meth)
		e.OccurredAt = e.OccurredAt.UTC()
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: list auth events: %w", err)
	}
	return out, nil
}

func (a *AuditLog) Anonymize(ctx context.Context, userID uuid.UUID) error {
	const q = `UPDATE auth_events SET email = '', ip = '', user_agent = '' WHERE user_id = $1`
	if _, err := a.pool.Exec(ctx, q, userID); err != nil {
		return fmt.Errorf("postgres: anonymise auth events: %w", err)
	}
	return nil
}

func truncateText(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}
