package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/avinas1209/day-journal/internal/core/domain"
	"github.com/avinas1209/day-journal/internal/core/port"
)

// SessionRepository implements port.SessionRepository.
type SessionRepository struct {
	pool *pgxpool.Pool
}

var _ port.SessionRepository = (*SessionRepository)(nil)

func NewSessionRepository(pool *pgxpool.Pool) *SessionRepository {
	return &SessionRepository{pool: pool}
}

const sessionColumns = `id, user_id, method, refresh_token_hash, previous_refresh_token_hash,
	ip, user_agent, created_at, last_refreshed_at, expires_at, revoked_at, revoke_reason`

func (r *SessionRepository) Create(ctx context.Context, s *domain.Session) error {
	const q = `INSERT INTO sessions (` + sessionColumns + `)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`
	_, err := r.pool.Exec(ctx, q,
		s.ID, s.UserID, string(s.Method), s.RefreshTokenHash, s.PreviousRefreshHash,
		s.IP, s.UserAgent, s.CreatedAt, s.LastRefreshedAt, s.ExpiresAt, s.RevokedAt, reasonOrNil(s.RevokeReason))
	if err != nil {
		return fmt.Errorf("postgres: create session: %w", err)
	}
	return nil
}

func (r *SessionRepository) FindByID(ctx context.Context, id uuid.UUID) (*domain.Session, error) {
	s, err := scanSession(r.pool.QueryRow(ctx, `SELECT `+sessionColumns+` FROM sessions WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrSessionNotFound
	}
	return s, err
}

// Rotate is a compare-and-swap on the refresh hash: the WHERE clause only
// matches if nobody rotated the token since it was read, and the session is
// still live. Zero rows affected means another request got there first.
func (r *SessionRepository) Rotate(ctx context.Context, s *domain.Session, expectedHash []byte) error {
	const q = `UPDATE sessions
		SET refresh_token_hash = $2, previous_refresh_token_hash = $3,
		    last_refreshed_at = $4, expires_at = $5
		WHERE id = $1 AND refresh_token_hash = $6 AND revoked_at IS NULL`
	tag, err := r.pool.Exec(ctx, q,
		s.ID, s.RefreshTokenHash, s.PreviousRefreshHash, s.LastRefreshedAt, s.ExpiresAt, expectedHash)
	if err != nil {
		return fmt.Errorf("postgres: rotate session: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return port.ErrStaleRefresh
	}
	return nil
}

func (r *SessionRepository) Revoke(ctx context.Context, s *domain.Session) error {
	// COALESCE keeps the first logout time if the session was already ended.
	const q = `UPDATE sessions
		SET revoked_at = COALESCE(revoked_at, $2), revoke_reason = COALESCE(revoke_reason, $3)
		WHERE id = $1`
	if _, err := r.pool.Exec(ctx, q, s.ID, s.RevokedAt, reasonOrNil(s.RevokeReason)); err != nil {
		return fmt.Errorf("postgres: revoke session: %w", err)
	}
	return nil
}

func (r *SessionRepository) RevokeAllForUser(ctx context.Context, userID uuid.UUID, reason domain.RevokeReason) ([]uuid.UUID, error) {
	const q = `UPDATE sessions
		SET revoked_at = now(), revoke_reason = $2
		WHERE user_id = $1 AND revoked_at IS NULL
		RETURNING id`
	rows, err := r.pool.Query(ctx, q, userID, string(reason))
	if err != nil {
		return nil, fmt.Errorf("postgres: revoke sessions: %w", err)
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return nil, fmt.Errorf("postgres: revoke sessions: %w", err)
	}
	return ids, nil
}

func (r *SessionRepository) ListForUser(ctx context.Context, userID uuid.UUID, limit int) ([]*domain.Session, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+sessionColumns+` FROM sessions WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2`,
		userID, limit)
	if err != nil {
		return nil, fmt.Errorf("postgres: list sessions: %w", err)
	}
	defer rows.Close()

	out := make([]*domain.Session, 0, limit)
	for rows.Next() {
		s, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: list sessions: %w", err)
	}
	return out, nil
}

func scanSession(row scanner) (*domain.Session, error) {
	var (
		s      domain.Session
		method string
		reason *string
	)
	err := row.Scan(&s.ID, &s.UserID, &method, &s.RefreshTokenHash, &s.PreviousRefreshHash,
		&s.IP, &s.UserAgent, &s.CreatedAt, &s.LastRefreshedAt, &s.ExpiresAt, &s.RevokedAt, &reason)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
		return nil, fmt.Errorf("postgres: scan session: %w", err)
	}
	s.Method = domain.AuthMethod(method)
	if reason != nil {
		s.RevokeReason = domain.RevokeReason(*reason)
	}
	s.CreatedAt = s.CreatedAt.UTC()
	s.LastRefreshedAt = s.LastRefreshedAt.UTC()
	s.ExpiresAt = s.ExpiresAt.UTC()
	if s.RevokedAt != nil {
		t := s.RevokedAt.UTC()
		s.RevokedAt = &t
	}
	return &s, nil
}

func reasonOrNil(r domain.RevokeReason) *string {
	if r == "" {
		return nil
	}
	s := string(r)
	return &s
}
