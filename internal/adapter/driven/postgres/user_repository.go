package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/avinas1209/day-journal/internal/core/domain"
	"github.com/avinas1209/day-journal/internal/core/port"
)

const uniqueViolation = "23505"

// UserRepository implements port.UserRepository.
type UserRepository struct {
	pool *pgxpool.Pool
}

var _ port.UserRepository = (*UserRepository)(nil)

func NewUserRepository(pool *pgxpool.Pool) *UserRepository {
	return &UserRepository{pool: pool}
}

const userColumns = `id, email, display_name, avatar_url, password_hash, google_subject,
	email_verified, created_at, updated_at, last_login_at`

func (r *UserRepository) Create(ctx context.Context, u *domain.User) error {
	const q = `INSERT INTO users (` + userColumns + `)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`
	_, err := r.pool.Exec(ctx, q,
		u.ID, u.Email, u.DisplayName, u.AvatarURL, nullable(u.PasswordHash), nullable(u.GoogleSubject),
		u.EmailVerified, u.CreatedAt, u.UpdatedAt, u.LastLoginAt)
	if err != nil {
		// The unique email constraint is the real guard against a race
		// between two sign-ups with the same address.
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation {
			return domain.ErrEmailTaken
		}
		return fmt.Errorf("postgres: create user: %w", err)
	}
	return nil
}

func (r *UserRepository) Update(ctx context.Context, u *domain.User) error {
	const q = `UPDATE users
		SET display_name = $2, avatar_url = $3, password_hash = $4, google_subject = $5,
		    email_verified = $6, updated_at = $7
		WHERE id = $1`
	tag, err := r.pool.Exec(ctx, q,
		u.ID, u.DisplayName, u.AvatarURL, nullable(u.PasswordHash), nullable(u.GoogleSubject),
		u.EmailVerified, u.UpdatedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation {
			return domain.ErrEmailTaken
		}
		return fmt.Errorf("postgres: update user: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrUserNotFound
	}
	return nil
}

func (r *UserRepository) FindByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	return r.findOne(ctx, `WHERE id = $1`, id)
}

func (r *UserRepository) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
	return r.findOne(ctx, `WHERE email = $1`, domain.NormalizeEmail(email))
}

func (r *UserRepository) FindByGoogleSubject(ctx context.Context, subject string) (*domain.User, error) {
	return r.findOne(ctx, `WHERE google_subject = $1`, subject)
}

func (r *UserRepository) RecordLogin(ctx context.Context, id uuid.UUID, at time.Time) error {
	if _, err := r.pool.Exec(ctx, `UPDATE users SET last_login_at = $2 WHERE id = $1`, id, at); err != nil {
		return fmt.Errorf("postgres: record login: %w", err)
	}
	return nil
}

func (r *UserRepository) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("postgres: delete user: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrUserNotFound
	}
	return nil
}

func (r *UserRepository) findOne(ctx context.Context, where string, arg any) (*domain.User, error) {
	var (
		u                     domain.User
		passwordHash, subject *string
	)
	err := r.pool.QueryRow(ctx, `SELECT `+userColumns+` FROM users `+where, arg).Scan(
		&u.ID, &u.Email, &u.DisplayName, &u.AvatarURL, &passwordHash, &subject,
		&u.EmailVerified, &u.CreatedAt, &u.UpdatedAt, &u.LastLoginAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: find user: %w", err)
	}
	u.PasswordHash = deref(passwordHash)
	u.GoogleSubject = deref(subject)
	u.CreatedAt, u.UpdatedAt = u.CreatedAt.UTC(), u.UpdatedAt.UTC()
	return &u, nil
}

// nullable stores "" as NULL, so the partial unique constraint on
// google_subject never sees two empty strings collide.
func nullable(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
