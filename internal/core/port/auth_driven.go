package port

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/avinas1209/day-journal/internal/core/domain"
)

// UserRepository persists accounts. Implemented by the Postgres adapter.
type UserRepository interface {
	// Create fails with domain.ErrEmailTaken if the email is already used.
	Create(ctx context.Context, u *domain.User) error
	Update(ctx context.Context, u *domain.User) error
	FindByID(ctx context.Context, id uuid.UUID) (*domain.User, error)
	FindByEmail(ctx context.Context, email string) (*domain.User, error)
	FindByGoogleSubject(ctx context.Context, subject string) (*domain.User, error)
	RecordLogin(ctx context.Context, id uuid.UUID, at time.Time) error
	// Delete removes the account. Its entries and sessions go with it
	// (ON DELETE CASCADE), in the same statement.
	Delete(ctx context.Context, id uuid.UUID) error
}

// SessionRepository persists sessions — which double as the login/logout
// audit trail. Implemented by the Postgres adapter.
type SessionRepository interface {
	Create(ctx context.Context, s *domain.Session) error
	FindByID(ctx context.Context, id uuid.UUID) (*domain.Session, error)
	// Rotate swaps the refresh token only if it still matches expectedHash,
	// so two concurrent refreshes with the same token cannot both win.
	Rotate(ctx context.Context, s *domain.Session, expectedHash []byte) error
	Revoke(ctx context.Context, s *domain.Session) error
	// RevokeAllForUser ends every active session and returns their ids so
	// callers can deny the access tokens already issued for them.
	RevokeAllForUser(ctx context.Context, userID uuid.UUID, reason domain.RevokeReason) ([]uuid.UUID, error)
	ListForUser(ctx context.Context, userID uuid.UUID, limit int) ([]*domain.Session, error)
}

// ErrStaleRefresh is returned by SessionRepository.Rotate when another
// request rotated the token first.
var ErrStaleRefresh = errors.New("refresh token already rotated")

// AuditLog records authentication events. Implemented by the Postgres adapter.
type AuditLog interface {
	Record(ctx context.Context, evt domain.AuthEvent) error
	ListForUser(ctx context.Context, userID uuid.UUID, limit int) ([]domain.AuthEvent, error)
	// Anonymize strips personal data (email, IP, user agent) from a deleted
	// user's events. The security timeline — what happened, and when —
	// survives; who it was traceable to does not.
	Anonymize(ctx context.Context, userID uuid.UUID) error
}

// PasswordHasher is implemented by the bcrypt adapter.
type PasswordHasher interface {
	Hash(password string) (string, error)
	// Compare returns nil only when password matches hash.
	Compare(hash, password string) error
}

// AccessClaims is what a verified access token asserts.
type AccessClaims struct {
	UserID    uuid.UUID
	SessionID uuid.UUID
	ExpiresAt time.Time
}

// AccessToken is a signed, short-lived bearer credential.
type AccessToken struct {
	Value     string
	ExpiresAt time.Time
}

// TokenIssuer signs and verifies access tokens. Implemented by the JWT adapter.
type TokenIssuer interface {
	Issue(userID, sessionID uuid.UUID) (AccessToken, error)
	// Verify fails with domain.ErrUnauthenticated for any bad token.
	Verify(token string) (AccessClaims, error)
	TTL() time.Duration
}

// GoogleVerifier checks a Google ID token's signature, issuer, audience and
// expiry. Implemented by the Google adapter.
type GoogleVerifier interface {
	Verify(ctx context.Context, idToken string) (domain.GoogleIdentity, error)
}

// SessionDenylist is a fast "has this session been logged out?" check,
// implemented in Redis. Entries only need to outlive the access token TTL:
// after that, every token for the session has expired on its own.
type SessionDenylist interface {
	Deny(ctx context.Context, sessionID uuid.UUID, ttl time.Duration) error
	IsDenied(ctx context.Context, sessionID uuid.UUID) (bool, error)
}

// RateLimiter caps attempts per key in a fixed window. Implemented in Redis.
type RateLimiter interface {
	Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error)
}
