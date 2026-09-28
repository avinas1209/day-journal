package domain

import (
	"time"

	"github.com/google/uuid"
)

// AuthMethod records how a session was established.
type AuthMethod string

const (
	AuthMethodPassword AuthMethod = "password"
	AuthMethodGoogle   AuthMethod = "google"
)

// RevokeReason records why a session ended.
type RevokeReason string

const (
	RevokeLogout      RevokeReason = "logout"
	RevokeLogoutAll   RevokeReason = "logout_all"
	RevokeTokenReuse  RevokeReason = "refresh_token_reuse"
	RevokeExpired     RevokeReason = "expired"
	RevokeUserDeleted RevokeReason = "user_deleted"
)

// Session is one signed-in device. It is also the audit record of that
// sign-in: CreatedAt is the login time and RevokedAt the logout time, written
// in the same statement that grants or ends access, so the trail can never
// disagree with what actually happened.
type Session struct {
	ID               uuid.UUID
	UserID           uuid.UUID
	Method           AuthMethod
	RefreshTokenHash []byte
	// PreviousRefreshHash is the token this one replaced. Seeing it again
	// means a rotated token was replayed — the signature of a stolen token.
	PreviousRefreshHash []byte
	IP                  string
	UserAgent           string
	CreatedAt           time.Time
	LastRefreshedAt     time.Time
	ExpiresAt           time.Time
	RevokedAt           *time.Time
	RevokeReason        RevokeReason
}

// NewSession opens a session that lasts ttl unless refreshed or revoked.
func NewSession(userID uuid.UUID, method AuthMethod, refreshHash []byte, ip, userAgent string, ttl time.Duration) *Session {
	now := time.Now().UTC()
	return &Session{
		ID:               uuid.New(),
		UserID:           userID,
		Method:           method,
		RefreshTokenHash: refreshHash,
		IP:               ip,
		UserAgent:        truncate(userAgent, 512),
		CreatedAt:        now,
		LastRefreshedAt:  now,
		ExpiresAt:        now.Add(ttl),
	}
}

// Active reports whether the session may still be used.
func (s *Session) Active(now time.Time) bool {
	return s.RevokedAt == nil && now.Before(s.ExpiresAt)
}

// Rotate swaps in a new refresh token and slides the expiry forward.
func (s *Session) Rotate(refreshHash []byte, ttl time.Duration) {
	now := time.Now().UTC()
	s.PreviousRefreshHash = s.RefreshTokenHash
	s.RefreshTokenHash = refreshHash
	s.LastRefreshedAt = now
	s.ExpiresAt = now.Add(ttl)
}

// Revoke ends the session. Revoking twice keeps the first logout time.
func (s *Session) Revoke(reason RevokeReason) {
	if s.RevokedAt != nil {
		return
	}
	now := time.Now().UTC()
	s.RevokedAt = &now
	s.RevokeReason = reason
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}
