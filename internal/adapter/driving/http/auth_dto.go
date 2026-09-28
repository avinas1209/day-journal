package http

import (
	"time"

	"github.com/google/uuid"

	"github.com/avinas1209/day-journal/internal/core/domain"
	"github.com/avinas1209/day-journal/internal/core/port"
)

type registerRequest struct {
	Email       string `json:"email" binding:"required"`
	Password    string `json:"password" binding:"required"`
	DisplayName string `json:"display_name"`
}

type loginRequest struct {
	Email    string `json:"email" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type googleRequest struct {
	IDToken string `json:"id_token" binding:"required"`
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// deleteAccountRequest takes one proof of identity. Both are optional at
// the transport level; the use case decides which the account needs.
type deleteAccountRequest struct {
	Password      string `json:"password"`
	GoogleIDToken string `json:"google_id_token"`
}

type updateMeRequest struct {
	DisplayName string `json:"display_name" binding:"required"`
}

type userResponse struct {
	ID            uuid.UUID  `json:"id"`
	Email         string     `json:"email"`
	DisplayName   string     `json:"display_name"`
	AvatarURL     string     `json:"avatar_url"`
	EmailVerified bool       `json:"email_verified"`
	HasPassword   bool       `json:"has_password"`
	GoogleLinked  bool       `json:"google_linked"`
	CreatedAt     time.Time  `json:"created_at"`
	LastLoginAt   *time.Time `json:"last_login_at"`
}

// toUserResponse deliberately omits the password hash and Google subject.
func toUserResponse(u *domain.User) userResponse {
	return userResponse{
		ID:            u.ID,
		Email:         u.Email,
		DisplayName:   u.DisplayName,
		AvatarURL:     u.AvatarURL,
		EmailVerified: u.EmailVerified,
		HasPassword:   u.HasPassword(),
		GoogleLinked:  u.GoogleSubject != "",
		CreatedAt:     u.CreatedAt,
		LastLoginAt:   u.LastLoginAt,
	}
}

type tokensResponse struct {
	TokenType             string    `json:"token_type"`
	AccessToken           string    `json:"access_token"`
	AccessTokenExpiresAt  time.Time `json:"access_token_expires_at"`
	ExpiresIn             int64     `json:"expires_in"` // seconds, per RFC 6749
	RefreshToken          string    `json:"refresh_token"`
	RefreshTokenExpiresAt time.Time `json:"refresh_token_expires_at"`
}

func toTokensResponse(t port.TokenPair) tokensResponse {
	return tokensResponse{
		TokenType:             "Bearer",
		AccessToken:           t.AccessToken,
		AccessTokenExpiresAt:  t.AccessTokenExpiresAt,
		ExpiresIn:             int64(time.Until(t.AccessTokenExpiresAt).Seconds()),
		RefreshToken:          t.RefreshToken,
		RefreshTokenExpiresAt: t.RefreshTokenExpiresAt,
	}
}

type authResponse struct {
	User    userResponse   `json:"user"`
	Tokens  tokensResponse `json:"tokens"`
	Created bool           `json:"created"`
}

func toAuthResponse(r port.AuthResult) authResponse {
	return authResponse{User: toUserResponse(r.User), Tokens: toTokensResponse(r.Tokens), Created: r.Created}
}

// sessionResponse speaks in login/logout terms: this is the audit view.
type sessionResponse struct {
	ID              uuid.UUID  `json:"id"`
	Method          string     `json:"method"`
	IP              string     `json:"ip"`
	UserAgent       string     `json:"user_agent"`
	LoggedInAt      time.Time  `json:"logged_in_at"`
	LastRefreshedAt time.Time  `json:"last_refreshed_at"`
	ExpiresAt       time.Time  `json:"expires_at"`
	LoggedOutAt     *time.Time `json:"logged_out_at"`
	LogoutReason    string     `json:"logout_reason,omitempty"`
	Active          bool       `json:"active"`
	Current         bool       `json:"current"`
}

func toSessionResponses(sessions []*domain.Session, current uuid.UUID) []sessionResponse {
	now := time.Now().UTC()
	out := make([]sessionResponse, 0, len(sessions))
	for _, s := range sessions {
		out = append(out, sessionResponse{
			ID:              s.ID,
			Method:          string(s.Method),
			IP:              s.IP,
			UserAgent:       s.UserAgent,
			LoggedInAt:      s.CreatedAt,
			LastRefreshedAt: s.LastRefreshedAt,
			ExpiresAt:       s.ExpiresAt,
			LoggedOutAt:     s.RevokedAt,
			LogoutReason:    string(s.RevokeReason),
			Active:          s.Active(now),
			Current:         s.ID == current,
		})
	}
	return out
}

type auditEventResponse struct {
	ID         uuid.UUID  `json:"id"`
	Event      string     `json:"event"`
	Method     string     `json:"method,omitempty"`
	SessionID  *uuid.UUID `json:"session_id,omitempty"`
	IP         string     `json:"ip"`
	UserAgent  string     `json:"user_agent"`
	Detail     string     `json:"detail,omitempty"`
	OccurredAt time.Time  `json:"occurred_at"`
}

func toAuditResponses(events []domain.AuthEvent) []auditEventResponse {
	out := make([]auditEventResponse, 0, len(events))
	for _, e := range events {
		out = append(out, auditEventResponse{
			ID: e.ID, Event: string(e.Type), Method: string(e.Method), SessionID: e.SessionID,
			IP: e.IP, UserAgent: e.UserAgent, Detail: e.Detail, OccurredAt: e.OccurredAt,
		})
	}
	return out
}
