package domain

import (
	"time"

	"github.com/google/uuid"
)

// AuthEventType names an auditable authentication event.
type AuthEventType string

const (
	AuthEventRegistered     AuthEventType = "registered"
	AuthEventLogin          AuthEventType = "login"
	AuthEventLoginFailed    AuthEventType = "login_failed"
	AuthEventTokenRefreshed AuthEventType = "token_refreshed"
	AuthEventLogout         AuthEventType = "logout"
	AuthEventLogoutAll      AuthEventType = "logout_all"
	AuthEventRefreshReuse   AuthEventType = "refresh_token_reuse"
	AuthEventGoogleLinked   AuthEventType = "google_linked"
	AuthEventReauthFailed   AuthEventType = "reauth_failed"
	AuthEventAccountDeleted AuthEventType = "account_deleted"
)

// AuthEvent is one line of the authentication audit log. UserID is nil for a
// failed attempt against an unknown email; Email is kept so such attempts can
// still be investigated.
type AuthEvent struct {
	ID         uuid.UUID
	Type       AuthEventType
	UserID     *uuid.UUID
	SessionID  *uuid.UUID
	Method     AuthMethod
	Email      string
	IP         string
	UserAgent  string
	Detail     string
	OccurredAt time.Time
}

// ClientInfo is where a request came from, captured for the audit trail.
type ClientInfo struct {
	IP        string
	UserAgent string
}
