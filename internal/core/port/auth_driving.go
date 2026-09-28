package port

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/avinas1209/day-journal/internal/core/domain"
)

type RegisterCommand struct {
	Email       string
	Password    string
	DisplayName string
	Client      domain.ClientInfo
}

type LoginCommand struct {
	Email    string
	Password string
	Client   domain.ClientInfo
}

type GoogleLoginCommand struct {
	IDToken string
	Client  domain.ClientInfo
}

// DeleteAccountCommand carries the proof of identity a deletion needs: the
// password for accounts that have one, or a fresh Google ID token.
type DeleteAccountCommand struct {
	Principal     Principal
	Password      string
	GoogleIDToken string
	Client        domain.ClientInfo
}

// TokenPair is what a client stores after signing in.
type TokenPair struct {
	AccessToken           string
	AccessTokenExpiresAt  time.Time
	RefreshToken          string
	RefreshTokenExpiresAt time.Time
}

// AuthResult is returned by every sign-in path.
type AuthResult struct {
	User    *domain.User
	Tokens  TokenPair
	Created bool // true when this sign-in created the account
}

// Principal is the authenticated caller, attached to each request.
type Principal struct {
	UserID    uuid.UUID
	SessionID uuid.UUID
}

// AuthService is the driving port for identity.
type AuthService interface {
	Register(ctx context.Context, cmd RegisterCommand) (AuthResult, error)
	Login(ctx context.Context, cmd LoginCommand) (AuthResult, error)
	LoginWithGoogle(ctx context.Context, cmd GoogleLoginCommand) (AuthResult, error)
	Refresh(ctx context.Context, refreshToken string, client domain.ClientInfo) (TokenPair, error)
	Logout(ctx context.Context, p Principal, client domain.ClientInfo) error
	LogoutAll(ctx context.Context, p Principal, client domain.ClientInfo) error

	// Authenticate turns a bearer token into a Principal, failing with
	// domain.ErrUnauthenticated if it is invalid, expired or logged out.
	Authenticate(ctx context.Context, accessToken string) (Principal, error)

	Me(ctx context.Context, userID uuid.UUID) (*domain.User, error)
	UpdateProfile(ctx context.Context, userID uuid.UUID, displayName string) (*domain.User, error)
	// DeleteAccount permanently removes the account, its entries and its
	// sessions, after re-verifying the person's identity.
	DeleteAccount(ctx context.Context, cmd DeleteAccountCommand) error
	Sessions(ctx context.Context, userID uuid.UUID) ([]*domain.Session, error)
	AuditTrail(ctx context.Context, userID uuid.UUID) ([]domain.AuthEvent, error)
}
