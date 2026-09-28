package domain

import "errors"

// Domain errors. Adapters translate these into transport-specific failures
// (HTTP status codes, for example) — the core never knows about those.
var (
	ErrEntryNotFound = errors.New("entry not found")
	ErrValidation    = errors.New("validation failed")
	ErrForbidden     = errors.New("entry belongs to another author")

	ErrUserNotFound = errors.New("user not found")
	ErrEmailTaken   = errors.New("an account with that email already exists")

	// ErrInvalidCredentials is deliberately vague: it never reveals whether
	// the email exists or only the password was wrong.
	ErrInvalidCredentials = errors.New("invalid email or password")

	// ErrUnauthenticated covers every form of a missing, malformed, expired
	// or revoked token. The client's response is always the same: sign in.
	ErrUnauthenticated = errors.New("authentication required")

	ErrSessionNotFound       = errors.New("session not found")
	ErrGoogleNotConfigured   = errors.New("google sign-in is not configured on this server")
	ErrGoogleTokenInvalid    = errors.New("google sign-in could not be verified")
	ErrGoogleEmailUnverified = errors.New("google has not verified this email address")
	ErrTooManyAttempts       = errors.New("too many attempts; try again later")

	// ErrReauthRequired: a destructive action needs the account's password
	// (or a fresh Google sign-in) on top of the session token, so a phone
	// left unlocked is not enough to delete someone's journal.
	ErrReauthRequired = errors.New("confirm it's you to continue")
	// ErrReauthFailed is deliberately distinct from ErrInvalidCredentials:
	// it is answered 403, not 401, so a client never mistakes a wrong
	// password for an expired token and signs the user out.
	ErrReauthFailed = errors.New("that password is incorrect")
)

// ValidationError carries the field that failed so handlers can report it.
type ValidationError struct {
	Field  string
	Reason string
}

func (e ValidationError) Error() string {
	return "validation failed on " + e.Field + ": " + e.Reason
}

// Unwrap lets callers use errors.Is(err, domain.ErrValidation).
func (e ValidationError) Unwrap() error { return ErrValidation }
