package domain

import (
	"net/mail"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
)

const (
	maxDisplayNameLen = 100
	minPasswordLen    = 8
	// bcrypt ignores everything past 72 bytes. Rejecting longer passwords is
	// better than silently truncating them.
	maxPasswordBytes = 72
)

// User is an account holder. A user can have a password, a linked Google
// identity, or both; at least one is always present.
type User struct {
	ID            uuid.UUID
	Email         string
	DisplayName   string
	AvatarURL     string
	PasswordHash  string // empty for Google-only accounts
	GoogleSubject string // Google's stable account id ("sub"); empty if not linked
	EmailVerified bool
	CreatedAt     time.Time
	UpdatedAt     time.Time
	LastLoginAt   *time.Time
}

// NewPasswordUser builds a user who signs in with email and password. The
// caller hashes the password; the domain never sees it in plain text once
// validated.
func NewPasswordUser(email, displayName, passwordHash string) (*User, error) {
	u := &User{
		ID:           uuid.New(),
		Email:        NormalizeEmail(email),
		DisplayName:  strings.TrimSpace(displayName),
		PasswordHash: passwordHash,
	}
	if u.DisplayName == "" {
		u.DisplayName = defaultDisplayName(u.Email)
	}
	if err := u.validate(); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	u.CreatedAt, u.UpdatedAt = now, now
	return u, nil
}

// NewGoogleUser builds a user from a verified Google identity.
func NewGoogleUser(id GoogleIdentity) (*User, error) {
	u := &User{
		ID:            uuid.New(),
		Email:         NormalizeEmail(id.Email),
		DisplayName:   strings.TrimSpace(id.Name),
		AvatarURL:     id.Picture,
		GoogleSubject: id.Subject,
		EmailVerified: id.EmailVerified,
	}
	if u.DisplayName == "" {
		u.DisplayName = defaultDisplayName(u.Email)
	}
	if err := u.validate(); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	u.CreatedAt, u.UpdatedAt = now, now
	return u, nil
}

// LinkGoogle attaches a Google identity to an existing account. Only
// permitted when Google vouches for the email, otherwise anyone could claim
// an account by creating a Google login with someone else's address.
func (u *User) LinkGoogle(id GoogleIdentity) error {
	if !id.EmailVerified {
		return ErrGoogleEmailUnverified
	}
	u.GoogleSubject = id.Subject
	u.EmailVerified = true
	if u.AvatarURL == "" {
		u.AvatarURL = id.Picture
	}
	u.UpdatedAt = time.Now().UTC()
	return nil
}

// Rename changes the display name.
func (u *User) Rename(displayName string) error {
	name := strings.TrimSpace(displayName)
	if name == "" {
		return ValidationError{Field: "display_name", Reason: "must not be empty"}
	}
	if utf8.RuneCountInString(name) > maxDisplayNameLen {
		return ValidationError{Field: "display_name", Reason: "is too long"}
	}
	u.DisplayName = name
	u.UpdatedAt = time.Now().UTC()
	return nil
}

func (u *User) HasPassword() bool { return u.PasswordHash != "" }

func (u *User) validate() error {
	if err := ValidateEmail(u.Email); err != nil {
		return err
	}
	if utf8.RuneCountInString(u.DisplayName) > maxDisplayNameLen {
		return ValidationError{Field: "display_name", Reason: "is too long"}
	}
	if u.PasswordHash == "" && u.GoogleSubject == "" {
		return ValidationError{Field: "credentials", Reason: "an account needs a password or a Google login"}
	}
	return nil
}

// NormalizeEmail makes addresses comparable: case and surrounding space never
// distinguish two accounts.
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func ValidateEmail(email string) error {
	if email == "" {
		return ValidationError{Field: "email", Reason: "must not be empty"}
	}
	if len(email) > 254 {
		return ValidationError{Field: "email", Reason: "is too long"}
	}
	addr, err := mail.ParseAddress(email)
	// ParseAddress accepts "Name <a@b>"; only a bare address is an email here.
	if err != nil || addr.Address != email || !strings.Contains(email, "@") {
		return ValidationError{Field: "email", Reason: "is not a valid email address"}
	}
	return nil
}

// ValidatePassword enforces the password policy before anything is hashed.
func ValidatePassword(password string) error {
	if utf8.RuneCountInString(password) < minPasswordLen {
		return ValidationError{Field: "password", Reason: "must be at least 8 characters"}
	}
	if len(password) > maxPasswordBytes {
		return ValidationError{Field: "password", Reason: "must be at most 72 bytes"}
	}
	if strings.TrimSpace(password) == "" {
		return ValidationError{Field: "password", Reason: "must not be only whitespace"}
	}
	return nil
}

func defaultDisplayName(email string) string {
	if at := strings.IndexByte(email, '@'); at > 0 {
		return email[:at]
	}
	return "Journaler"
}

// GoogleIdentity is what a verified Google ID token tells us about a person.
type GoogleIdentity struct {
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
	Picture       string
}
