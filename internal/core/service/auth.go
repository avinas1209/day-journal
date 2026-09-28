package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/avinas1209/day-journal/internal/core/domain"
	"github.com/avinas1209/day-journal/internal/core/port"
)

// AuthConfig holds the tunables of the identity use cases.
type AuthConfig struct {
	RefreshTTL time.Duration

	// Brute-force limits, each a count per AttemptWindow.
	AttemptWindow time.Duration
	// LoginAttemptsPerEmailIP is the tight limit: one source guessing one
	// account. Keyed on the pair so a stranger cannot lock the owner out.
	LoginAttemptsPerEmailIP int
	// LoginAttemptsPerEmail caps guessing spread across many IPs. Generous on
	// purpose: reaching it takes a botnet, not ten requests from a stranger.
	LoginAttemptsPerEmail int
	LoginAttemptsPerIP    int
	RegistrationsPerIP    int
	// DeleteAttemptsPerUser stops a stolen session being used to brute-force
	// the password through the deletion endpoint.
	DeleteAttemptsPerUser int
}

func DefaultAuthConfig() AuthConfig {
	return AuthConfig{
		RefreshTTL:              30 * 24 * time.Hour,
		AttemptWindow:           15 * time.Minute,
		LoginAttemptsPerEmailIP: 10,
		LoginAttemptsPerEmail:   100,
		LoginAttemptsPerIP:      50,
		RegistrationsPerIP:      20,
		DeleteAttemptsPerUser:   5,
	}
}

const (
	refreshSecretBytes = 32
	sessionListLimit   = 50
	auditListLimit     = 100
	// denylistMargin covers clock skew between servers verifying tokens.
	denylistMargin = time.Minute
)

// AuthService implements port.AuthService.
type AuthService struct {
	users    port.UserRepository
	sessions port.SessionRepository
	audit    port.AuditLog
	hasher   port.PasswordHasher
	tokens   port.TokenIssuer
	google   port.GoogleVerifier // nil when Google sign-in is not configured
	denylist port.SessionDenylist
	limiter  port.RateLimiter
	log      *slog.Logger
	cfg      AuthConfig

	// dummyHash is compared against when an email is unknown, so a failed
	// login costs the same bcrypt time whether or not the account exists.
	dummyHash string
}

var _ port.AuthService = (*AuthService)(nil)

// AuthDeps groups the driven ports so the constructor stays readable.
type AuthDeps struct {
	Users    port.UserRepository
	Sessions port.SessionRepository
	Audit    port.AuditLog
	Hasher   port.PasswordHasher
	Tokens   port.TokenIssuer
	Google   port.GoogleVerifier
	Denylist port.SessionDenylist
	Limiter  port.RateLimiter
}

func NewAuthService(deps AuthDeps, cfg AuthConfig, log *slog.Logger) (*AuthService, error) {
	dummy, err := deps.Hasher.Hash("timing-equaliser-not-a-real-password")
	if err != nil {
		return nil, fmt.Errorf("auth: prepare timing hash: %w", err)
	}
	return &AuthService{
		users:     deps.Users,
		sessions:  deps.Sessions,
		audit:     deps.Audit,
		hasher:    deps.Hasher,
		tokens:    deps.Tokens,
		google:    deps.Google,
		denylist:  deps.Denylist,
		limiter:   deps.Limiter,
		log:       log,
		cfg:       cfg,
		dummyHash: dummy,
	}, nil
}

// --- sign-up and sign-in ---

func (s *AuthService) Register(ctx context.Context, cmd port.RegisterCommand) (port.AuthResult, error) {
	// Validate first: it is cheap, and a malformed request should not spend
	// the budget of everyone else behind the same IP.
	email := domain.NormalizeEmail(cmd.Email)
	if err := domain.ValidateEmail(email); err != nil {
		return port.AuthResult{}, err
	}
	if err := domain.ValidatePassword(cmd.Password); err != nil {
		return port.AuthResult{}, err
	}
	if err := s.limit(ctx, "register:ip:"+cmd.Client.IP, s.cfg.RegistrationsPerIP); err != nil {
		return port.AuthResult{}, err
	}

	hash, err := s.hasher.Hash(cmd.Password)
	if err != nil {
		return port.AuthResult{}, fmt.Errorf("auth: hash password: %w", err)
	}
	user, err := domain.NewPasswordUser(email, cmd.DisplayName, hash)
	if err != nil {
		return port.AuthResult{}, err
	}
	if err := s.users.Create(ctx, user); err != nil {
		return port.AuthResult{}, err
	}
	s.record(ctx, domain.AuthEvent{
		Type: domain.AuthEventRegistered, UserID: &user.ID,
		Method: domain.AuthMethodPassword, Email: user.Email,
	}, cmd.Client)

	tokens, err := s.startSession(ctx, user, domain.AuthMethodPassword, cmd.Client)
	if err != nil {
		return port.AuthResult{}, err
	}
	return port.AuthResult{User: user, Tokens: tokens, Created: true}, nil
}

func (s *AuthService) Login(ctx context.Context, cmd port.LoginCommand) (port.AuthResult, error) {
	email := domain.NormalizeEmail(cmd.Email)

	// Three limits. Per email+IP stops one source guessing one account
	// without letting that source lock the real owner out; per IP stops one
	// source spraying many accounts; the high per-email ceiling bounds
	// guessing distributed across many IPs.
	for _, l := range []struct {
		key string
		max int
	}{
		{"login:email-ip:" + email + "|" + cmd.Client.IP, s.cfg.LoginAttemptsPerEmailIP},
		{"login:ip:" + cmd.Client.IP, s.cfg.LoginAttemptsPerIP},
		{"login:email:" + email, s.cfg.LoginAttemptsPerEmail},
	} {
		if err := s.limit(ctx, l.key, l.max); err != nil {
			return port.AuthResult{}, err
		}
	}

	user, err := s.users.FindByEmail(ctx, email)
	switch {
	case errors.Is(err, domain.ErrUserNotFound):
		_ = s.hasher.Compare(s.dummyHash, cmd.Password)
		s.failedLogin(ctx, nil, email, "unknown email", cmd.Client)
		return port.AuthResult{}, domain.ErrInvalidCredentials
	case err != nil:
		return port.AuthResult{}, err
	}

	if !user.HasPassword() {
		// A Google-only account. Answered exactly like a wrong password so
		// the response never reveals which sign-in method an email uses.
		_ = s.hasher.Compare(s.dummyHash, cmd.Password)
		s.failedLogin(ctx, &user.ID, email, "account has no password", cmd.Client)
		return port.AuthResult{}, domain.ErrInvalidCredentials
	}
	if err := s.hasher.Compare(user.PasswordHash, cmd.Password); err != nil {
		s.failedLogin(ctx, &user.ID, email, "wrong password", cmd.Client)
		return port.AuthResult{}, domain.ErrInvalidCredentials
	}

	tokens, err := s.startSession(ctx, user, domain.AuthMethodPassword, cmd.Client)
	if err != nil {
		return port.AuthResult{}, err
	}
	return port.AuthResult{User: user, Tokens: tokens}, nil
}

func (s *AuthService) LoginWithGoogle(ctx context.Context, cmd port.GoogleLoginCommand) (port.AuthResult, error) {
	if s.google == nil {
		return port.AuthResult{}, domain.ErrGoogleNotConfigured
	}
	if err := s.limit(ctx, "google:ip:"+cmd.Client.IP, s.cfg.LoginAttemptsPerIP); err != nil {
		return port.AuthResult{}, err
	}

	identity, err := s.google.Verify(ctx, cmd.IDToken)
	if err != nil {
		return port.AuthResult{}, err
	}

	// 1. Returning Google user.
	user, err := s.users.FindByGoogleSubject(ctx, identity.Subject)
	if err == nil {
		tokens, err := s.startSession(ctx, user, domain.AuthMethodGoogle, cmd.Client)
		if err != nil {
			return port.AuthResult{}, err
		}
		return port.AuthResult{User: user, Tokens: tokens}, nil
	}
	if !errors.Is(err, domain.ErrUserNotFound) {
		return port.AuthResult{}, err
	}

	// An unverified Google email can neither claim an existing account nor
	// squat an address its real owner might later register.
	if !identity.EmailVerified {
		return port.AuthResult{}, domain.ErrGoogleEmailUnverified
	}

	// 2. Existing password account with the same email: link it.
	user, err = s.users.FindByEmail(ctx, identity.Email)
	if err == nil {
		if err := user.LinkGoogle(identity); err != nil {
			return port.AuthResult{}, err
		}
		if err := s.users.Update(ctx, user); err != nil {
			return port.AuthResult{}, err
		}
		s.record(ctx, domain.AuthEvent{
			Type: domain.AuthEventGoogleLinked, UserID: &user.ID,
			Method: domain.AuthMethodGoogle, Email: user.Email,
		}, cmd.Client)

		tokens, err := s.startSession(ctx, user, domain.AuthMethodGoogle, cmd.Client)
		if err != nil {
			return port.AuthResult{}, err
		}
		return port.AuthResult{User: user, Tokens: tokens}, nil
	}
	if !errors.Is(err, domain.ErrUserNotFound) {
		return port.AuthResult{}, err
	}

	// 3. Brand new person: register them.
	user, err = domain.NewGoogleUser(identity)
	if err != nil {
		return port.AuthResult{}, err
	}
	if err := s.users.Create(ctx, user); err != nil {
		return port.AuthResult{}, err
	}
	s.record(ctx, domain.AuthEvent{
		Type: domain.AuthEventRegistered, UserID: &user.ID,
		Method: domain.AuthMethodGoogle, Email: user.Email,
	}, cmd.Client)

	tokens, err := s.startSession(ctx, user, domain.AuthMethodGoogle, cmd.Client)
	if err != nil {
		return port.AuthResult{}, err
	}
	return port.AuthResult{User: user, Tokens: tokens, Created: true}, nil
}

// --- token lifecycle ---

func (s *AuthService) Refresh(ctx context.Context, refreshToken string, client domain.ClientInfo) (port.TokenPair, error) {
	sessionID, secret, err := splitRefreshToken(refreshToken)
	if err != nil {
		return port.TokenPair{}, domain.ErrUnauthenticated
	}

	session, err := s.sessions.FindByID(ctx, sessionID)
	if errors.Is(err, domain.ErrSessionNotFound) {
		return port.TokenPair{}, domain.ErrUnauthenticated
	}
	if err != nil {
		return port.TokenPair{}, err
	}
	if !session.Active(time.Now().UTC()) {
		return port.TokenPair{}, domain.ErrUnauthenticated
	}

	presented := hashSecret(secret)
	if !constantTimeEqual(presented, session.RefreshTokenHash) {
		if constantTimeEqual(presented, session.PreviousRefreshHash) {
			// A token that was already rotated away came back. Either the
			// client or an attacker holds a stale copy; there is no way to
			// tell which, so the whole session is ended.
			s.revokeForReuse(ctx, session, client)
		}
		return port.TokenPair{}, domain.ErrUnauthenticated
	}

	newSecret, err := newRefreshSecret()
	if err != nil {
		return port.TokenPair{}, err
	}
	expected := session.RefreshTokenHash
	session.Rotate(hashSecret(newSecret), s.cfg.RefreshTTL)
	if err := s.sessions.Rotate(ctx, session, expected); err != nil {
		if errors.Is(err, port.ErrStaleRefresh) {
			return port.TokenPair{}, domain.ErrUnauthenticated
		}
		return port.TokenPair{}, err
	}

	access, err := s.tokens.Issue(session.UserID, session.ID)
	if err != nil {
		return port.TokenPair{}, fmt.Errorf("auth: issue access token: %w", err)
	}
	return port.TokenPair{
		AccessToken:           access.Value,
		AccessTokenExpiresAt:  access.ExpiresAt,
		RefreshToken:          joinRefreshToken(session.ID, newSecret),
		RefreshTokenExpiresAt: session.ExpiresAt,
	}, nil
}

func (s *AuthService) Logout(ctx context.Context, p port.Principal, client domain.ClientInfo) error {
	session, err := s.sessions.FindByID(ctx, p.SessionID)
	if errors.Is(err, domain.ErrSessionNotFound) {
		return nil // nothing to end; logout is idempotent
	}
	if err != nil {
		return err
	}
	if session.RevokedAt != nil {
		return nil
	}

	session.Revoke(domain.RevokeLogout)
	if err := s.sessions.Revoke(ctx, session); err != nil {
		return err
	}
	_ = s.deny(ctx, session.ID)
	s.record(ctx, domain.AuthEvent{
		Type: domain.AuthEventLogout, UserID: &session.UserID,
		SessionID: &session.ID, Method: session.Method,
	}, client)
	return nil
}

func (s *AuthService) LogoutAll(ctx context.Context, p port.Principal, client domain.ClientInfo) error {
	ids, err := s.sessions.RevokeAllForUser(ctx, p.UserID, domain.RevokeLogoutAll)
	if err != nil {
		return err
	}
	for _, id := range ids {
		_ = s.deny(ctx, id)
	}
	s.record(ctx, domain.AuthEvent{
		Type: domain.AuthEventLogoutAll, UserID: &p.UserID, SessionID: &p.SessionID,
		Detail: fmt.Sprintf("%d session(s) ended", len(ids)),
	}, client)
	return nil
}

func (s *AuthService) Authenticate(ctx context.Context, accessToken string) (port.Principal, error) {
	claims, err := s.tokens.Verify(accessToken)
	if err != nil {
		return port.Principal{}, domain.ErrUnauthenticated
	}

	denied, err := s.denylist.IsDenied(ctx, claims.SessionID)
	if err != nil {
		// Redis is only the fast path. If it is unreachable, ask Postgres
		// rather than either locking everyone out or letting a logged-out
		// token through.
		s.log.WarnContext(ctx, "denylist unavailable, checking session store", "error", err)
		session, err := s.sessions.FindByID(ctx, claims.SessionID)
		if err != nil || !session.Active(time.Now().UTC()) {
			return port.Principal{}, domain.ErrUnauthenticated
		}
	} else if denied {
		return port.Principal{}, domain.ErrUnauthenticated
	}

	return port.Principal{UserID: claims.UserID, SessionID: claims.SessionID}, nil
}

// --- account ---

func (s *AuthService) Me(ctx context.Context, userID uuid.UUID) (*domain.User, error) {
	return s.users.FindByID(ctx, userID)
}

func (s *AuthService) UpdateProfile(ctx context.Context, userID uuid.UUID, displayName string) (*domain.User, error) {
	user, err := s.users.FindByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if err := user.Rename(displayName); err != nil {
		return nil, err
	}
	if err := s.users.Update(ctx, user); err != nil {
		return nil, err
	}
	return user, nil
}

func (s *AuthService) DeleteAccount(ctx context.Context, cmd port.DeleteAccountCommand) error {
	userID := cmd.Principal.UserID
	if err := s.limit(ctx, "delete:user:"+userID.String(), s.cfg.DeleteAttemptsPerUser); err != nil {
		return err
	}

	user, err := s.users.FindByID(ctx, userID)
	if err != nil {
		return err
	}
	if err := s.reauthenticate(ctx, user, cmd); err != nil {
		if errors.Is(err, domain.ErrReauthFailed) {
			s.record(ctx, domain.AuthEvent{
				Type: domain.AuthEventReauthFailed, UserID: &user.ID,
				SessionID: &cmd.Principal.SessionID, Detail: "account deletion",
			}, cmd.Client)
		}
		return err
	}

	// End every session first and denylist them, so no access token issued
	// to this account keeps working for the rest of its 15 minutes. If any
	// denylist write fails, stop *before* deleting anything: the person is
	// already signed out everywhere and can sign in again to retry, which is
	// better than a deleted account with a token that still authenticates.
	ids, err := s.sessions.RevokeAllForUser(ctx, user.ID, domain.RevokeUserDeleted)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if err := s.deny(ctx, id); err != nil {
			return fmt.Errorf("auth: end sessions before deleting account: %w", err)
		}
	}

	// One statement: the account, its entries and its sessions go together.
	if err := s.users.Delete(ctx, user.ID); err != nil {
		return err
	}

	// Keep the security timeline but not the personal data in it. The final
	// event deliberately carries no email, IP or user agent either.
	if err := s.audit.Anonymize(ctx, user.ID); err != nil {
		s.log.ErrorContext(ctx, "could not anonymise audit trail", "user_id", user.ID, "error", err)
	}
	s.record(ctx, domain.AuthEvent{
		Type: domain.AuthEventAccountDeleted, UserID: &user.ID,
		Detail: fmt.Sprintf("%d session(s) ended", len(ids)),
	}, domain.ClientInfo{})

	s.log.InfoContext(ctx, "account deleted", "user_id", user.ID)
	return nil
}

// reauthenticate demands fresh proof of identity: the password if the account
// has one, otherwise (or alternatively) a Google ID token for the same Google
// account that is linked.
func (s *AuthService) reauthenticate(ctx context.Context, user *domain.User, cmd port.DeleteAccountCommand) error {
	switch {
	case cmd.Password != "" && user.HasPassword():
		if err := s.hasher.Compare(user.PasswordHash, cmd.Password); err != nil {
			return domain.ErrReauthFailed
		}
		return nil

	case cmd.GoogleIDToken != "" && user.GoogleSubject != "":
		if s.google == nil {
			return domain.ErrGoogleNotConfigured
		}
		identity, err := s.google.Verify(ctx, cmd.GoogleIDToken)
		if err != nil {
			return err
		}
		// A valid token for a *different* Google account proves nothing.
		if identity.Subject != user.GoogleSubject {
			return domain.ErrReauthFailed
		}
		return nil

	default:
		return domain.ErrReauthRequired
	}
}

func (s *AuthService) Sessions(ctx context.Context, userID uuid.UUID) ([]*domain.Session, error) {
	return s.sessions.ListForUser(ctx, userID, sessionListLimit)
}

func (s *AuthService) AuditTrail(ctx context.Context, userID uuid.UUID) ([]domain.AuthEvent, error) {
	return s.audit.ListForUser(ctx, userID, auditListLimit)
}

// --- internals ---

// startSession opens a session and issues its first token pair. The session
// row is the durable login record; the audit event beside it is best-effort.
func (s *AuthService) startSession(ctx context.Context, user *domain.User, method domain.AuthMethod, client domain.ClientInfo) (port.TokenPair, error) {
	secret, err := newRefreshSecret()
	if err != nil {
		return port.TokenPair{}, err
	}
	session := domain.NewSession(user.ID, method, hashSecret(secret), client.IP, client.UserAgent, s.cfg.RefreshTTL)
	if err := s.sessions.Create(ctx, session); err != nil {
		return port.TokenPair{}, err
	}

	access, err := s.tokens.Issue(user.ID, session.ID)
	if err != nil {
		return port.TokenPair{}, fmt.Errorf("auth: issue access token: %w", err)
	}

	now := time.Now().UTC()
	if err := s.users.RecordLogin(ctx, user.ID, now); err != nil {
		// Report only what was saved: the response keeps the previous value.
		s.log.WarnContext(ctx, "could not record last login", "user_id", user.ID, "error", err)
	} else {
		user.LastLoginAt = &now
	}

	s.record(ctx, domain.AuthEvent{
		Type: domain.AuthEventLogin, UserID: &user.ID, SessionID: &session.ID,
		Method: method, Email: user.Email,
	}, client)

	return port.TokenPair{
		AccessToken:           access.Value,
		AccessTokenExpiresAt:  access.ExpiresAt,
		RefreshToken:          joinRefreshToken(session.ID, secret),
		RefreshTokenExpiresAt: session.ExpiresAt,
	}, nil
}

func (s *AuthService) revokeForReuse(ctx context.Context, session *domain.Session, client domain.ClientInfo) {
	session.Revoke(domain.RevokeTokenReuse)
	if err := s.sessions.Revoke(ctx, session); err != nil {
		s.log.ErrorContext(ctx, "could not revoke session after token reuse",
			"session_id", session.ID, "error", err)
		return
	}
	_ = s.deny(ctx, session.ID)
	s.record(ctx, domain.AuthEvent{
		Type: domain.AuthEventRefreshReuse, UserID: &session.UserID,
		SessionID: &session.ID, Method: session.Method,
		Detail: "a rotated refresh token was replayed; session revoked",
	}, client)
}

func (s *AuthService) failedLogin(ctx context.Context, userID *uuid.UUID, email, detail string, client domain.ClientInfo) {
	s.record(ctx, domain.AuthEvent{
		Type: domain.AuthEventLoginFailed, UserID: userID,
		Method: domain.AuthMethodPassword, Email: email, Detail: detail,
	}, client)
}

// deny pushes a session onto the Redis denylist, retrying transient failures.
//
// It matters that this succeeds: Authenticate only falls back to Postgres
// when Redis cannot *answer*, so a denylist write that silently failed would
// let that session's access token live on for the rest of its lifetime.
// Callers that can abort safely (account deletion) do so on error; the rest
// have already revoked the session row, and the error is logged for alerting.
func (s *AuthService) deny(ctx context.Context, sessionID uuid.UUID) error {
	const attempts = 3
	var err error
	for i := 0; i < attempts; i++ {
		if err = s.denylist.Deny(ctx, sessionID, s.tokens.TTL()+denylistMargin); err == nil {
			return nil
		}
		if i == attempts-1 {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(50<<i) * time.Millisecond):
		}
	}
	s.log.ErrorContext(ctx, "could not denylist session; its access token stays valid until it expires",
		"session_id", sessionID, "error", err)
	return err
}

// record writes an audit event. Failing to audit never fails the request:
// login and logout times are already durable on the session row.
func (s *AuthService) record(ctx context.Context, evt domain.AuthEvent, client domain.ClientInfo) {
	evt.ID = uuid.New()
	evt.IP = client.IP
	evt.UserAgent = client.UserAgent
	evt.OccurredAt = time.Now().UTC()
	if err := s.audit.Record(ctx, evt); err != nil {
		s.log.ErrorContext(ctx, "could not write audit event", "event", evt.Type, "error", err)
	}
}

// limit fails with ErrTooManyAttempts once key exceeds its budget. If the
// limiter itself is down it lets the request through: a Redis outage must not
// lock every user out, and the limits are a defence in depth, not the only
// one (bcrypt makes each guess expensive regardless).
func (s *AuthService) limit(ctx context.Context, key string, max int) error {
	if max <= 0 {
		return nil
	}
	ok, err := s.limiter.Allow(ctx, key, max, s.cfg.AttemptWindow)
	if err != nil {
		s.log.WarnContext(ctx, "rate limiter unavailable; allowing request", "key", key, "error", err)
		return nil
	}
	if !ok {
		return domain.ErrTooManyAttempts
	}
	return nil
}

// Refresh tokens are "<session id>.<secret>". The id lets the server find
// the session with one indexed read; only the secret's hash is stored.

func newRefreshSecret() ([]byte, error) {
	b := make([]byte, refreshSecretBytes)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("auth: generate refresh token: %w", err)
	}
	return b, nil
}

func joinRefreshToken(sessionID uuid.UUID, secret []byte) string {
	return sessionID.String() + "." + base64.RawURLEncoding.EncodeToString(secret)
}

func splitRefreshToken(token string) (uuid.UUID, []byte, error) {
	idPart, secretPart, ok := strings.Cut(token, ".")
	if !ok {
		return uuid.Nil, nil, errors.New("malformed refresh token")
	}
	id, err := uuid.Parse(idPart)
	if err != nil {
		return uuid.Nil, nil, err
	}
	secret, err := base64.RawURLEncoding.DecodeString(secretPart)
	if err != nil || len(secret) != refreshSecretBytes {
		return uuid.Nil, nil, errors.New("malformed refresh token")
	}
	return id, secret, nil
}

// hashSecret uses SHA-256, not bcrypt: the secret is 256 bits of randomness,
// so it cannot be brute-forced and a slow hash would only add latency.
func hashSecret(secret []byte) []byte {
	sum := sha256.Sum256(secret)
	return sum[:]
}

func constantTimeEqual(a, b []byte) bool {
	return len(a) > 0 && len(a) == len(b) && subtle.ConstantTimeCompare(a, b) == 1
}
