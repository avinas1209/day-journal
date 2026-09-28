package service_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/avinas1209/day-journal/internal/core/domain"
	"github.com/avinas1209/day-journal/internal/core/port"
	"github.com/avinas1209/day-journal/internal/core/service"
)

type authFixture struct {
	svc      *service.AuthService
	users    *fakeUsers
	sessions *fakeSessions
	audit    *fakeAudit
	denylist *fakeDenylist
	limiter  *fakeLimiter
	google   *fakeGoogle
}

var client = domain.ClientInfo{IP: "203.0.113.7", UserAgent: "DayJournal/1.0 iOS"}

func newAuthFixture(t *testing.T, withGoogle bool) *authFixture {
	t.Helper()
	f := &authFixture{
		users:    newFakeUsers(),
		sessions: newFakeSessions(),
		audit:    &fakeAudit{},
		denylist: newFakeDenylist(),
		limiter:  newFakeLimiter(),
		google:   &fakeGoogle{identities: map[string]domain.GoogleIdentity{}},
	}
	deps := service.AuthDeps{
		Users: f.users, Sessions: f.sessions, Audit: f.audit,
		Hasher: fakeHasher{}, Tokens: fakeTokens{ttl: 15 * time.Minute},
		Denylist: f.denylist, Limiter: f.limiter,
	}
	if withGoogle {
		deps.Google = f.google
	}
	svc, err := service.NewAuthService(deps, service.DefaultAuthConfig(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("new auth service: %v", err)
	}
	f.svc = svc
	return f
}

func (f *authFixture) register(t *testing.T, email, password string) port.AuthResult {
	t.Helper()
	res, err := f.svc.Register(context.Background(), port.RegisterCommand{
		Email: email, Password: password, DisplayName: "Test User", Client: client,
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	return res
}

// --- registration ---

func TestRegisterCreatesAccountAndSignsIn(t *testing.T) {
	f := newAuthFixture(t, false)
	res := f.register(t, "  Ada@Example.COM ", "correct horse")

	if res.User.Email != "ada@example.com" {
		t.Errorf("email = %q, want it normalised", res.User.Email)
	}
	if !res.Created {
		t.Error("Created = false, want true for a new account")
	}
	if res.Tokens.AccessToken == "" || res.Tokens.RefreshToken == "" {
		t.Fatal("expected both tokens to be issued")
	}
	if res.User.PasswordHash == "correct horse" {
		t.Fatal("password stored in plain text")
	}
	if f.audit.count(domain.AuthEventRegistered) != 1 || f.audit.count(domain.AuthEventLogin) != 1 {
		t.Errorf("audit = %v, want one registered and one login", f.audit.types())
	}
}

func TestRegisterRejectsDuplicateEmailWhateverTheCase(t *testing.T) {
	f := newAuthFixture(t, false)
	f.register(t, "ada@example.com", "correct horse")

	_, err := f.svc.Register(context.Background(), port.RegisterCommand{
		Email: "ADA@example.com", Password: "another password", Client: client,
	})
	if !errors.Is(err, domain.ErrEmailTaken) {
		t.Fatalf("err = %v, want ErrEmailTaken", err)
	}
}

func TestRegisterEnforcesPasswordPolicy(t *testing.T) {
	f := newAuthFixture(t, false)
	for name, pw := range map[string]string{
		"too short":  "short",
		"whitespace": "          ",
		"over 72b":   strings.Repeat("x", 73),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := f.svc.Register(context.Background(), port.RegisterCommand{
				Email: "p@example.com", Password: pw, Client: client,
			})
			var vErr domain.ValidationError
			if !errors.As(err, &vErr) || vErr.Field != "password" {
				t.Fatalf("err = %v, want a validation error on password", err)
			}
		})
	}
}

func TestRegisterRejectsMalformedEmail(t *testing.T) {
	f := newAuthFixture(t, false)
	for _, email := range []string{"", "not-an-email", "Ada <ada@example.com>"} {
		_, err := f.svc.Register(context.Background(), port.RegisterCommand{
			Email: email, Password: "correct horse", Client: client,
		})
		var vErr domain.ValidationError
		if !errors.As(err, &vErr) || vErr.Field != "email" {
			t.Errorf("email %q: err = %v, want a validation error on email", email, err)
		}
	}
}

// --- password login ---

func TestLoginSucceedsWithTheRightPassword(t *testing.T) {
	f := newAuthFixture(t, false)
	f.register(t, "ada@example.com", "correct horse")

	res, err := f.svc.Login(context.Background(), port.LoginCommand{
		Email: "ADA@example.com", Password: "correct horse", Client: client,
	})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if res.Created {
		t.Error("Created = true on a login, want false")
	}
	if res.User.LastLoginAt == nil {
		t.Error("LastLoginAt not recorded")
	}
}

// A wrong password and an unknown email must be indistinguishable, or the
// endpoint becomes a way to discover who has an account.
func TestLoginFailuresAreIndistinguishable(t *testing.T) {
	f := newAuthFixture(t, false)
	f.register(t, "ada@example.com", "correct horse")

	_, wrongPassword := f.svc.Login(context.Background(), port.LoginCommand{
		Email: "ada@example.com", Password: "wrong password", Client: client,
	})
	_, unknownEmail := f.svc.Login(context.Background(), port.LoginCommand{
		Email: "nobody@example.com", Password: "whatever12", Client: client,
	})

	if !errors.Is(wrongPassword, domain.ErrInvalidCredentials) || !errors.Is(unknownEmail, domain.ErrInvalidCredentials) {
		t.Fatalf("errors = %v / %v, want ErrInvalidCredentials for both", wrongPassword, unknownEmail)
	}
	if wrongPassword.Error() != unknownEmail.Error() {
		t.Errorf("messages differ: %q vs %q", wrongPassword, unknownEmail)
	}
	if n := f.audit.count(domain.AuthEventLoginFailed); n != 2 {
		t.Errorf("login_failed events = %d, want 2 (both attempts audited)", n)
	}
}

func TestPasswordLoginToAGoogleOnlyAccountIsRefusedGenerically(t *testing.T) {
	f := newAuthFixture(t, true)
	f.google.identities["tok"] = domain.GoogleIdentity{Subject: "g-1", Email: "g@example.com", EmailVerified: true}
	if _, err := f.svc.LoginWithGoogle(context.Background(), port.GoogleLoginCommand{IDToken: "tok", Client: client}); err != nil {
		t.Fatalf("google sign-up: %v", err)
	}

	_, err := f.svc.Login(context.Background(), port.LoginCommand{
		Email: "g@example.com", Password: "anything123", Client: client,
	})
	if !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Fatalf("err = %v, want the same ErrInvalidCredentials as a wrong password", err)
	}
}

func TestLoginIsRateLimitedPerEmailAndIP(t *testing.T) {
	f := newAuthFixture(t, false)
	f.register(t, "ada@example.com", "correct horse")

	var err error
	for i := 0; i < service.DefaultAuthConfig().LoginAttemptsPerEmailIP+1; i++ {
		_, err = f.svc.Login(context.Background(), port.LoginCommand{
			Email: "ada@example.com", Password: "wrong password", Client: client,
		})
	}
	if !errors.Is(err, domain.ErrTooManyAttempts) {
		t.Fatalf("err = %v, want ErrTooManyAttempts once the budget is spent", err)
	}
}

// Knowing someone's email must not be enough to lock them out: a stranger
// burning through the budget from their own IP leaves the owner's IP free.
func TestAStrangerCannotLockTheOwnerOut(t *testing.T) {
	f := newAuthFixture(t, false)
	f.register(t, "ada@example.com", "correct horse")

	attacker := domain.ClientInfo{IP: "198.51.100.66", UserAgent: "curl"}
	for i := 0; i < service.DefaultAuthConfig().LoginAttemptsPerEmailIP+5; i++ {
		_, _ = f.svc.Login(context.Background(), port.LoginCommand{
			Email: "ada@example.com", Password: "guess", Client: attacker,
		})
	}

	if _, err := f.svc.Login(context.Background(), port.LoginCommand{
		Email: "ada@example.com", Password: "correct horse", Client: client,
	}); err != nil {
		t.Fatalf("owner login: %v, want it unaffected by the attacker's attempts", err)
	}
}

func TestMalformedRegistrationsDoNotSpendTheIPBudget(t *testing.T) {
	f := newAuthFixture(t, false)
	for i := 0; i < service.DefaultAuthConfig().RegistrationsPerIP+5; i++ {
		_, _ = f.svc.Register(context.Background(), port.RegisterCommand{
			Email: "not-an-email", Password: "correct horse", Client: client,
		})
	}
	f.register(t, "real@example.com", "correct horse")
}

// A Redis outage must degrade to "no rate limiting", never to "no logins".
func TestLoginStillWorksWhenTheRateLimiterIsDown(t *testing.T) {
	f := newAuthFixture(t, false)
	f.register(t, "ada@example.com", "correct horse")
	f.limiter.err = errors.New("redis down")

	if _, err := f.svc.Login(context.Background(), port.LoginCommand{
		Email: "ada@example.com", Password: "correct horse", Client: client,
	}); err != nil {
		t.Fatalf("login: %v, want it allowed while the limiter is unavailable", err)
	}
}

// --- tokens ---

func TestAuthenticateAcceptsAFreshAccessToken(t *testing.T) {
	f := newAuthFixture(t, false)
	res := f.register(t, "ada@example.com", "correct horse")

	p, err := f.svc.Authenticate(context.Background(), res.Tokens.AccessToken)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if p.UserID != res.User.ID {
		t.Errorf("user = %s, want %s", p.UserID, res.User.ID)
	}
}

func TestAuthenticateRejectsGarbage(t *testing.T) {
	f := newAuthFixture(t, false)
	if _, err := f.svc.Authenticate(context.Background(), "not.a.token"); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("err = %v, want ErrUnauthenticated", err)
	}
}

func TestRefreshRotatesTheToken(t *testing.T) {
	f := newAuthFixture(t, false)
	res := f.register(t, "ada@example.com", "correct horse")

	next, err := f.svc.Refresh(context.Background(), res.Tokens.RefreshToken, client)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if next.RefreshToken == res.Tokens.RefreshToken {
		t.Error("refresh token was not rotated")
	}
	if _, err := f.svc.Refresh(context.Background(), next.RefreshToken, client); err != nil {
		t.Fatalf("second refresh with the new token: %v", err)
	}
}

// Replaying a rotated refresh token is the signature of theft, so it must
// end the session outright — including the attacker's copy.
func TestReplayingARotatedRefreshTokenRevokesTheSession(t *testing.T) {
	f := newAuthFixture(t, false)
	res := f.register(t, "ada@example.com", "correct horse")

	next, err := f.svc.Refresh(context.Background(), res.Tokens.RefreshToken, client)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}

	// The stale token comes back.
	if _, err := f.svc.Refresh(context.Background(), res.Tokens.RefreshToken, client); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("replay err = %v, want ErrUnauthenticated", err)
	}
	// And now even the legitimate newest token is dead.
	if _, err := f.svc.Refresh(context.Background(), next.RefreshToken, client); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("post-replay err = %v, want the whole session revoked", err)
	}
	if f.audit.count(domain.AuthEventRefreshReuse) != 1 {
		t.Errorf("audit = %v, want a refresh_token_reuse event", f.audit.types())
	}
}

// The session id is readable inside any JWT. Knowing it plus a made-up
// secret must not be enough to log someone out.
func TestAForgedRefreshSecretDoesNotRevokeTheSession(t *testing.T) {
	f := newAuthFixture(t, false)
	res := f.register(t, "ada@example.com", "correct horse")

	sessionID, _, _ := strings.Cut(res.Tokens.RefreshToken, ".")
	forged := sessionID + ".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if _, err := f.svc.Refresh(context.Background(), forged, client); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("forged err = %v, want ErrUnauthenticated", err)
	}
	if _, err := f.svc.Refresh(context.Background(), res.Tokens.RefreshToken, client); err != nil {
		t.Fatalf("genuine refresh after forgery: %v, want the session untouched", err)
	}
}

// --- logout ---

func TestLogoutEndsTheSessionAndRecordsTheTime(t *testing.T) {
	f := newAuthFixture(t, false)
	res := f.register(t, "ada@example.com", "correct horse")
	p, _ := f.svc.Authenticate(context.Background(), res.Tokens.AccessToken)

	if err := f.svc.Logout(context.Background(), p, client); err != nil {
		t.Fatalf("logout: %v", err)
	}

	if _, err := f.svc.Authenticate(context.Background(), res.Tokens.AccessToken); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Errorf("access token still accepted after logout: %v", err)
	}
	if _, err := f.svc.Refresh(context.Background(), res.Tokens.RefreshToken, client); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Errorf("refresh token still accepted after logout: %v", err)
	}

	s, _ := f.sessions.FindByID(context.Background(), p.SessionID)
	if s.RevokedAt == nil || s.RevokeReason != domain.RevokeLogout {
		t.Errorf("session = revoked_at %v reason %q, want a logout time recorded", s.RevokedAt, s.RevokeReason)
	}
	if !s.RevokedAt.After(s.CreatedAt) && !s.RevokedAt.Equal(s.CreatedAt) {
		t.Error("logout time precedes login time")
	}
	if f.audit.count(domain.AuthEventLogout) != 1 {
		t.Errorf("audit = %v, want one logout event", f.audit.types())
	}
}

func TestLogoutIsIdempotent(t *testing.T) {
	f := newAuthFixture(t, false)
	res := f.register(t, "ada@example.com", "correct horse")
	p, _ := f.svc.Authenticate(context.Background(), res.Tokens.AccessToken)

	for i := 0; i < 2; i++ {
		if err := f.svc.Logout(context.Background(), p, client); err != nil {
			t.Fatalf("logout #%d: %v", i+1, err)
		}
	}
	if n := f.audit.count(domain.AuthEventLogout); n != 1 {
		t.Errorf("logout events = %d, want one — the second call was a no-op", n)
	}
}

func TestLogoutAllEndsEverySession(t *testing.T) {
	f := newAuthFixture(t, false)
	phone := f.register(t, "ada@example.com", "correct horse")
	laptop, err := f.svc.Login(context.Background(), port.LoginCommand{
		Email: "ada@example.com", Password: "correct horse", Client: client,
	})
	if err != nil {
		t.Fatalf("second login: %v", err)
	}

	p, _ := f.svc.Authenticate(context.Background(), phone.Tokens.AccessToken)
	if err := f.svc.LogoutAll(context.Background(), p, client); err != nil {
		t.Fatalf("logout all: %v", err)
	}

	for name, tok := range map[string]string{"phone": phone.Tokens.AccessToken, "laptop": laptop.Tokens.AccessToken} {
		if _, err := f.svc.Authenticate(context.Background(), tok); !errors.Is(err, domain.ErrUnauthenticated) {
			t.Errorf("%s still signed in after logout-all", name)
		}
	}
}

// If Redis cannot answer, Postgres decides — a logged-out token must never
// slip through just because the cache is down.
func TestLoggedOutTokenIsRejectedEvenWhenTheDenylistIsDown(t *testing.T) {
	f := newAuthFixture(t, false)
	res := f.register(t, "ada@example.com", "correct horse")
	p, _ := f.svc.Authenticate(context.Background(), res.Tokens.AccessToken)
	if err := f.svc.Logout(context.Background(), p, client); err != nil {
		t.Fatalf("logout: %v", err)
	}

	f.denylist.err = errors.New("redis down")
	if _, err := f.svc.Authenticate(context.Background(), res.Tokens.AccessToken); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("err = %v, want the session store to reject the logged-out token", err)
	}
}

func TestSignedInUserStillWorksWhenTheDenylistIsDown(t *testing.T) {
	f := newAuthFixture(t, false)
	res := f.register(t, "ada@example.com", "correct horse")
	f.denylist.err = errors.New("redis down")

	if _, err := f.svc.Authenticate(context.Background(), res.Tokens.AccessToken); err != nil {
		t.Fatalf("authenticate: %v, want a live session accepted via the session store", err)
	}
}

// --- google ---

func TestGoogleSignInCreatesANewAccount(t *testing.T) {
	f := newAuthFixture(t, true)
	f.google.identities["tok"] = domain.GoogleIdentity{
		Subject: "g-42", Email: "Grace@Example.com", EmailVerified: true, Name: "Grace Hopper",
	}

	res, err := f.svc.LoginWithGoogle(context.Background(), port.GoogleLoginCommand{IDToken: "tok", Client: client})
	if err != nil {
		t.Fatalf("google: %v", err)
	}
	if !res.Created || res.User.DisplayName != "Grace Hopper" || res.User.Email != "grace@example.com" {
		t.Errorf("user = %+v created=%v, want a new, normalised account", res.User, res.Created)
	}
	if res.User.HasPassword() {
		t.Error("a Google account should have no password")
	}
}

func TestGoogleSignInReturnsTheSameAccountNextTime(t *testing.T) {
	f := newAuthFixture(t, true)
	f.google.identities["tok"] = domain.GoogleIdentity{Subject: "g-42", Email: "grace@example.com", EmailVerified: true}

	first, _ := f.svc.LoginWithGoogle(context.Background(), port.GoogleLoginCommand{IDToken: "tok", Client: client})
	second, err := f.svc.LoginWithGoogle(context.Background(), port.GoogleLoginCommand{IDToken: "tok", Client: client})
	if err != nil {
		t.Fatalf("second google sign-in: %v", err)
	}
	if second.User.ID != first.User.ID || second.Created {
		t.Error("second sign-in created a new account")
	}
}

func TestGoogleSignInLinksAnExistingPasswordAccount(t *testing.T) {
	f := newAuthFixture(t, true)
	existing := f.register(t, "ada@example.com", "correct horse")
	f.google.identities["tok"] = domain.GoogleIdentity{Subject: "g-7", Email: "ada@example.com", EmailVerified: true}

	res, err := f.svc.LoginWithGoogle(context.Background(), port.GoogleLoginCommand{IDToken: "tok", Client: client})
	if err != nil {
		t.Fatalf("google: %v", err)
	}
	if res.User.ID != existing.User.ID || res.Created {
		t.Fatal("expected the existing account to be linked, not a new one created")
	}
	if !res.User.HasPassword() || res.User.GoogleSubject != "g-7" {
		t.Error("linked account should keep its password and gain the Google identity")
	}
	if f.audit.count(domain.AuthEventGoogleLinked) != 1 {
		t.Errorf("audit = %v, want a google_linked event", f.audit.types())
	}
}

// Otherwise anyone could create a Google login with someone else's address
// and take over their journal.
func TestGoogleSignInWithAnUnverifiedEmailCannotClaimAnAccount(t *testing.T) {
	f := newAuthFixture(t, true)
	f.register(t, "ada@example.com", "correct horse")
	f.google.identities["tok"] = domain.GoogleIdentity{Subject: "g-evil", Email: "ada@example.com", EmailVerified: false}

	_, err := f.svc.LoginWithGoogle(context.Background(), port.GoogleLoginCommand{IDToken: "tok", Client: client})
	if !errors.Is(err, domain.ErrGoogleEmailUnverified) {
		t.Fatalf("err = %v, want ErrGoogleEmailUnverified", err)
	}
}

func TestGoogleSignInRejectsAnInvalidToken(t *testing.T) {
	f := newAuthFixture(t, true)
	_, err := f.svc.LoginWithGoogle(context.Background(), port.GoogleLoginCommand{IDToken: "forged", Client: client})
	if !errors.Is(err, domain.ErrGoogleTokenInvalid) {
		t.Fatalf("err = %v, want ErrGoogleTokenInvalid", err)
	}
}

func TestGoogleSignInIsUnavailableWhenNotConfigured(t *testing.T) {
	f := newAuthFixture(t, false)
	_, err := f.svc.LoginWithGoogle(context.Background(), port.GoogleLoginCommand{IDToken: "tok", Client: client})
	if !errors.Is(err, domain.ErrGoogleNotConfigured) {
		t.Fatalf("err = %v, want ErrGoogleNotConfigured", err)
	}
}

// --- account ---

func TestSessionsListLoginHistoryNewestFirst(t *testing.T) {
	f := newAuthFixture(t, false)
	res := f.register(t, "ada@example.com", "correct horse")
	time.Sleep(2 * time.Millisecond)
	if _, err := f.svc.Login(context.Background(), port.LoginCommand{
		Email: "ada@example.com", Password: "correct horse", Client: client,
	}); err != nil {
		t.Fatalf("login: %v", err)
	}

	sessions, err := f.svc.Sessions(context.Background(), res.User.ID)
	if err != nil {
		t.Fatalf("sessions: %v", err)
	}
	if len(sessions) != 2 {
		t.Fatalf("sessions = %d, want 2", len(sessions))
	}
	if sessions[0].CreatedAt.Before(sessions[1].CreatedAt) {
		t.Error("sessions not newest first")
	}
	if sessions[0].IP != client.IP || sessions[0].UserAgent != client.UserAgent {
		t.Error("session did not capture the client's IP and user agent")
	}
}

func TestUpdateProfileRenames(t *testing.T) {
	f := newAuthFixture(t, false)
	res := f.register(t, "ada@example.com", "correct horse")

	u, err := f.svc.UpdateProfile(context.Background(), res.User.ID, "  Ada Lovelace ")
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if u.DisplayName != "Ada Lovelace" {
		t.Errorf("display name = %q", u.DisplayName)
	}
	if _, err := f.svc.UpdateProfile(context.Background(), res.User.ID, "   "); !errors.Is(err, domain.ErrValidation) {
		t.Errorf("blank name err = %v, want a validation error", err)
	}
}

// --- account deletion ---

func (f *authFixture) principal(t *testing.T, res port.AuthResult) port.Principal {
	t.Helper()
	p, err := f.svc.Authenticate(context.Background(), res.Tokens.AccessToken)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	return p
}

func TestDeleteAccountRemovesTheUserAndEndsEverySession(t *testing.T) {
	f := newAuthFixture(t, false)
	phone := f.register(t, "ada@example.com", "correct horse")
	laptop, _ := f.svc.Login(context.Background(), port.LoginCommand{
		Email: "ada@example.com", Password: "correct horse", Client: client,
	})

	err := f.svc.DeleteAccount(context.Background(), port.DeleteAccountCommand{
		Principal: f.principal(t, phone), Password: "correct horse", Client: client,
	})
	if err != nil {
		t.Fatalf("delete: %v", err)
	}

	if _, err := f.users.FindByID(context.Background(), phone.User.ID); !errors.Is(err, domain.ErrUserNotFound) {
		t.Error("user still exists after deletion")
	}
	// Both devices' tokens die at once, not 15 minutes later.
	for name, tok := range map[string]string{"phone": phone.Tokens.AccessToken, "laptop": laptop.Tokens.AccessToken} {
		if _, err := f.svc.Authenticate(context.Background(), tok); !errors.Is(err, domain.ErrUnauthenticated) {
			t.Errorf("%s token still accepted after deletion", name)
		}
	}
	// The email is free to register again.
	f.register(t, "ada@example.com", "a new password")
}

func TestDeleteAccountScrubsPersonalDataFromTheAuditTrail(t *testing.T) {
	f := newAuthFixture(t, false)
	res := f.register(t, "ada@example.com", "correct horse")

	if err := f.svc.DeleteAccount(context.Background(), port.DeleteAccountCommand{
		Principal: f.principal(t, res), Password: "correct horse", Client: client,
	}); err != nil {
		t.Fatalf("delete: %v", err)
	}

	events := f.audit.forUser(res.User.ID)
	if len(events) == 0 {
		t.Fatal("the security timeline should survive deletion")
	}
	sawDeletion := false
	for _, e := range events {
		if e.Email != "" || e.IP != "" || e.UserAgent != "" {
			t.Errorf("event %s still carries personal data: %+v", e.Type, e)
		}
		if e.Type == domain.AuthEventAccountDeleted {
			sawDeletion = true
		}
	}
	if !sawDeletion {
		t.Error("no account_deleted event recorded")
	}
}

func TestDeleteAccountNeedsThePassword(t *testing.T) {
	f := newAuthFixture(t, false)
	res := f.register(t, "ada@example.com", "correct horse")
	p := f.principal(t, res)

	err := f.svc.DeleteAccount(context.Background(), port.DeleteAccountCommand{Principal: p, Client: client})
	if !errors.Is(err, domain.ErrReauthRequired) {
		t.Fatalf("no password: err = %v, want ErrReauthRequired", err)
	}

	err = f.svc.DeleteAccount(context.Background(), port.DeleteAccountCommand{Principal: p, Password: "wrong", Client: client})
	if !errors.Is(err, domain.ErrReauthFailed) {
		t.Fatalf("wrong password: err = %v, want ErrReauthFailed", err)
	}
	if f.audit.count(domain.AuthEventReauthFailed) != 1 {
		t.Errorf("audit = %v, want the failed confirmation recorded", f.audit.types())
	}
	if _, err := f.users.FindByID(context.Background(), res.User.ID); err != nil {
		t.Fatal("account deleted despite a wrong password")
	}
	if _, err := f.svc.Authenticate(context.Background(), res.Tokens.AccessToken); err != nil {
		t.Fatal("a wrong password must not end the session")
	}
}

func TestDeleteAccountCannotBeUsedToBruteForceThePassword(t *testing.T) {
	f := newAuthFixture(t, false)
	res := f.register(t, "ada@example.com", "correct horse")
	p := f.principal(t, res)

	var err error
	for i := 0; i < service.DefaultAuthConfig().DeleteAttemptsPerUser+1; i++ {
		err = f.svc.DeleteAccount(context.Background(), port.DeleteAccountCommand{Principal: p, Password: "guess", Client: client})
	}
	if !errors.Is(err, domain.ErrTooManyAttempts) {
		t.Fatalf("err = %v, want ErrTooManyAttempts", err)
	}
}

func TestDeleteGoogleAccountConfirmsWithTheSameGoogleAccount(t *testing.T) {
	f := newAuthFixture(t, true)
	f.google.identities["signin"] = domain.GoogleIdentity{Subject: "g-1", Email: "g@example.com", EmailVerified: true}
	f.google.identities["same"] = domain.GoogleIdentity{Subject: "g-1", Email: "g@example.com", EmailVerified: true}
	f.google.identities["other"] = domain.GoogleIdentity{Subject: "g-2", Email: "x@example.com", EmailVerified: true}
	res, _ := f.svc.LoginWithGoogle(context.Background(), port.GoogleLoginCommand{IDToken: "signin", Client: client})
	p := f.principal(t, res)

	// No password exists to check, and someone else's Google account proves nothing.
	if err := f.svc.DeleteAccount(context.Background(), port.DeleteAccountCommand{Principal: p, Password: "anything", Client: client}); !errors.Is(err, domain.ErrReauthRequired) {
		t.Fatalf("password on a Google account: err = %v, want ErrReauthRequired", err)
	}
	if err := f.svc.DeleteAccount(context.Background(), port.DeleteAccountCommand{Principal: p, GoogleIDToken: "other", Client: client}); !errors.Is(err, domain.ErrReauthFailed) {
		t.Fatalf("other Google account: err = %v, want ErrReauthFailed", err)
	}

	if err := f.svc.DeleteAccount(context.Background(), port.DeleteAccountCommand{Principal: p, GoogleIDToken: "same", Client: client}); err != nil {
		t.Fatalf("delete with the same Google account: %v", err)
	}
}

// A single failed denylist write used to be logged and ignored, leaving that
// session's access token valid for a deleted account.
func TestDeleteAccountAbortsIfASessionCannotBeDenylisted(t *testing.T) {
	f := newAuthFixture(t, false)
	res := f.register(t, "ada@example.com", "correct horse")
	p := f.principal(t, res)
	f.denylist.denyFailures = 100 // Redis keeps refusing writes

	err := f.svc.DeleteAccount(context.Background(), port.DeleteAccountCommand{
		Principal: p, Password: "correct horse", Client: client,
	})
	if err == nil {
		t.Fatal("want deletion to fail rather than leave a live token")
	}
	if _, err := f.users.FindByID(context.Background(), res.User.ID); err != nil {
		t.Fatal("account was deleted even though its session could not be ended")
	}
}

func TestATransientDenylistFailureIsRetried(t *testing.T) {
	f := newAuthFixture(t, false)
	res := f.register(t, "ada@example.com", "correct horse")
	p := f.principal(t, res)
	f.denylist.denyFailures = 2 // fails twice, then recovers

	if err := f.svc.DeleteAccount(context.Background(), port.DeleteAccountCommand{
		Principal: p, Password: "correct horse", Client: client,
	}); err != nil {
		t.Fatalf("delete: %v, want the retry to succeed", err)
	}
	if _, err := f.svc.Authenticate(context.Background(), res.Tokens.AccessToken); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Error("token still accepted after deletion")
	}
}
