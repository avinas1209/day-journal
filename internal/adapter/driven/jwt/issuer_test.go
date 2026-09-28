package jwt

import (
	"errors"
	"strings"
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/avinas1209/day-journal/internal/core/domain"
)

const (
	secretA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	secretB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func newTestIssuer(t *testing.T, cfg Config) *Issuer {
	t.Helper()
	if cfg.Secret == "" {
		cfg.Secret = secretA
	}
	if cfg.Issuer == "" {
		cfg.Issuer = "day-journal"
	}
	if cfg.Audience == "" {
		cfg.Audience = "day-journal-api"
	}
	if cfg.TTL == 0 {
		cfg.TTL = 15 * time.Minute
	}
	iss, err := NewIssuer(cfg)
	if err != nil {
		t.Fatalf("new issuer: %v", err)
	}
	return iss
}

func TestIssueThenVerifyRoundTrips(t *testing.T) {
	iss := newTestIssuer(t, Config{})
	user, session := uuid.New(), uuid.New()

	tok, err := iss.Issue(user, session)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	claims, err := iss.Verify(tok.Value)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.UserID != user || claims.SessionID != session {
		t.Errorf("claims = %+v, want user %s session %s", claims, user, session)
	}
}

func TestRejectsATokenSignedWithAnotherSecret(t *testing.T) {
	tok, _ := newTestIssuer(t, Config{Secret: secretB}).Issue(uuid.New(), uuid.New())
	if _, err := newTestIssuer(t, Config{}).Verify(tok.Value); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("err = %v, want ErrUnauthenticated", err)
	}
}

func TestRejectsATamperedPayload(t *testing.T) {
	iss := newTestIssuer(t, Config{})
	tok, _ := iss.Issue(uuid.New(), uuid.New())

	parts := strings.Split(tok.Value, ".")
	other, _ := iss.Issue(uuid.New(), uuid.New())
	parts[1] = strings.Split(other.Value, ".")[1] // someone else's claims, our signature
	if _, err := iss.Verify(strings.Join(parts, ".")); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("err = %v, want ErrUnauthenticated", err)
	}
}

// The classic JWT attack: declare no algorithm and send no signature.
func TestRejectsAlgNone(t *testing.T) {
	iss := newTestIssuer(t, Config{})
	unsigned := gojwt.NewWithClaims(gojwt.SigningMethodNone, claims{
		SessionID: uuid.NewString(),
		RegisteredClaims: gojwt.RegisteredClaims{
			Issuer: "day-journal", Subject: uuid.NewString(),
			Audience:  gojwt.ClaimStrings{"day-journal-api"},
			ExpiresAt: gojwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	})
	raw, err := unsigned.SignedString(gojwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("build unsigned token: %v", err)
	}
	if _, err := iss.Verify(raw); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("err = %v, want alg=none rejected", err)
	}
}

func TestRejectsAnExpiredToken(t *testing.T) {
	// A negative TTL is refused by NewIssuer, so build an already-expired
	// token by hand with the right key.
	iss := newTestIssuer(t, Config{})
	expired := gojwt.NewWithClaims(gojwt.SigningMethodHS256, claims{
		SessionID: uuid.NewString(),
		RegisteredClaims: gojwt.RegisteredClaims{
			Issuer: "day-journal", Subject: uuid.NewString(),
			Audience:  gojwt.ClaimStrings{"day-journal-api"},
			IssuedAt:  gojwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
			ExpiresAt: gojwt.NewNumericDate(time.Now().Add(-time.Hour)),
		},
	})
	expired.Header["kid"] = keyID(secretA)
	raw, _ := expired.SignedString([]byte(secretA))

	if _, err := iss.Verify(raw); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("err = %v, want an expired token rejected", err)
	}
}

func TestRejectsATokenForAnotherAudience(t *testing.T) {
	tok, _ := newTestIssuer(t, Config{Audience: "some-other-api"}).Issue(uuid.New(), uuid.New())
	if _, err := newTestIssuer(t, Config{}).Verify(tok.Value); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("err = %v, want a foreign audience rejected", err)
	}
}

// Rotating the secret must not sign everyone out: tokens from the old key
// keep verifying until they expire, while new tokens use the new key.
func TestKeyRotationKeepsOldTokensValid(t *testing.T) {
	before := newTestIssuer(t, Config{Secret: secretA})
	oldToken, _ := before.Issue(uuid.New(), uuid.New())

	after := newTestIssuer(t, Config{Secret: secretB, PreviousSecrets: []string{secretA}})
	if _, err := after.Verify(oldToken.Value); err != nil {
		t.Fatalf("old token rejected after rotation: %v", err)
	}
	newToken, _ := after.Issue(uuid.New(), uuid.New())
	if _, err := before.Verify(newToken.Value); err == nil {
		t.Fatal("new token verified with the retired key only; it should be signed with the new key")
	}
}

func TestRefusesAShortSecret(t *testing.T) {
	if _, err := NewIssuer(Config{Secret: "too-short", TTL: time.Minute}); err == nil {
		t.Fatal("want an error for a secret under 32 bytes")
	}
}
