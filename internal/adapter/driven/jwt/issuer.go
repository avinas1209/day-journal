// Package jwt implements port.TokenIssuer with HMAC-SHA256 signed JWTs.
package jwt

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/avinas1209/day-journal/internal/core/domain"
	"github.com/avinas1209/day-journal/internal/core/port"
)

// minSecretBytes matches HS256's output size; a shorter key weakens it.
const minSecretBytes = 32

// leeway absorbs clock drift between the server that issued a token and the
// one verifying it.
const leeway = 30 * time.Second

type Config struct {
	// Secret signs new tokens.
	Secret string
	// PreviousSecrets still verify tokens but never sign. Moving the old
	// secret here during a rotation keeps existing sessions alive until
	// their access tokens expire naturally.
	PreviousSecrets []string
	Issuer          string
	Audience        string
	TTL             time.Duration
}

// Issuer implements port.TokenIssuer.
type Issuer struct {
	signingKey []byte
	signingKID string
	keys       map[string][]byte // kid -> secret, for verification
	issuer     string
	audience   string
	ttl        time.Duration
}

var _ port.TokenIssuer = (*Issuer)(nil)

type claims struct {
	SessionID string `json:"sid"`
	gojwt.RegisteredClaims
}

func NewIssuer(cfg Config) (*Issuer, error) {
	if len(cfg.Secret) < minSecretBytes {
		return nil, fmt.Errorf("jwt: secret must be at least %d bytes", minSecretBytes)
	}
	if cfg.TTL <= 0 {
		return nil, errors.New("jwt: ttl must be positive")
	}

	iss := &Issuer{
		signingKey: []byte(cfg.Secret),
		signingKID: keyID(cfg.Secret),
		keys:       map[string][]byte{keyID(cfg.Secret): []byte(cfg.Secret)},
		issuer:     cfg.Issuer,
		audience:   cfg.Audience,
		ttl:        cfg.TTL,
	}
	for _, s := range cfg.PreviousSecrets {
		if len(s) < minSecretBytes {
			return nil, fmt.Errorf("jwt: previous secret must be at least %d bytes", minSecretBytes)
		}
		iss.keys[keyID(s)] = []byte(s)
	}
	return iss, nil
}

func (i *Issuer) TTL() time.Duration { return i.ttl }

func (i *Issuer) Issue(userID, sessionID uuid.UUID) (port.AccessToken, error) {
	now := time.Now().UTC()
	exp := now.Add(i.ttl)

	token := gojwt.NewWithClaims(gojwt.SigningMethodHS256, claims{
		SessionID: sessionID.String(),
		RegisteredClaims: gojwt.RegisteredClaims{
			Issuer:    i.issuer,
			Subject:   userID.String(),
			Audience:  gojwt.ClaimStrings{i.audience},
			IssuedAt:  gojwt.NewNumericDate(now),
			NotBefore: gojwt.NewNumericDate(now),
			ExpiresAt: gojwt.NewNumericDate(exp),
			ID:        uuid.NewString(),
		},
	})
	token.Header["kid"] = i.signingKID

	signed, err := token.SignedString(i.signingKey)
	if err != nil {
		return port.AccessToken{}, fmt.Errorf("jwt: sign: %w", err)
	}
	return port.AccessToken{Value: signed, ExpiresAt: exp}, nil
}

func (i *Issuer) Verify(raw string) (port.AccessClaims, error) {
	var c claims
	_, err := gojwt.ParseWithClaims(raw, &c, i.keyFor,
		// Pinning the algorithm closes the classic "alg: none" and
		// RS/HS confusion attacks.
		gojwt.WithValidMethods([]string{gojwt.SigningMethodHS256.Alg()}),
		gojwt.WithIssuer(i.issuer),
		gojwt.WithAudience(i.audience),
		gojwt.WithExpirationRequired(),
		gojwt.WithIssuedAt(),
		gojwt.WithLeeway(leeway),
	)
	if err != nil {
		return port.AccessClaims{}, domain.ErrUnauthenticated
	}

	userID, err := uuid.Parse(c.Subject)
	if err != nil {
		return port.AccessClaims{}, domain.ErrUnauthenticated
	}
	sessionID, err := uuid.Parse(c.SessionID)
	if err != nil {
		return port.AccessClaims{}, domain.ErrUnauthenticated
	}
	return port.AccessClaims{UserID: userID, SessionID: sessionID, ExpiresAt: c.ExpiresAt.Time}, nil
}

func (i *Issuer) keyFor(t *gojwt.Token) (any, error) {
	kid, _ := t.Header["kid"].(string)
	key, ok := i.keys[kid]
	if !ok {
		return nil, errors.New("jwt: unknown key id")
	}
	return key, nil
}

// keyID names a secret without revealing it: the first 8 bytes of its hash.
func keyID(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:8])
}
