// Package google verifies Google Sign-In ID tokens.
package google

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/api/idtoken"

	"github.com/avinas1209/day-journal/internal/core/domain"
	"github.com/avinas1209/day-journal/internal/core/port"
)

// Verifier implements port.GoogleVerifier using Google's official validator,
// which checks the signature against Google's rotating public keys (cached),
// the issuer, and the expiry.
type Verifier struct {
	validator *idtoken.Validator
	audiences map[string]struct{}
}

var _ port.GoogleVerifier = (*Verifier)(nil)

// NewVerifier accepts every OAuth client id that may mint tokens for this
// backend — typically the iOS client and, later, a web client.
func NewVerifier(ctx context.Context, clientIDs []string) (*Verifier, error) {
	if len(clientIDs) == 0 {
		return nil, errors.New("google: at least one client id is required")
	}
	v, err := idtoken.NewValidator(ctx)
	if err != nil {
		return nil, fmt.Errorf("google: build validator: %w", err)
	}
	aud := make(map[string]struct{}, len(clientIDs))
	for _, id := range clientIDs {
		aud[id] = struct{}{}
	}
	return &Verifier{validator: v, audiences: aud}, nil
}

func (v *Verifier) Verify(ctx context.Context, rawToken string) (domain.GoogleIdentity, error) {
	// An empty audience defers the audience check to us, so several client
	// ids can be accepted rather than exactly one.
	payload, err := v.validator.Validate(ctx, rawToken, "")
	if err != nil {
		return domain.GoogleIdentity{}, domain.ErrGoogleTokenInvalid
	}
	if _, ok := v.audiences[payload.Audience]; !ok {
		return domain.GoogleIdentity{}, domain.ErrGoogleTokenInvalid
	}
	if payload.Subject == "" {
		return domain.GoogleIdentity{}, domain.ErrGoogleTokenInvalid
	}

	email, _ := payload.Claims["email"].(string)
	if email == "" {
		return domain.GoogleIdentity{}, domain.ErrGoogleTokenInvalid
	}
	name, _ := payload.Claims["name"].(string)
	picture, _ := payload.Claims["picture"].(string)

	return domain.GoogleIdentity{
		Subject:       payload.Subject,
		Email:         email,
		EmailVerified: emailVerified(payload.Claims["email_verified"]),
		Name:          name,
		Picture:       picture,
	}, nil
}

// emailVerified accepts both encodings Google has used for this claim.
func emailVerified(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return t == "true"
	}
	return false
}
