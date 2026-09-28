// Package crypto holds the password hashing adapter.
package crypto

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"

	"github.com/avinas1209/day-journal/internal/core/port"
)

// BcryptHasher implements port.PasswordHasher.
type BcryptHasher struct {
	cost int
}

var _ port.PasswordHasher = (*BcryptHasher)(nil)

// NewBcryptHasher clamps cost to bcrypt's valid range. 12 is a sensible
// production default (~250ms on a modern core); tests pass bcrypt.MinCost.
func NewBcryptHasher(cost int) *BcryptHasher {
	if cost < bcrypt.MinCost {
		cost = bcrypt.MinCost
	}
	if cost > bcrypt.MaxCost {
		cost = bcrypt.MaxCost
	}
	return &BcryptHasher{cost: cost}
}

func (h *BcryptHasher) Hash(password string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(password), h.cost)
	if err != nil {
		return "", fmt.Errorf("bcrypt: hash: %w", err)
	}
	return string(b), nil
}

func (h *BcryptHasher) Compare(hash, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}
