package service_test

import (
	"bytes"
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/avinas1209/day-journal/internal/core/domain"
	"github.com/avinas1209/day-journal/internal/core/port"
)

// --- users ---

type fakeUsers struct {
	mu    sync.Mutex
	byID  map[uuid.UUID]*domain.User
	fails error
}

func newFakeUsers() *fakeUsers { return &fakeUsers{byID: map[uuid.UUID]*domain.User{}} }

func (f *fakeUsers) Create(_ context.Context, u *domain.User) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, existing := range f.byID {
		if existing.Email == u.Email {
			return domain.ErrEmailTaken
		}
	}
	c := *u
	f.byID[u.ID] = &c
	return nil
}

func (f *fakeUsers) Update(_ context.Context, u *domain.User) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.byID[u.ID]; !ok {
		return domain.ErrUserNotFound
	}
	c := *u
	f.byID[u.ID] = &c
	return nil
}

func (f *fakeUsers) find(match func(*domain.User) bool) (*domain.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, u := range f.byID {
		if match(u) {
			c := *u
			return &c, nil
		}
	}
	return nil, domain.ErrUserNotFound
}

func (f *fakeUsers) FindByID(_ context.Context, id uuid.UUID) (*domain.User, error) {
	return f.find(func(u *domain.User) bool { return u.ID == id })
}

func (f *fakeUsers) FindByEmail(_ context.Context, email string) (*domain.User, error) {
	email = domain.NormalizeEmail(email)
	return f.find(func(u *domain.User) bool { return u.Email == email })
}

func (f *fakeUsers) FindByGoogleSubject(_ context.Context, sub string) (*domain.User, error) {
	return f.find(func(u *domain.User) bool { return u.GoogleSubject != "" && u.GoogleSubject == sub })
}

func (f *fakeUsers) RecordLogin(_ context.Context, id uuid.UUID, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if u, ok := f.byID[id]; ok {
		u.LastLoginAt = &at
	}
	return nil
}

func (f *fakeUsers) Delete(_ context.Context, id uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.byID[id]; !ok {
		return domain.ErrUserNotFound
	}
	delete(f.byID, id)
	return nil
}

// --- sessions ---

type fakeSessions struct {
	mu   sync.Mutex
	byID map[uuid.UUID]*domain.Session
}

func newFakeSessions() *fakeSessions { return &fakeSessions{byID: map[uuid.UUID]*domain.Session{}} }

func (f *fakeSessions) Create(_ context.Context, s *domain.Session) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := *s
	f.byID[s.ID] = &c
	return nil
}

func (f *fakeSessions) FindByID(_ context.Context, id uuid.UUID) (*domain.Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.byID[id]
	if !ok {
		return nil, domain.ErrSessionNotFound
	}
	c := *s
	return &c, nil
}

func (f *fakeSessions) Rotate(_ context.Context, s *domain.Session, expected []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cur, ok := f.byID[s.ID]
	if !ok || !bytes.Equal(cur.RefreshTokenHash, expected) || cur.RevokedAt != nil {
		return port.ErrStaleRefresh
	}
	c := *s
	f.byID[s.ID] = &c
	return nil
}

func (f *fakeSessions) Revoke(_ context.Context, s *domain.Session) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if cur, ok := f.byID[s.ID]; ok && cur.RevokedAt == nil {
		cur.RevokedAt, cur.RevokeReason = s.RevokedAt, s.RevokeReason
	}
	return nil
}

func (f *fakeSessions) RevokeAllForUser(_ context.Context, userID uuid.UUID, reason domain.RevokeReason) ([]uuid.UUID, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var ids []uuid.UUID
	now := time.Now().UTC()
	for _, s := range f.byID {
		if s.UserID == userID && s.RevokedAt == nil {
			s.RevokedAt, s.RevokeReason = &now, reason
			ids = append(ids, s.ID)
		}
	}
	return ids, nil
}

func (f *fakeSessions) ListForUser(_ context.Context, userID uuid.UUID, limit int) ([]*domain.Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*domain.Session
	for _, s := range f.byID {
		if s.UserID == userID {
			c := *s
			out = append(out, &c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// --- audit ---

type fakeAudit struct {
	mu     sync.Mutex
	events []domain.AuthEvent
}

func (f *fakeAudit) Record(_ context.Context, e domain.AuthEvent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, e)
	return nil
}

func (f *fakeAudit) ListForUser(_ context.Context, userID uuid.UUID, limit int) ([]domain.AuthEvent, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []domain.AuthEvent
	for _, e := range f.events {
		if e.UserID != nil && *e.UserID == userID {
			out = append(out, e)
		}
	}
	return out, nil
}

func (f *fakeAudit) Anonymize(_ context.Context, userID uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, e := range f.events {
		if e.UserID != nil && *e.UserID == userID {
			f.events[i].Email, f.events[i].IP, f.events[i].UserAgent = "", "", ""
		}
	}
	return nil
}

func (f *fakeAudit) forUser(id uuid.UUID) []domain.AuthEvent {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []domain.AuthEvent
	for _, e := range f.events {
		if e.UserID != nil && *e.UserID == id {
			out = append(out, e)
		}
	}
	return out
}

func (f *fakeAudit) types() []domain.AuthEventType {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]domain.AuthEventType, 0, len(f.events))
	for _, e := range f.events {
		out = append(out, e.Type)
	}
	return out
}

func (f *fakeAudit) count(t domain.AuthEventType) int {
	n := 0
	for _, got := range f.types() {
		if got == t {
			n++
		}
	}
	return n
}

// --- hasher: reversible and instant, which is fine for tests only ---

type fakeHasher struct{}

func (fakeHasher) Hash(p string) (string, error) { return "hashed:" + p, nil }
func (fakeHasher) Compare(h, p string) error {
	if h != "hashed:"+p {
		return errors.New("mismatch")
	}
	return nil
}

// --- tokens: opaque "<user>|<session>" strings ---

type fakeTokens struct{ ttl time.Duration }

func (t fakeTokens) Issue(userID, sessionID uuid.UUID) (port.AccessToken, error) {
	return port.AccessToken{Value: userID.String() + "|" + sessionID.String(), ExpiresAt: time.Now().Add(t.ttl)}, nil
}

func (t fakeTokens) Verify(raw string) (port.AccessClaims, error) {
	if len(raw) != 73 || raw[36] != '|' {
		return port.AccessClaims{}, domain.ErrUnauthenticated
	}
	u, err1 := uuid.Parse(raw[:36])
	s, err2 := uuid.Parse(raw[37:])
	if err1 != nil || err2 != nil {
		return port.AccessClaims{}, domain.ErrUnauthenticated
	}
	return port.AccessClaims{UserID: u, SessionID: s}, nil
}

func (t fakeTokens) TTL() time.Duration { return t.ttl }

// --- google ---

type fakeGoogle struct {
	identities map[string]domain.GoogleIdentity // id token -> identity
}

func (g *fakeGoogle) Verify(_ context.Context, token string) (domain.GoogleIdentity, error) {
	id, ok := g.identities[token]
	if !ok {
		return domain.GoogleIdentity{}, domain.ErrGoogleTokenInvalid
	}
	return id, nil
}

// --- denylist ---

type fakeDenylist struct {
	mu     sync.Mutex
	denied map[uuid.UUID]bool
	err    error // fails IsDenied: Redis unreachable
	// denyFailures makes the next N Deny calls fail: a transient write error
	// while Redis is otherwise up.
	denyFailures int
	denyCalls    int
}

func newFakeDenylist() *fakeDenylist { return &fakeDenylist{denied: map[uuid.UUID]bool{}} }

func (d *fakeDenylist) Deny(_ context.Context, id uuid.UUID, _ time.Duration) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.denyCalls++
	if d.denyFailures > 0 {
		d.denyFailures--
		return errors.New("redis: write failed")
	}
	d.denied[id] = true
	return nil
}

func (d *fakeDenylist) IsDenied(_ context.Context, id uuid.UUID) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.err != nil {
		return false, d.err
	}
	return d.denied[id], nil
}

// --- rate limiter ---

type fakeLimiter struct {
	mu     sync.Mutex
	counts map[string]int
	err    error
}

func newFakeLimiter() *fakeLimiter { return &fakeLimiter{counts: map[string]int{}} }

func (l *fakeLimiter) Allow(_ context.Context, key string, limit int, _ time.Duration) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err != nil {
		return false, l.err
	}
	l.counts[key]++
	return l.counts[key] <= limit, nil
}
