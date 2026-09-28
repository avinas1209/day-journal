package postgres

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/avinas1209/day-journal/internal/core/domain"
	"github.com/avinas1209/day-journal/internal/core/port"
	"github.com/avinas1209/day-journal/migrations"
)

// These tests run real SQL, which the core's in-memory fakes cannot: they
// exist because a nil-tags insert once failed only against Postgres.
//
//	TEST_POSTGRES_DSN=postgres://... go test ./internal/adapter/driven/postgres/
//
// Without the variable they skip, so `go test ./...` stays hermetic.
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("TEST_POSTGRES_DSN not set")
	}
	ctx := context.Background()
	pool, err := NewPool(ctx, Config{DSN: dsn, MaxConns: 4, MinConns: 1, MaxConnLifetime: time.Hour, ConnectTimeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := Migrate(ctx, pool, migrations.FS, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return pool
}

// createUser inserts a throwaway account and removes it (cascading to its
// entries and sessions) when the test ends.
func createUser(t *testing.T, pool *pgxpool.Pool) *domain.User {
	t.Helper()
	u, err := domain.NewPasswordUser("it-"+uuid.NewString()[:8]+"@example.com", "Integration", "hash")
	if err != nil {
		t.Fatalf("new user: %v", err)
	}
	if err := NewUserRepository(pool).Create(context.Background(), u); err != nil {
		t.Fatalf("create user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, u.ID)
	})
	return u
}

func TestEntryWithoutTagsRoundTrips(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	user := createUser(t, pool)
	repo := NewEntryRepository(pool)

	entry, err := domain.NewEntry(user.ID, time.Now().Add(-time.Hour), "No tags", "", domain.MoodNeutral, nil)
	if err != nil {
		t.Fatalf("new entry: %v", err)
	}
	if err := repo.Create(ctx, entry); err != nil {
		t.Fatalf("create with nil tags: %v", err)
	}

	got, err := repo.FindByID(ctx, entry.ID)
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if len(got.Tags) != 0 {
		t.Errorf("tags = %v, want none", got.Tags)
	}

	title := "Still no tags"
	if err := got.Edit(&title, nil, nil, nil, nil); err != nil {
		t.Fatalf("edit: %v", err)
	}
	if err := repo.Update(ctx, got); err != nil {
		t.Fatalf("update with nil tags: %v", err)
	}
}

func TestEntryForUnknownAuthorIsRejectedByForeignKey(t *testing.T) {
	pool := testPool(t)
	entry, _ := domain.NewEntry(uuid.New(), time.Now().Add(-time.Hour), "Orphan", "", domain.MoodNeutral, nil)
	if err := NewEntryRepository(pool).Create(context.Background(), entry); err == nil {
		t.Fatal("want the entries_author_fk constraint to reject an entry with no account")
	}
}

func TestDuplicateEmailMapsToErrEmailTaken(t *testing.T) {
	pool := testPool(t)
	user := createUser(t, pool)

	dupe, _ := domain.NewPasswordUser(user.Email, "Dupe", "hash")
	if err := NewUserRepository(pool).Create(context.Background(), dupe); !errors.Is(err, domain.ErrEmailTaken) {
		t.Fatalf("err = %v, want ErrEmailTaken from the unique constraint", err)
	}
}

func TestSessionRotateIsACompareAndSwap(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	user := createUser(t, pool)
	repo := NewSessionRepository(pool)

	s := domain.NewSession(user.ID, domain.AuthMethodPassword, []byte("hash-1"), "127.0.0.1", "test", time.Hour)
	if err := repo.Create(ctx, s); err != nil {
		t.Fatalf("create: %v", err)
	}

	// Two requests read the same session, both try to rotate from hash-1.
	a, _ := repo.FindByID(ctx, s.ID)
	b, _ := repo.FindByID(ctx, s.ID)
	a.Rotate([]byte("hash-2a"), time.Hour)
	b.Rotate([]byte("hash-2b"), time.Hour)

	if err := repo.Rotate(ctx, a, []byte("hash-1")); err != nil {
		t.Fatalf("first rotate: %v", err)
	}
	if err := repo.Rotate(ctx, b, []byte("hash-1")); !errors.Is(err, port.ErrStaleRefresh) {
		t.Fatalf("second rotate err = %v, want ErrStaleRefresh", err)
	}
}

func TestRevokeKeepsTheFirstLogoutTime(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	user := createUser(t, pool)
	repo := NewSessionRepository(pool)

	s := domain.NewSession(user.ID, domain.AuthMethodPassword, []byte("h"), "", "", time.Hour)
	_ = repo.Create(ctx, s)

	s.Revoke(domain.RevokeLogout)
	first := *s.RevokedAt
	if err := repo.Revoke(ctx, s); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	again := *s
	later := first.Add(time.Hour)
	again.RevokedAt, again.RevokeReason = &later, domain.RevokeLogoutAll
	if err := repo.Revoke(ctx, &again); err != nil {
		t.Fatalf("second revoke: %v", err)
	}

	got, _ := repo.FindByID(ctx, s.ID)
	if !got.RevokedAt.Equal(first.Truncate(time.Microsecond)) || got.RevokeReason != domain.RevokeLogout {
		t.Errorf("revoked_at %v reason %q, want the first logout preserved", got.RevokedAt, got.RevokeReason)
	}
}

func TestDeletingAUserCascadesToEntriesAndSessions(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	user := createUser(t, pool)

	entry, _ := domain.NewEntry(user.ID, time.Now().Add(-time.Hour), "Gone soon", "", domain.MoodNeutral, nil)
	if err := NewEntryRepository(pool).Create(ctx, entry); err != nil {
		t.Fatalf("create entry: %v", err)
	}
	session := domain.NewSession(user.ID, domain.AuthMethodPassword, []byte("h"), "1.2.3.4", "ua", time.Hour)
	if err := NewSessionRepository(pool).Create(ctx, session); err != nil {
		t.Fatalf("create session: %v", err)
	}
	audit := NewAuditLog(pool)
	_ = audit.Record(ctx, domain.AuthEvent{ID: uuid.New(), Type: domain.AuthEventLogin, UserID: &user.ID,
		Email: user.Email, IP: "1.2.3.4", UserAgent: "ua", OccurredAt: time.Now()})

	if err := NewUserRepository(pool).Delete(ctx, user.ID); err != nil {
		t.Fatalf("delete user: %v", err)
	}
	if err := audit.Anonymize(ctx, user.ID); err != nil {
		t.Fatalf("anonymise: %v", err)
	}

	if _, err := NewEntryRepository(pool).FindByID(ctx, entry.ID); !errors.Is(err, domain.ErrEntryNotFound) {
		t.Errorf("entry survived its author's deletion: %v", err)
	}
	if _, err := NewSessionRepository(pool).FindByID(ctx, session.ID); !errors.Is(err, domain.ErrSessionNotFound) {
		t.Errorf("session survived its user's deletion: %v", err)
	}
	events, _ := audit.ListForUser(ctx, user.ID, 10)
	if len(events) != 1 || events[0].Email != "" || events[0].IP != "" || events[0].UserAgent != "" {
		t.Errorf("audit rows = %+v, want one row kept with personal data removed", events)
	}
	_, _ = pool.Exec(ctx, `DELETE FROM auth_events WHERE user_id = $1`, user.ID)
}
