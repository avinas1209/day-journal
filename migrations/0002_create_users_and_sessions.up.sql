-- Accounts. Email is stored normalised (lower-cased, trimmed) by the domain,
-- so a plain unique constraint is enough to stop duplicate accounts.
CREATE TABLE IF NOT EXISTS users (
    id             UUID PRIMARY KEY,
    email          TEXT        NOT NULL,
    display_name   TEXT        NOT NULL,
    avatar_url     TEXT        NOT NULL DEFAULT '',
    password_hash  TEXT,                       -- NULL for Google-only accounts
    google_subject TEXT,                       -- Google's stable "sub"; NULL if not linked
    email_verified BOOLEAN     NOT NULL DEFAULT false,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at  TIMESTAMPTZ,

    CONSTRAINT users_email_key          UNIQUE (email),
    CONSTRAINT users_google_subject_key UNIQUE (google_subject),
    CONSTRAINT users_email_normalised   CHECK (email = lower(btrim(email))),
    CONSTRAINT users_has_credential     CHECK (password_hash IS NOT NULL OR google_subject IS NOT NULL)
);

-- One row per signed-in device. Doubles as the login/logout audit trail:
-- created_at is the login time, revoked_at the logout time.
CREATE TABLE IF NOT EXISTS sessions (
    id                          UUID PRIMARY KEY,
    user_id                     UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    method                      TEXT        NOT NULL,
    refresh_token_hash          BYTEA       NOT NULL,
    previous_refresh_token_hash BYTEA,
    ip                          TEXT        NOT NULL DEFAULT '',
    user_agent                  TEXT        NOT NULL DEFAULT '',
    created_at                  TIMESTAMPTZ NOT NULL,
    last_refreshed_at           TIMESTAMPTZ NOT NULL,
    expires_at                  TIMESTAMPTZ NOT NULL,
    revoked_at                  TIMESTAMPTZ,
    revoke_reason               TEXT,

    CONSTRAINT sessions_method_check  CHECK (method IN ('password', 'google')),
    CONSTRAINT sessions_revoke_paired CHECK ((revoked_at IS NULL) = (revoke_reason IS NULL))
);

-- "My sign-in history", newest first.
CREATE INDEX IF NOT EXISTS sessions_user_created_idx ON sessions (user_id, created_at DESC);
-- "Sign out everywhere" touches only live sessions.
CREATE INDEX IF NOT EXISTS sessions_user_active_idx ON sessions (user_id) WHERE revoked_at IS NULL;

-- Append-only authentication audit log. No foreign keys on purpose: audit
-- rows must outlive the users and sessions they describe.
CREATE TABLE IF NOT EXISTS auth_events (
    id          UUID PRIMARY KEY,
    event       TEXT        NOT NULL,
    user_id     UUID,
    session_id  UUID,
    method      TEXT        NOT NULL DEFAULT '',
    email       TEXT        NOT NULL DEFAULT '',
    ip          TEXT        NOT NULL DEFAULT '',
    user_agent  TEXT        NOT NULL DEFAULT '',
    detail      TEXT        NOT NULL DEFAULT '',
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS auth_events_user_idx  ON auth_events (user_id, occurred_at DESC);
-- Investigating attempts against an address, including unknown ones.
CREATE INDEX IF NOT EXISTS auth_events_email_idx ON auth_events (email, occurred_at DESC);

-- Entries now belong to real accounts. Added NOT VALID so rows written before
-- accounts existed don't block the deploy; new and updated rows are checked
-- immediately. Once legacy rows are reassigned or removed, run:
--   ALTER TABLE entries VALIDATE CONSTRAINT entries_author_fk;
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'entries_author_fk') THEN
        ALTER TABLE entries
            ADD CONSTRAINT entries_author_fk
            FOREIGN KEY (author_id) REFERENCES users (id) ON DELETE CASCADE NOT VALID;
    END IF;
END
$$;
