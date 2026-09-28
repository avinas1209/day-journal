CREATE EXTENSION IF NOT EXISTS "pg_trgm";

CREATE TABLE IF NOT EXISTS entries (
    id          UUID PRIMARY KEY,
    author_id   UUID        NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    title       TEXT        NOT NULL,
    body        TEXT        NOT NULL DEFAULT '',
    mood        TEXT        NOT NULL,
    tags        TEXT[]      NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT entries_mood_check CHECK (mood IN ('happy', 'neutral', 'sad', 'angry', 'tired')),
    CONSTRAINT entries_title_not_blank CHECK (length(btrim(title)) > 0)
);

-- Serves the app's main read: one author's entries for a selected day, newest
-- first. Also covers the unfiltered listing and any date-range query.
CREATE INDEX IF NOT EXISTS entries_author_occurred_idx ON entries (author_id, occurred_at DESC);

-- Supports ?tag= filtering via `$n = ANY(tags)`.
CREATE INDEX IF NOT EXISTS entries_tags_idx ON entries USING GIN (tags);

-- Supports ?search= (ILIKE with a leading wildcard, which no btree can serve).
CREATE INDEX IF NOT EXISTS entries_title_trgm_idx ON entries USING GIN (title gin_trgm_ops);
CREATE INDEX IF NOT EXISTS entries_body_trgm_idx  ON entries USING GIN (body  gin_trgm_ops);
