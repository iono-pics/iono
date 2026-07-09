create table pastes (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    key TEXT NOT NULL UNIQUE,
    title TEXT COLLATE "en-US-x-icu",
    content TEXT NOT NULL,
    syntax TEXT,
    views BIGINT NOT NULL DEFAULT 0 CHECK (views >= 0),
    password_hash TEXT,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
) with (fillfactor = 90);

create index pastes_user_created_idx on pastes (user_id, created_at desc);
create index pastes_expires_at_idx on pastes (expires_at) where expires_at is not null;
