create table short_links (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    key TEXT NOT NULL UNIQUE,
    target_url TEXT NOT NULL CHECK (target_url ~ '^https?://'),
    clicks BIGINT NOT NULL DEFAULT 0 CHECK (clicks >= 0),
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
) with (fillfactor = 90);

create index short_links_user_created_idx on short_links (user_id, created_at desc);
create index short_links_expires_at_idx on short_links (expires_at) where expires_at is not null;
