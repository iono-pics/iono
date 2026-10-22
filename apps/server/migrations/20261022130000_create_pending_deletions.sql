-- work left over once a row is gone: its object in storage and its copies at
-- the edge. written in the same transaction as the row delete, so a crash or a
-- failed call is retried by the janitor instead of being forgotten
create table pending_deletions (
    id TEXT PRIMARY KEY,
    s3_key TEXT,
    cache_tag TEXT,
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (s3_key IS NOT NULL OR cache_tag IS NOT NULL)
);

create index pending_deletions_created_at_idx on pending_deletions (created_at);
