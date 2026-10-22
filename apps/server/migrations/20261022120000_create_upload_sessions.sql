-- chunked uploads, for files bigger than one request through the edge allows
create table upload_sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    s3_key TEXT NOT NULL UNIQUE,
    s3_upload_id TEXT NOT NULL,
    size_bytes BIGINT NOT NULL CHECK (size_bytes > 0),
    part_size_bytes BIGINT NOT NULL CHECK (part_size_bytes > 0),
    -- sniffed from part 1, so null until it arrives
    content_type TEXT,
    -- part number -> etag
    parts JSONB NOT NULL DEFAULT '{}',
    encryption_key_version SMALLINT NOT NULL,
    encryption_iv BYTEA NOT NULL,
    wrapped_dek BYTEA NOT NULL,
    dek_iv BYTEA NOT NULL,
    -- the user key lives here wrapped only until complete hands it out
    wrapped_user_key BYTEA,
    user_key_wrap_iv BYTEA,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK ((wrapped_user_key IS NULL) = (user_key_wrap_iv IS NULL))
);

create index upload_sessions_user_id_idx on upload_sessions (user_id);
create index upload_sessions_expires_at_idx on upload_sessions (expires_at);
