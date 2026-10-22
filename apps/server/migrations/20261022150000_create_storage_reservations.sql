-- quota promised to an upload still streaming in. counted as used, so two
-- uploads at once cannot both spend the same remaining space. deleted in the
-- transaction that stores the file, or left to expire if the upload dies
create table storage_reservations (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    bytes BIGINT NOT NULL CHECK (bytes >= 0),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

create index storage_reservations_user_id_idx on storage_reservations (user_id, expires_at);
create index storage_reservations_expires_at_idx on storage_reservations (expires_at);
