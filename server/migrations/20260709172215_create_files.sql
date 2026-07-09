create table files (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    folder_id TEXT,
    key TEXT NOT NULL UNIQUE,
    original_name TEXT COLLATE "en-US-x-icu",
    content_type TEXT NOT NULL,
    size_bytes BIGINT NOT NULL CHECK (size_bytes >= 0),
    views BIGINT NOT NULL DEFAULT 0 CHECK (views >= 0),
    password_hash TEXT,
    expires_at TIMESTAMPTZ,
    is_favourite BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT files_folder_same_user_fkey
        FOREIGN KEY (folder_id, user_id) REFERENCES folders (id, user_id) ON DELETE SET NULL (folder_id)
) with (fillfactor = 90);

create index files_user_created_idx on files (user_id, created_at desc);
create index files_expires_at_idx on files (expires_at) where expires_at is not null;
create index files_folder_id_idx on files (folder_id);
create index files_favourites_idx on files (user_id, created_at desc)
    include (key, original_name, content_type, size_bytes)
    where is_favourite;
