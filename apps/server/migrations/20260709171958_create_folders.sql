create table folders (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    parent_id TEXT,
    name TEXT COLLATE "en-US-x-icu" NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (id, user_id),
    UNIQUE (user_id, parent_id, name),
    CONSTRAINT folders_parent_same_user_fkey
        FOREIGN KEY (parent_id, user_id) REFERENCES folders (id, user_id) ON DELETE CASCADE
);

create index folders_parent_id_idx on folders (parent_id);
