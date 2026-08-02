create table embed_presets (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    name TEXT COLLATE "en-US-x-icu" NOT NULL,
    site_name TEXT,
    site_url TEXT,
    author_name TEXT,
    author_url TEXT,
    title TEXT,
    description TEXT,
    color TEXT CHECK (color IS NULL OR color ~ '^#[0-9a-fA-F]{6}$'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (id, user_id),
    UNIQUE (user_id, name)
);

create trigger embed_presets_set_updated_at
    before update on embed_presets
    for each row execute function set_updated_at();
