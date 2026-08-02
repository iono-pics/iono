create table embed_settings (
    user_id TEXT PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    enabled BOOLEAN NOT NULL DEFAULT false,
    active_preset_id TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT embed_settings_active_preset_same_user_fkey
        FOREIGN KEY (active_preset_id, user_id) REFERENCES embed_presets (id, user_id) ON DELETE SET NULL (active_preset_id),
    CHECK (NOT enabled OR active_preset_id IS NOT NULL)
);

create index embed_settings_active_preset_id_idx on embed_settings (active_preset_id);

create trigger embed_settings_set_updated_at
    before update on embed_settings
    for each row execute function set_updated_at();
