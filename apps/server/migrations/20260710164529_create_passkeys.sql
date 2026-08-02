create table passkeys (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    name TEXT COLLATE "en-US-x-icu",
    credential_id TEXT NOT NULL UNIQUE,
    public_key TEXT NOT NULL,
    sign_count BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ
);

create index passkeys_user_id_idx on passkeys (user_id);

alter table users add column passkey_required BOOLEAN NOT NULL DEFAULT false;
