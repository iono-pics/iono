delete from passkeys;

alter table passkeys drop column public_key;
alter table passkeys drop column sign_count;
alter table passkeys add column credential JSONB NOT NULL;

create table webauthn_ceremonies (
    id TEXT PRIMARY KEY,
    user_id TEXT REFERENCES users (id) ON DELETE CASCADE,
    purpose TEXT NOT NULL,
    state JSONB NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

create index webauthn_ceremonies_expires_at_idx on webauthn_ceremonies (expires_at);
