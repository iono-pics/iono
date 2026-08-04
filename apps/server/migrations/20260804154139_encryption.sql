update files set encrypted = false where encrypted;

alter table files
    add column encryption_iv BYTEA,
    add column user_key_iv BYTEA,
    add column user_key_hash TEXT,
    add constraint files_user_key_complete CHECK (
        (user_key_iv IS NULL) = (user_key_hash IS NULL)
        AND (encrypted = (user_key_hash IS NOT NULL))
    );

create index files_pending_encryption_idx on files (id) where encryption_iv is null;

alter table pastes
    add column e2e_encrypted BOOLEAN NOT NULL DEFAULT false;

alter table user_settings
    add column encrypt_pastes BOOLEAN NOT NULL DEFAULT false;
