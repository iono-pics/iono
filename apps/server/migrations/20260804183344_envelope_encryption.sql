alter table files
    add column wrapped_dek BYTEA,
    add column dek_iv BYTEA,
    add constraint files_wrapped_dek_complete CHECK (
        (wrapped_dek IS NULL) = (dek_iv IS NULL)
        AND (wrapped_dek IS NULL OR encryption_iv IS NOT NULL)
    );

create index files_pending_encryption_idx2
    on files (encryption_key_version)
    where encryption_iv is null or wrapped_dek is null;
