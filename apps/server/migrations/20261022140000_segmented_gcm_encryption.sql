-- 1 is aes-ctr, unauthenticated and only read now. 2 is aes-256-gcm over 64KiB
-- segments, its encryption_iv is the content key salt and a user key is mixed
-- into the content key instead of being a second layer with its own iv
alter table files
    add column encryption_format SMALLINT NOT NULL DEFAULT 1
        CHECK (encryption_format IN (1, 2));

alter table files drop constraint files_user_key_complete;
alter table files add constraint files_user_key_complete CHECK (
    encrypted = (user_key_hash IS NOT NULL)
    AND CASE WHEN encryption_format = 1
        THEN (user_key_iv IS NULL) = (user_key_hash IS NULL)
        ELSE user_key_iv IS NULL
    END
);

alter table files add constraint files_segmented_has_envelope CHECK (
    encryption_format = 1 OR (wrapped_dek IS NOT NULL AND encryption_iv IS NOT NULL)
);

-- the second was a superset of the first, and both predate format 2
drop index files_pending_encryption_idx;
drop index files_pending_encryption_idx2;

-- rows the backfill still has work on: plaintext, ctr without a user key
-- (rewritable), or a data key under the old unauthenticated wrap
create index files_needs_backfill_idx on files (id)
    where encryption_iv is null
       or (encryption_format = 1 and user_key_hash is null)
       or octet_length(wrapped_dek) <> 48;
