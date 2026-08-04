alter table files add column encryption_key_version SMALLINT;

update files set encryption_key_version = 1 where encryption_iv is not null;

alter table files
    add constraint files_encryption_version_present CHECK (
        (encryption_iv IS NULL) = (encryption_key_version IS NULL)
    );

create index files_encryption_key_version_idx
    on files (encryption_key_version) where encryption_key_version is not null;
