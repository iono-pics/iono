drop index files_favourites_idx;

alter table files drop column original_name;
alter table files rename column key to original_name;

alter table files add column display_name TEXT;
update files set display_name = original_name;
alter table files alter column display_name set not null;
alter table files add constraint files_display_name_key unique (display_name);

create index files_favourites_idx on files (user_id, created_at desc)
    include (display_name, original_name, content_type, size_bytes)
    where is_favourite;
