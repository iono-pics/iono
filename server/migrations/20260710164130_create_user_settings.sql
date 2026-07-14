create table user_settings (
    user_id TEXT PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    display_name_length SMALLINT NOT NULL DEFAULT 16 CHECK (display_name_length BETWEEN 16 AND 32),
    display_name_style TEXT NOT NULL DEFAULT 'normal' CHECK (display_name_style IN ('normal', 'emoji', 'accents', 'invisible')),
    display_name_include_extension BOOLEAN NOT NULL DEFAULT true,
    raw_links_only BOOLEAN NOT NULL DEFAULT false,
    default_expires_in_seconds BIGINT CHECK (default_expires_in_seconds IS NULL OR default_expires_in_seconds > 0),
    lossless_images BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

create trigger user_settings_set_updated_at
    before update on user_settings
    for each row execute function set_updated_at();

create function create_default_user_settings()
returns trigger as $$
begin
    insert into user_settings (user_id) values (new.id);
    return new;
end;
$$ language plpgsql;

create trigger users_create_default_user_settings
    after insert on users
    for each row execute function create_default_user_settings();

insert into user_settings (user_id)
select id from users
on conflict (user_id) do nothing;
