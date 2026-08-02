create table domains (
    id TEXT PRIMARY KEY,
    owner_id TEXT REFERENCES users (id) ON DELETE CASCADE,
    name TEXT COLLATE case_insensitive NOT NULL UNIQUE,
    wildcard BOOLEAN NOT NULL DEFAULT false,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'active', 'failed')),
    visibility TEXT NOT NULL DEFAULT 'private' CHECK (visibility IN ('public', 'private', 'invite_only')),
    cloudflare_hostname_id TEXT UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

create index domains_owner_id_idx on domains (owner_id);

create table domain_invites (
    domain_id TEXT NOT NULL REFERENCES domains (id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    invited_by TEXT REFERENCES users (id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (domain_id, user_id)
);

create index domain_invites_user_id_idx on domain_invites (user_id);
create index domain_invites_invited_by_idx on domain_invites (invited_by);

create function can_use_domain(p_user_id TEXT, p_domain_id TEXT)
returns boolean as $$
    select exists (
        select 1
        from domains d
        where d.id = p_domain_id
        and (
            d.visibility = 'public'
            or d.owner_id = p_user_id
            or (
                d.visibility = 'invite_only'
                and exists (
                    select 1
                    from domain_invites di
                    where di.domain_id = d.id
                    and di.user_id = p_user_id
                )
            )
        )
    );
$$ language sql stable parallel safe;

create table domain_settings (
    user_id TEXT PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    files_domain_id TEXT REFERENCES domains (id) ON DELETE SET NULL,
    pastes_domain_id TEXT REFERENCES domains (id) ON DELETE SET NULL,
    short_links_domain_id TEXT REFERENCES domains (id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

create index domain_settings_files_domain_id_idx on domain_settings (files_domain_id);
create index domain_settings_pastes_domain_id_idx on domain_settings (pastes_domain_id);
create index domain_settings_short_links_domain_id_idx on domain_settings (short_links_domain_id);

create trigger domain_settings_set_updated_at
    before update on domain_settings
    for each row execute function set_updated_at();

create function domain_settings_check_access()
returns trigger as $$
begin
    if new.files_domain_id is not null and not can_use_domain(new.user_id, new.files_domain_id) then
        raise exception 'user % is not permitted to use domain % for files', new.user_id, new.files_domain_id;
    end if;
    if new.pastes_domain_id is not null and not can_use_domain(new.user_id, new.pastes_domain_id) then
        raise exception 'user % is not permitted to use domain % for pastes', new.user_id, new.pastes_domain_id;
    end if;
    if new.short_links_domain_id is not null and not can_use_domain(new.user_id, new.short_links_domain_id) then
        raise exception 'user % is not permitted to use domain % for short links', new.user_id, new.short_links_domain_id;
    end if;
    return new;
end;
$$ language plpgsql;

create trigger domain_settings_check_access
    before insert or update on domain_settings
    for each row execute function domain_settings_check_access();
