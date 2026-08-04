create function create_default_embed_settings()
returns trigger as $$
begin
    insert into embed_settings (user_id) values (new.id);
    return new;
end;
$$ language plpgsql;

create trigger users_create_default_embed_settings
    after insert on users
    for each row execute function create_default_embed_settings();

insert into embed_settings (user_id)
select id from users
on conflict (user_id) do nothing;
