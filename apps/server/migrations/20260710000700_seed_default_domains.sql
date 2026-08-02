insert into domains (id, owner_id, name, wildcard, status, visibility) values
    ('bcc76552-72f8-4cf2-823e-ff1b0e25d6ff', null, 'cdn.iono.pics', false, 'active', 'public');

create function create_default_domain_settings()
returns trigger as $$
begin
    insert into domain_settings (user_id, files_domain_id, pastes_domain_id, short_links_domain_id)
    values (new.id, 'bcc76552-72f8-4cf2-823e-ff1b0e25d6ff', 'bcc76552-72f8-4cf2-823e-ff1b0e25d6ff', 'bcc76552-72f8-4cf2-823e-ff1b0e25d6ff');
    return new;
end;
$$ language plpgsql;

create trigger users_create_default_domain_settings
    after insert on users
    for each row execute function create_default_domain_settings();

insert into domain_settings (user_id, files_domain_id, pastes_domain_id, short_links_domain_id)
select id, 'bcc76552-72f8-4cf2-823e-ff1b0e25d6ff', 'bcc76552-72f8-4cf2-823e-ff1b0e25d6ff', 'bcc76552-72f8-4cf2-823e-ff1b0e25d6ff'
from users
on conflict (user_id) do nothing;
