create collation case_insensitive (provider = icu, locale = 'und-u-ks-level2', deterministic = false);

create function set_updated_at()
returns trigger as $$
begin
    new.updated_at = now();
    return new;
end;
$$ language plpgsql;

create table plans (
    id TEXT PRIMARY KEY,
    name TEXT COLLATE "en-US-x-icu" NOT NULL UNIQUE,
    storage_quota_bytes BIGINT NOT NULL CHECK (storage_quota_bytes >= 0),
    max_upload_bytes BIGINT NOT NULL CHECK (max_upload_bytes >= 0),
    stripe_product_id TEXT UNIQUE,
    stripe_price_id TEXT UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

create trigger plans_set_updated_at
    before update on plans
    for each row execute function set_updated_at();

insert into plans (id, name, storage_quota_bytes, max_upload_bytes) values
    ('free', 'Free', 500 * 1024 * 1024, 75 * 1024 * 1024), /* 500MB */
    ('pro', 'Pro', 100::bigint * 1024 * 1024 * 1024, 10::bigint * 1024 * 1024 * 1024); /* 100GB */
