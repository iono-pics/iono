alter table redemption_codes add column duration_days INTEGER
    CHECK (duration_days IS NULL OR duration_days > 0);

alter table users add column plan_expires_at TIMESTAMPTZ;

create index users_plan_expires_at_idx on users (plan_expires_at)
    where plan_expires_at is not null;
