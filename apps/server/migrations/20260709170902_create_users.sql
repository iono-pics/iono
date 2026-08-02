create table users (
    id TEXT PRIMARY KEY,
    username TEXT COLLATE case_insensitive NOT NULL UNIQUE,
    email TEXT COLLATE case_insensitive NOT NULL UNIQUE,
    password_hash TEXT,
    plan_id TEXT NOT NULL REFERENCES plans (id) DEFAULT 'free',
    stripe_customer_id TEXT UNIQUE,
    totp_secret TEXT,
    totp_enabled BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (NOT totp_enabled OR totp_secret IS NOT NULL)
);

create index users_plan_id_idx on users (plan_id);

create trigger users_set_updated_at
    before update on users
    for each row execute function set_updated_at();

create table subscriptions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    plan_id TEXT NOT NULL REFERENCES plans (id),
    stripe_subscription_id TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL CHECK (status IN ('trialing', 'active', 'past_due', 'canceled', 'unpaid', 'incomplete', 'incomplete_expired', 'paused')),
    current_period_end TIMESTAMPTZ,
    cancel_at_period_end BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

create index subscriptions_user_id_idx on subscriptions (user_id);
create index subscriptions_plan_id_idx on subscriptions (plan_id);
create unique index subscriptions_one_active_per_user_idx on subscriptions (user_id)
    where status in ('trialing', 'active', 'past_due');

create trigger subscriptions_set_updated_at
    before update on subscriptions
    for each row execute function set_updated_at();

create table stripe_events (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);