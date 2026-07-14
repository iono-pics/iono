create table redemption_codes (
    id TEXT PRIMARY KEY,
    code TEXT NOT NULL UNIQUE,
    plan_id TEXT NOT NULL REFERENCES plans (id),
    redeemed_by TEXT REFERENCES users (id) ON DELETE SET NULL,
    redeemed_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK ((redeemed_by IS NULL) = (redeemed_at IS NULL))
);

create index redemption_codes_redeemed_by_idx on redemption_codes (redeemed_by) where redeemed_by is not null;
create index redemption_codes_unredeemed_idx on redemption_codes (id) where redeemed_by is null;
