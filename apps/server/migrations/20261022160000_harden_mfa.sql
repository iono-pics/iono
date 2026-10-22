-- the last totp time step accepted, so the same code cannot be used twice
alter table users add column totp_last_step BIGINT;

-- wrong codes in a row, and how long the account refuses codes after too many
alter table users
    add column totp_failed_attempts SMALLINT NOT NULL DEFAULT 0
        CHECK (totp_failed_attempts >= 0),
    add column totp_locked_until TIMESTAMPTZ;

-- totp_secret is now sealed with the file keyring on first use or setup, a
-- plain base32 value is a secret from before and still reads

-- discord tokens were only ever needed during the login that fetched them
update oauth_accounts set access_token = null, refresh_token = null, expires_at = null;
