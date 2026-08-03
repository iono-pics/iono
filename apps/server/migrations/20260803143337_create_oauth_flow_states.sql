CREATE TABLE oauth_flow_states (
    id            TEXT PRIMARY KEY,
    provider      TEXT NOT NULL,
    pkce_verifier TEXT NOT NULL,
    link_user_id  TEXT REFERENCES users (id) ON DELETE CASCADE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at    TIMESTAMPTZ NOT NULL
);

CREATE INDEX oauth_flow_states_expires_at_idx ON oauth_flow_states (expires_at);
