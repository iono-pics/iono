use std::env;

use secrecy::{ExposeSecret, SecretString};

#[derive(Debug, Clone)]
pub struct Config {
    pub host: String,
    pub gateway_port: u16,
    pub ingest_port: u16,
    pub viewer_port: u16,
    pub janitor_port: u16,
    pub maintenance_token: Option<SecretString>,

    pub database_url: SecretString,
    pub database_max_connections: u32,

    pub s3_bucket: String,
    pub s3_region: String,
    pub s3_endpoint: Option<String>,
    pub s3_access_key_id: String,
    pub s3_secret_access_key: SecretString,

    pub jwt_secret: SecretString,
    pub jwt_access_ttl_minutes: i64,
    pub refresh_token_ttl_days: i64,

    pub auth_rate_limit_seconds_per_request: u64,
    pub auth_rate_limit_burst: u32,

    pub ingest_rate_limit_seconds_per_request: u64,
    pub ingest_rate_limit_burst: u32,

    pub file_encryption_key: SecretString,
    pub file_encryption_key_version: i16,
    pub file_encryption_previous_keys: SecretString,

    pub recovery_window_days: i64,
    pub totp_recovery_code_count: usize,

    pub oauth_flow_state_ttl_minutes: i64,
    pub webauthn_ceremony_ttl_minutes: i64,

    pub max_paste_content_bytes: usize,

    pub sweep_batch_size: i64,
    pub encrypt_backfill_batch_size: i64,
    pub encrypt_backfill_max_object_bytes: i64,

    pub browser_cache_max_age_seconds: u32,
    pub edge_cache_max_age_seconds: u32,

    pub webauthn_rp_id: String,
    pub webauthn_rp_origin: String,

    pub public_ingest_url: String,

    pub max_upload_size_bytes: usize,

    pub max_image_decode_bytes: usize,

    pub cloudflare_zone_id: Option<String>,
    pub cloudflare_api_token: Option<SecretString>,

    pub stripe_api_key: Option<SecretString>,
    pub stripe_portal_return_url: Option<String>,

    pub discord_client_id: Option<String>,
    pub discord_client_secret: Option<SecretString>,
    pub discord_redirect_uri: Option<String>,
    pub discord_success_redirect_url: Option<String>,
}

impl Config {
    pub fn keyring(&self) -> crate::crypto::Keyring {
        crate::crypto::Keyring::new(
            self.file_encryption_key_version,
            self.file_encryption_key.expose_secret(),
            self.file_encryption_previous_keys.expose_secret(),
        )
        .expect("file encryption keys malformed")
    }

    pub fn from_env() -> Self {
        Self {
            host: env_or("HOST", "0.0.0.0"),
            gateway_port: env_or("GATEWAY_PORT", "8080")
                .parse()
                .expect("GATEWAY_PORT malformed"),
            ingest_port: env_or("INGEST_PORT", "8081")
                .parse()
                .expect("INGEST_PORT malformed"),
            viewer_port: env_or("VIEWER_PORT", "8082")
                .parse()
                .expect("VIEWER_PORT malformed"),
            janitor_port: env_or("JANITOR_PORT", "8083")
                .parse()
                .expect("JANITOR_PORT malformed"),
            maintenance_token: env::var("MAINTENANCE_TOKEN")
                .ok()
                .filter(|s| !s.is_empty())
                .map(SecretString::from),

            database_url: env_secret_or("DATABASE_URL", "postgres://iono:iono@localhost:5432/iono"),
            database_max_connections: env_or("DATABASE_MAX_CONNECTIONS", "10")
                .parse()
                .expect("DATABASE_MAX_CONNECTIONS malformed"),

            s3_bucket: env_or("S3_BUCKET", "iono-uploads"),
            s3_region: env_or("S3_REGION", "auto"),
            s3_endpoint: env::var("S3_ENDPOINT").ok().filter(|s| !s.is_empty()),
            s3_access_key_id: env_or("S3_ACCESS_KEY_ID", ""),
            s3_secret_access_key: env_secret_or("S3_SECRET_ACCESS_KEY", ""),

            jwt_secret: SecretString::from(
                env::var("JWT_SECRET")
                    .ok()
                    .filter(|s| !s.is_empty())
                    .expect("JWT_SECRET must be set"),
            ),
            jwt_access_ttl_minutes: env_or("JWT_ACCESS_TTL_MINUTES", "15")
                .parse()
                .expect("JWT_ACCESS_TTL_MINUTES malformed"),
            refresh_token_ttl_days: env_or("REFRESH_TOKEN_TTL_DAYS", "30")
                .parse()
                .expect("REFRESH_TOKEN_TTL_DAYS malformed"),

            auth_rate_limit_seconds_per_request: env_or("AUTH_RATE_LIMIT_SECONDS_PER_REQUEST", "2")
                .parse()
                .expect("AUTH_RATE_LIMIT_SECONDS_PER_REQUEST malformed"),
            auth_rate_limit_burst: env_or("AUTH_RATE_LIMIT_BURST", "5")
                .parse()
                .expect("AUTH_RATE_LIMIT_BURST malformed"),
            ingest_rate_limit_seconds_per_request: env_or(
                "INGEST_RATE_LIMIT_SECONDS_PER_REQUEST",
                "1",
            )
            .parse()
            .expect("INGEST_RATE_LIMIT_SECONDS_PER_REQUEST malformed"),
            ingest_rate_limit_burst: env_or("INGEST_RATE_LIMIT_BURST", "30")
                .parse()
                .expect("INGEST_RATE_LIMIT_BURST malformed"),

            file_encryption_key: SecretString::from({
                let key = env::var("FILE_ENCRYPTION_KEY")
                    .ok()
                    .filter(|s| !s.is_empty())
                    .expect("FILE_ENCRYPTION_KEY must be set");
                crate::crypto::parse_key(&key).expect("FILE_ENCRYPTION_KEY malformed");
                key
            }),
            file_encryption_key_version: env_or("FILE_ENCRYPTION_KEY_VERSION", "1")
                .parse()
                .expect("FILE_ENCRYPTION_KEY_VERSION malformed"),
            file_encryption_previous_keys: env_secret_or("FILE_ENCRYPTION_PREVIOUS_KEYS", ""),

            recovery_window_days: env_or("RECOVERY_WINDOW_DAYS", "30")
                .parse()
                .expect("RECOVERY_WINDOW_DAYS malformed"),
            totp_recovery_code_count: env_or("TOTP_RECOVERY_CODE_COUNT", "10")
                .parse()
                .expect("TOTP_RECOVERY_CODE_COUNT malformed"),
            oauth_flow_state_ttl_minutes: env_or("OAUTH_FLOW_STATE_TTL_MINUTES", "15")
                .parse()
                .expect("OAUTH_FLOW_STATE_TTL_MINUTES malformed"),
            webauthn_ceremony_ttl_minutes: env_or("WEBAUTHN_CEREMONY_TTL_MINUTES", "5")
                .parse()
                .expect("WEBAUTHN_CEREMONY_TTL_MINUTES malformed"),

            max_paste_content_bytes: env_or("MAX_PASTE_SIZE_KB", "1024")
                .parse::<usize>()
                .expect("MAX_PASTE_SIZE_KB malformed")
                * 1024,

            sweep_batch_size: env_or("SWEEP_BATCH_SIZE", "500")
                .parse()
                .expect("SWEEP_BATCH_SIZE malformed"),
            encrypt_backfill_batch_size: env_or("ENCRYPT_BACKFILL_BATCH_SIZE", "100")
                .parse()
                .expect("ENCRYPT_BACKFILL_BATCH_SIZE malformed"),
            encrypt_backfill_max_object_bytes: env_or("ENCRYPT_BACKFILL_MAX_OBJECT_MB", "10240")
                .parse::<i64>()
                .expect("ENCRYPT_BACKFILL_MAX_OBJECT_MB malformed")
                * 1024
                * 1024,

            browser_cache_max_age_seconds: env_or("BROWSER_CACHE_MAX_AGE_SECONDS", "300")
                .parse()
                .expect("BROWSER_CACHE_MAX_AGE_SECONDS malformed"),
            edge_cache_max_age_seconds: env_or("EDGE_CACHE_MAX_AGE_SECONDS", "31536000")
                .parse()
                .expect("EDGE_CACHE_MAX_AGE_SECONDS malformed"),

            webauthn_rp_id: env_or("WEBAUTHN_RP_ID", "localhost"),
            webauthn_rp_origin: env_or("WEBAUTHN_RP_ORIGIN", "http://localhost:5173"),

            public_ingest_url: env_url_or("PUBLIC_INGEST_URL", "http://localhost:8081"),

            max_upload_size_bytes: env_or("MAX_UPLOAD_SIZE_MB", "10240")
                .parse::<usize>()
                .expect("MAX_UPLOAD_SIZE_MB malformed")
                * 1024
                * 1024,

            max_image_decode_bytes: env_or("MAX_IMAGE_DECODE_SIZE_MB", "32")
                .parse::<usize>()
                .expect("MAX_IMAGE_DECODE_SIZE_MB malformed")
                * 1024
                * 1024,

            cloudflare_zone_id: env::var("CLOUDFLARE_ZONE_ID")
                .ok()
                .filter(|s| !s.is_empty()),
            cloudflare_api_token: env::var("CLOUDFLARE_API_TOKEN")
                .ok()
                .filter(|s| !s.is_empty())
                .map(SecretString::from),

            stripe_api_key: env::var("STRIPE_API_KEY")
                .ok()
                .filter(|s| !s.is_empty())
                .map(SecretString::from),
            stripe_portal_return_url: env::var("STRIPE_PORTAL_RETURN_URL")
                .ok()
                .filter(|s| !s.is_empty())
                .map(|s| s.trim_end_matches('/').to_string()),

            discord_client_id: env::var("DISCORD_CLIENT_ID").ok().filter(|s| !s.is_empty()),
            discord_client_secret: env::var("DISCORD_CLIENT_SECRET")
                .ok()
                .filter(|s| !s.is_empty())
                .map(SecretString::from),
            discord_redirect_uri: env::var("DISCORD_REDIRECT_URI")
                .ok()
                .filter(|s| !s.is_empty()),
            discord_success_redirect_url: env::var("DISCORD_SUCCESS_REDIRECT_URL")
                .ok()
                .filter(|s| !s.is_empty()),
        }
    }
}

fn env_or(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}

fn env_secret_or(key: &str, default: &str) -> SecretString {
    SecretString::from(env_or(key, default))
}

fn env_url_or(key: &str, default: &str) -> String {
    env_or(key, default).trim_end_matches('/').to_string()
}
