use std::env;

use secrecy::{ExposeSecret, SecretString};

use crate::trusted_proxy::TrustedProxies;

const MIN_SECRET_LEN: usize = 32;

#[derive(Debug, Clone)]
pub struct Config {
    pub host: String,
    /// proxies whose `cf-connecting-ip` header is believed
    pub trusted_proxies: TrustedProxies,
    pub cors_allowed_origins: Vec<String>,
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

/// why the environment could not be turned into a [`Config`]
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("{0} must be set")]
    Missing(&'static str),

    #[error("{0} malformed")]
    Malformed(&'static str),

    #[error("{0} must be at least {1} characters")]
    TooShort(&'static str, usize),

    #[error("{0} must be between {1} and {2}")]
    OutOfRange(&'static str, i64, i64),

    #[error("FILE_ENCRYPTION_KEY malformed")]
    EncryptionKey(#[source] crate::crypto::KeyError),

    #[error("file encryption keys malformed")]
    Keyring(#[source] crate::error::AppError),
}

impl Config {
    /// builds the keyring from the configured current and previous keys
    ///
    /// # Errors
    ///
    /// Returns an error when a key is not hex, is the wrong length, or a
    /// version is defined twice. [`Config::from_env`] already checks this, so
    /// it only fails on a `Config` built by hand.
    pub fn keyring(&self) -> Result<crate::crypto::Keyring, crate::error::AppError> {
        crate::crypto::Keyring::new(
            self.file_encryption_key_version,
            self.file_encryption_key.expose_secret(),
            self.file_encryption_previous_keys.expose_secret(),
        )
    }

    /// reads the configuration from environment variables
    ///
    /// # Errors
    ///
    /// Returns a [`ConfigError`] naming the first variable that is missing or
    /// malformed.
    pub fn from_env() -> Result<Self, ConfigError> {
        let config = Self {
            host: env_or("HOST", "127.0.0.1"),
            trusted_proxies: TrustedProxies::parse(&env_or("TRUSTED_PROXY_CIDRS", ""))
                .map_err(|_| ConfigError::Malformed("TRUSTED_PROXY_CIDRS"))?,
            cors_allowed_origins: parse_origins(&env_or("CORS_ALLOWED_ORIGINS", ""))?,
            gateway_port: env_parse("GATEWAY_PORT", "8080")?,
            ingest_port: env_parse("INGEST_PORT", "8081")?,
            viewer_port: env_parse("VIEWER_PORT", "8082")?,
            janitor_port: env_parse("JANITOR_PORT", "8083")?,
            maintenance_token: env_optional("MAINTENANCE_TOKEN")
                .map(|token| min_len("MAINTENANCE_TOKEN", token))
                .transpose()?
                .map(SecretString::from),

            database_url: SecretString::from(env_required("DATABASE_URL")?),
            database_max_connections: env_parse("DATABASE_MAX_CONNECTIONS", "10")?,

            s3_bucket: env_or("S3_BUCKET", "iono-uploads"),
            s3_region: env_or("S3_REGION", "auto"),
            s3_endpoint: env_optional("S3_ENDPOINT"),
            s3_access_key_id: env_required("S3_ACCESS_KEY_ID")?,
            s3_secret_access_key: SecretString::from(env_required("S3_SECRET_ACCESS_KEY")?),

            jwt_secret: SecretString::from(min_len("JWT_SECRET", env_required("JWT_SECRET")?)?),
            jwt_access_ttl_minutes: env_parse("JWT_ACCESS_TTL_MINUTES", "15")?,
            refresh_token_ttl_days: env_parse("REFRESH_TOKEN_TTL_DAYS", "30")?,

            auth_rate_limit_seconds_per_request: env_parse(
                "AUTH_RATE_LIMIT_SECONDS_PER_REQUEST",
                "2",
            )?,
            auth_rate_limit_burst: env_parse("AUTH_RATE_LIMIT_BURST", "5")?,
            ingest_rate_limit_seconds_per_request: env_parse(
                "INGEST_RATE_LIMIT_SECONDS_PER_REQUEST",
                "1",
            )?,
            ingest_rate_limit_burst: env_parse("INGEST_RATE_LIMIT_BURST", "30")?,

            file_encryption_key: SecretString::from({
                let key = env_required("FILE_ENCRYPTION_KEY")?;
                crate::crypto::parse_key(&key).map_err(ConfigError::EncryptionKey)?;
                key
            }),
            file_encryption_key_version: env_parse("FILE_ENCRYPTION_KEY_VERSION", "1")?,
            file_encryption_previous_keys: env_secret_or("FILE_ENCRYPTION_PREVIOUS_KEYS", ""),

            recovery_window_days: env_parse("RECOVERY_WINDOW_DAYS", "30")?,
            totp_recovery_code_count: env_parse("TOTP_RECOVERY_CODE_COUNT", "10")?,
            oauth_flow_state_ttl_minutes: env_parse("OAUTH_FLOW_STATE_TTL_MINUTES", "15")?,
            webauthn_ceremony_ttl_minutes: env_parse("WEBAUTHN_CEREMONY_TTL_MINUTES", "5")?,

            max_paste_content_bytes: env_scaled("MAX_PASTE_SIZE_KB", "1024", KIB)?,

            sweep_batch_size: env_parse("SWEEP_BATCH_SIZE", "500")?,
            encrypt_backfill_batch_size: env_parse("ENCRYPT_BACKFILL_BATCH_SIZE", "100")?,
            encrypt_backfill_max_object_bytes: env_scaled(
                "ENCRYPT_BACKFILL_MAX_OBJECT_MB",
                "10240",
                MIB,
            )?,

            browser_cache_max_age_seconds: env_parse("BROWSER_CACHE_MAX_AGE_SECONDS", "300")?,
            edge_cache_max_age_seconds: env_parse("EDGE_CACHE_MAX_AGE_SECONDS", "31536000")?,

            webauthn_rp_id: env_required("WEBAUTHN_RP_ID")?,
            webauthn_rp_origin: env_required("WEBAUTHN_RP_ORIGIN")?,

            public_ingest_url: env_url_or("PUBLIC_INGEST_URL", "http://localhost:8081"),

            max_upload_size_bytes: env_scaled("MAX_UPLOAD_SIZE_MB", "10240", MIB)?,

            max_image_decode_bytes: env_scaled("MAX_IMAGE_DECODE_SIZE_MB", "32", MIB)?,

            cloudflare_zone_id: env_optional("CLOUDFLARE_ZONE_ID"),
            cloudflare_api_token: env_optional("CLOUDFLARE_API_TOKEN").map(SecretString::from),

            stripe_api_key: env_optional("STRIPE_API_KEY").map(SecretString::from),
            stripe_portal_return_url: env_optional("STRIPE_PORTAL_RETURN_URL")
                .map(|s| s.trim_end_matches('/').to_string()),

            discord_client_id: env_optional("DISCORD_CLIENT_ID"),
            discord_client_secret: env_optional("DISCORD_CLIENT_SECRET").map(SecretString::from),
            discord_redirect_uri: env_optional("DISCORD_REDIRECT_URI"),
            discord_success_redirect_url: env_optional("DISCORD_SUCCESS_REDIRECT_URL"),
        };

        config.validate_ranges()?;
        // fail at startup on a bad previous key too, not on the first request
        config.keyring().map_err(ConfigError::Keyring)?;
        Ok(config)
    }

    /// refuses numbers that would panic or misbehave later, such as a zero
    /// rate limit burst or a token lifetime too large for a date
    fn validate_ranges(&self) -> Result<(), ConfigError> {
        const MINUTES_PER_WEEK: i64 = 7 * 24 * 60;
        const DAYS_PER_DECADE: i64 = 3650;

        in_range(
            "DATABASE_MAX_CONNECTIONS",
            self.database_max_connections,
            1,
            1000,
        )?;
        in_range(
            "JWT_ACCESS_TTL_MINUTES",
            self.jwt_access_ttl_minutes,
            1,
            MINUTES_PER_WEEK,
        )?;
        in_range(
            "REFRESH_TOKEN_TTL_DAYS",
            self.refresh_token_ttl_days,
            1,
            DAYS_PER_DECADE,
        )?;
        in_range(
            "RECOVERY_WINDOW_DAYS",
            self.recovery_window_days,
            0,
            DAYS_PER_DECADE,
        )?;
        in_range(
            "OAUTH_FLOW_STATE_TTL_MINUTES",
            self.oauth_flow_state_ttl_minutes,
            1,
            MINUTES_PER_WEEK,
        )?;
        in_range(
            "WEBAUTHN_CEREMONY_TTL_MINUTES",
            self.webauthn_ceremony_ttl_minutes,
            1,
            MINUTES_PER_WEEK,
        )?;
        in_range(
            "TOTP_RECOVERY_CODE_COUNT",
            self.totp_recovery_code_count,
            1,
            100,
        )?;
        in_range("SWEEP_BATCH_SIZE", self.sweep_batch_size, 1, 100_000)?;
        in_range(
            "ENCRYPT_BACKFILL_BATCH_SIZE",
            self.encrypt_backfill_batch_size,
            1,
            100_000,
        )?;
        // governor refuses a zero period or burst
        in_range(
            "AUTH_RATE_LIMIT_SECONDS_PER_REQUEST",
            self.auth_rate_limit_seconds_per_request,
            1,
            86_400,
        )?;
        in_range(
            "AUTH_RATE_LIMIT_BURST",
            self.auth_rate_limit_burst,
            1,
            100_000,
        )?;
        in_range(
            "INGEST_RATE_LIMIT_SECONDS_PER_REQUEST",
            self.ingest_rate_limit_seconds_per_request,
            1,
            86_400,
        )?;
        in_range(
            "INGEST_RATE_LIMIT_BURST",
            self.ingest_rate_limit_burst,
            1,
            100_000,
        )?;
        Ok(())
    }
}

fn in_range<T: Copy>(key: &'static str, value: T, min: i64, max: i64) -> Result<(), ConfigError>
where
    i64: TryFrom<T>,
{
    // a value too big for an i64 is certainly above max
    let value = i64::try_from(value).unwrap_or(i64::MAX);
    if (min..=max).contains(&value) {
        Ok(())
    } else {
        Err(ConfigError::OutOfRange(key, min, max))
    }
}

const KIB: u64 = 1024;
const MIB: u64 = 1024 * 1024;

fn env_or(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}

fn env_optional(key: &str) -> Option<String> {
    env::var(key).ok().filter(|s| !s.is_empty())
}

fn env_required(key: &'static str) -> Result<String, ConfigError> {
    env_optional(key).ok_or(ConfigError::Missing(key))
}

fn env_parse<T: std::str::FromStr>(key: &'static str, default: &str) -> Result<T, ConfigError> {
    env_or(key, default)
        .parse()
        .map_err(|_| ConfigError::Malformed(key))
}

/// a whole number of `unit`s, as a byte count that fits `T`
fn env_scaled<T: TryFrom<u64>>(
    key: &'static str,
    default: &str,
    unit: u64,
) -> Result<T, ConfigError> {
    let count: u64 = env_parse(key, default)?;
    count
        .checked_mul(unit)
        .and_then(|bytes| T::try_from(bytes).ok())
        .ok_or(ConfigError::Malformed(key))
}

fn env_secret_or(key: &str, default: &str) -> SecretString {
    SecretString::from(env_or(key, default))
}

fn min_len(key: &'static str, value: String) -> Result<String, ConfigError> {
    if value.len() < MIN_SECRET_LEN {
        return Err(ConfigError::TooShort(key, MIN_SECRET_LEN));
    }
    Ok(value)
}

/// a comma separated list of `scheme://host[:port]` origins
fn parse_origins(list: &str) -> Result<Vec<String>, ConfigError> {
    list.split(',')
        .map(str::trim)
        .filter(|origin| !origin.is_empty())
        .map(|origin| {
            let authority = origin
                .strip_prefix("https://")
                .or_else(|| origin.strip_prefix("http://"))
                .filter(|rest| !rest.is_empty() && !rest.contains(['/', '?', '#', '*', '@', ' ']));
            authority
                .map(|_| origin.to_owned())
                .ok_or(ConfigError::Malformed("CORS_ALLOWED_ORIGINS"))
        })
        .collect()
}

fn env_url_or(key: &str, default: &str) -> String {
    env_or(key, default).trim_end_matches('/').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origins_must_be_bare_scheme_and_host() {
        assert_eq!(
            parse_origins("https://app.example.com, http://localhost:5173").unwrap(),
            ["https://app.example.com", "http://localhost:5173"]
        );
        assert!(parse_origins("").unwrap().is_empty());
        for bad in [
            "*",
            "app.example.com",
            "https://app.example.com/",
            "https://*.example.com",
            "https://user@app.example.com",
            "null",
            "https://",
        ] {
            assert!(parse_origins(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn numbers_outside_their_range_are_refused() {
        assert!(in_range("X", 5u32, 1, 10).is_ok());
        assert!(in_range("X", 0u32, 1, 10).is_err());
        assert!(in_range("X", -1i64, 0, 10).is_err());
        assert!(in_range("X", u64::MAX, 1, 10).is_err());
        assert!(in_range("X", 11usize, 1, 10).is_err());
    }

    #[test]
    fn short_secrets_are_refused() {
        assert!(min_len("JWT_SECRET", "short".into()).is_err());
        assert!(min_len("JWT_SECRET", "x".repeat(MIN_SECRET_LEN)).is_ok());
    }
}
