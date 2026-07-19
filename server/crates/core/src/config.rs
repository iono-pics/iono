use std::env;

use secrecy::SecretString;

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

    pub webauthn_rp_id: String,
    pub webauthn_rp_origin: String,

    pub max_upload_size_bytes: usize,
}

impl Config {
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
            jwt_access_ttl_minutes: env_or("JWT_ACCESS_TTL_MINUTES", "1440")
                .parse()
                .expect("JWT_ACCESS_TTL_MINUTES malformed"),

            webauthn_rp_id: env_or("WEBAUTHN_RP_ID", "localhost"),
            webauthn_rp_origin: env_or("WEBAUTHN_RP_ORIGIN", "http://localhost:5173"),

            max_upload_size_bytes: env_or("MAX_UPLOAD_SIZE_MB", "10240")
                .parse::<usize>()
                .expect("MAX_UPLOAD_SIZE_MB malformed")
                * 1024
                * 1024,
        }
    }
}

fn env_or(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}

fn env_secret_or(key: &str, default: &str) -> SecretString {
    SecretString::from(env_or(key, default))
}
