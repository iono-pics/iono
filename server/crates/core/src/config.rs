use std::env;

use secrecy::SecretString;

#[derive(Debug, Clone)]
pub struct Config {
    pub host: String,
    pub gateway_port: u16,
    pub ingest_port: u16,

    pub database_url: SecretString,
    pub database_max_connections: u32,

    pub s3_bucket: String,
    pub s3_region: String,
    pub s3_endpoint: Option<String>,
    pub s3_access_key_id: String,
    pub s3_secret_access_key: SecretString,
    pub s3_public_url_base: Option<String>,
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

            database_url: env_secret_or(
                "DATABASE_URL",
                "postgres://iono:iono@localhost:5432/iono",
            ),
            database_max_connections: env_or("DATABASE_MAX_CONNECTIONS", "10")
                .parse()
                .expect("DATABASE_MAX_CONNECTIONS malformed"),

            s3_bucket: env_or("S3_BUCKET", "iono-uploads"),
            s3_region: env_or("S3_REGION", "auto"),
            s3_endpoint: env::var("S3_ENDPOINT").ok().filter(|s| !s.is_empty()),
            s3_access_key_id: env_or("S3_ACCESS_KEY_ID", ""),
            s3_secret_access_key: env_secret_or("S3_SECRET_ACCESS_KEY", ""),
            s3_public_url_base: env::var("S3_PUBLIC_URL_BASE")
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
