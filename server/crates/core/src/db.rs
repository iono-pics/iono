use secrecy::ExposeSecret;
use sqlx::postgres::{PgPool, PgPoolOptions};

use crate::config::Config;
use crate::error::AppResult;

pub async fn build(config: &Config) -> AppResult<PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(config.database_max_connections)
        .connect(config.database_url.expose_secret())
        .await?;

    Ok(pool)
}
