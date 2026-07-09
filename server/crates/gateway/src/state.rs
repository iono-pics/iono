use iono_core::Config;
use sqlx::PgPool;

pub struct AppState {
    pub db: PgPool,
    pub config: Config,
}
