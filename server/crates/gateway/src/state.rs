use iono_core::Config;
use sqlx::PgPool;
use webauthn_rs::Webauthn;

pub struct AppState {
    pub db: PgPool,
    pub config: Config,
    pub webauthn: Webauthn,
}
