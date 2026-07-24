use iono_core::{state::HasDb, Config};
use sqlx::PgPool;
use webauthn_rs::Webauthn;

pub struct AppState {
    pub db: PgPool,
    pub config: Config,
    pub webauthn: Webauthn,
}

impl HasDb for AppState {
    fn db(&self) -> &PgPool {
        &self.db
    }
}
