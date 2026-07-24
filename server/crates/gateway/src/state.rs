use iono_core::{
    state::{HasDb, HasJwtSecret},
    Config,
};
use secrecy::SecretString;
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

impl HasJwtSecret for AppState {
    fn jwt_secret(&self) -> &SecretString {
        &self.config.jwt_secret
    }
}
