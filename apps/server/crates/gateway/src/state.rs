use iono_core::{
    cloudflare::CloudflareClient,
    state::{HasDb, HasJwtSecret},
    storage::Storage,
    Config,
};
use secrecy::SecretString;
use sqlx::PgPool;
use std::sync::Arc;
use webauthn_rs::Webauthn;

pub struct AppState {
    pub db: PgPool,
    pub storage: Arc<dyn Storage>,
    pub cloudflare: Arc<CloudflareClient>,
    pub stripe: Option<stripe::Client>,
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
