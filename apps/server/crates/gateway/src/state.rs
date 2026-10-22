use iono_core::{
    cloudflare::CloudflareClient,
    crypto::Keyring,
    deletion::Deleter,
    oauth::OAuthClient,
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
    pub discord: Arc<OAuthClient>,
    pub stripe: Option<stripe::Client>,
    pub config: Config,
    pub webauthn: Webauthn,
    /// seals totp secrets at rest
    pub keyring: Keyring,
}

impl AppState {
    /// finishes queued deletions off the request path, whatever fails here
    /// stays queued for the janitor
    pub fn process_deletions(&self, ids: Vec<String>) {
        if ids.is_empty() {
            return;
        }
        let db = self.db.clone();
        let storage = self.storage.clone();
        let cloudflare = self.cloudflare.clone();
        tokio::spawn(async move {
            let deleter = Deleter {
                db: &db,
                storage: storage.as_ref(),
                cloudflare: &cloudflare,
            };
            if let Err(e) = deleter.process_ids(&ids).await {
                tracing::warn!(error = %e, "pending deletions left for the janitor");
            }
        });
    }
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
