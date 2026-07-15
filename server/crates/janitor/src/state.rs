use iono_core::storage::Storage;
use secrecy::SecretString;
use sqlx::PgPool;
use std::sync::{Arc, Mutex};
use tokio::task::JoinHandle;

pub struct AppState {
    pub storage: Arc<dyn Storage>,
    pub db: PgPool,
    pub maintenance_token: SecretString,
    pub bg: tokio::runtime::Handle,
    pub sweep_task: Mutex<Option<JoinHandle<()>>>,
}
