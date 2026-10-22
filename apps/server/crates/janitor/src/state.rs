use iono_core::{cloudflare::CloudflareClient, state::CoreState};
use secrecy::SecretString;
use std::sync::Mutex;
use tokio::task::JoinHandle;

pub struct AppState {
    pub core: CoreState,
    pub cloudflare: CloudflareClient,
    pub maintenance_token: SecretString,
    pub bg: tokio::runtime::Handle,
    pub sweep_task: Mutex<Option<JoinHandle<()>>>,
    pub backfill_task: Mutex<Option<JoinHandle<()>>>,
}
