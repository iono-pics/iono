use iono_core::state::CoreState;
use secrecy::SecretString;
use std::sync::Mutex;
use tokio::task::JoinHandle;

pub struct AppState {
    pub core: CoreState,
    pub maintenance_token: SecretString,
    pub bg: tokio::runtime::Handle,
    pub sweep_task: Mutex<Option<JoinHandle<()>>>,
}
