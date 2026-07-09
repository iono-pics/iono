use iono_core::{storage::Storage, Config};
use std::sync::Arc;

pub struct AppState {
    pub storage: Arc<dyn Storage>,
    pub config: Config,
}
