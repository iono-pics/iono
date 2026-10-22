use iono_core::{config::Config, state::CoreState};
use std::ops::Deref;

use crate::unlock::Unlocker;

pub struct AppState {
    pub core: CoreState,
    pub unlocker: Unlocker,
}

impl AppState {
    pub async fn build(config: &Config) -> Self {
        Self {
            core: CoreState::build(config).await,
            unlocker: Unlocker::default(),
        }
    }
}

impl Deref for AppState {
    type Target = CoreState;

    fn deref(&self) -> &CoreState {
        &self.core
    }
}
