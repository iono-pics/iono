use crate::state::AppState;

pub type ApiKeyUser = iono_core::auth::ApiKeyUser<AppState>;
pub type AuthedUser = iono_core::auth::AuthedUser<AppState>;
