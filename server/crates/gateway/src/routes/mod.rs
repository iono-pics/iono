pub mod auth;
pub mod rate_limit;
pub mod user;

use actix_web::{get, web};
use iono_core::{entities::DisplayNameStyle, openapi::BearerSecurity};
use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(
    info(title = "iono gateway", description = "auth and account management"),
    paths(
        auth::signup::signup,
        auth::login::login,
        auth::verify_totp::verify_login_totp,
        user::me::me,
        user::api_keys::regenerate_apikey,
        user::settings::update_settings,
        user::change_password::change_password,
        user::totp::setup::setup_totp,
        user::totp::confirm::confirm_totp,
        user::totp::disable::disable_totp,
        user::totp::recovery_codes::regenerate_recovery_codes,
    ),
    components(schemas(
        auth::signup::SignupRequest,
        auth::login::LoginRequest,
        auth::verify_totp::VerifyLoginTotpRequest,
        user::settings::UpdateSettingsRequest,
        user::settings::SelfDestructDuration,
        DisplayNameStyle,
        user::change_password::ChangePasswordRequest,
        user::totp::ReauthRequest,
        user::totp::confirm::ConfirmTotpRequest,
    )),
    modifiers(&BearerSecurity)
)]
struct ApiDoc;

#[get("/openapi.json")]
async fn openapi_spec() -> web::Json<utoipa::openapi::OpenApi> {
    web::Json(ApiDoc::openapi())
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(auth::scope())
        .service(user::scope())
        .service(openapi_spec);
}
