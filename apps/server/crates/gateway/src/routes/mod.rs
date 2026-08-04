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
        auth::verify_passkey_start::verify_passkey_start,
        auth::verify_passkey_finish::verify_passkey_finish,
        auth::passkey_login_start::passkey_login_start,
        auth::passkey_login_finish::passkey_login_finish,
        auth::restore::restore,
        auth::discord::start::discord_start,
        auth::discord::callback::discord_callback,
        auth::discord::login::discord_login,
        user::connections::discord::unlink_discord,
        user::connections::discord::start_link_discord,
        user::me::me,
        user::api_keys::regenerate_apikey,
        user::storage::get_storage,
        user::export::export_data,
        user::settings::update::update_settings,
        user::settings::domains::get_domain_settings,
        user::settings::domains::update_domain_settings,
        user::embeds::settings::get_embed_settings,
        user::embeds::settings::update_embed_settings,
        user::embeds::presets::list::list_embed_presets,
        user::embeds::presets::create::create_embed_preset,
        user::embeds::presets::update::update_embed_preset,
        user::embeds::presets::delete::delete_embed_preset,
        user::embeds::variables::list_embed_variables,
        user::change_password::change_password,
        user::delete_account::delete_account,
        user::redeem::redeem_code,
        user::billing::portal::create_portal_session,
        user::totp::setup::setup_totp,
        user::totp::confirm::confirm_totp,
        user::totp::disable::disable_totp,
        user::totp::recovery_codes::regenerate_recovery_codes,
        user::passkeys::register_start::register_start,
        user::passkeys::register_finish::register_finish,
        user::passkeys::list::list_passkeys,
        user::passkeys::remove::remove_passkey,
        user::passkeys::require::require_passkey,
        user::files::list::list_files,
        user::files::delete::delete_file,
        user::files::update::update_file,
        user::folders::create::create_folder,
        user::folders::list::list_folders,
        user::folders::update::update_folder,
        user::folders::delete::delete_folder,
        user::pastes::list::list_pastes,
        user::pastes::delete::delete_paste,
        user::pastes::update::update_paste,
        user::links::list::list_short_links,
        user::links::delete::delete_short_link,
        user::links::update::update_short_link,
        user::sharex::sharex_config,
    ),
    components(schemas(
        auth::signup::SignupRequest,
        auth::login::LoginRequest,
        auth::verify_totp::VerifyLoginTotpRequest,
        auth::verify_passkey_start::VerifyPasskeyStartRequest,
        auth::verify_passkey_finish::VerifyPasskeyFinishRequest,
        auth::passkey_login_start::PasskeyLoginStartRequest,
        auth::passkey_login_finish::PasskeyLoginFinishRequest,
        auth::restore::RestoreRequest,
        auth::discord::login::DiscordLoginRequest,
        auth::discord::DiscordAuthResponse,
        user::storage::StorageUsage,
        user::export::ExportType,
        user::settings::update::UpdateSettingsRequest,
        user::settings::update::SelfDestructDuration,
        user::settings::domains::DomainSettingsResponse,
        user::settings::domains::UpdateDomainSettingsRequest,
        user::embeds::settings::EmbedSettingsResponse,
        user::embeds::settings::UpdateEmbedSettingsRequest,
        user::embeds::presets::EmbedPresetResponse,
        user::embeds::presets::create::CreateEmbedPresetRequest,
        user::embeds::presets::update::UpdateEmbedPresetRequest,
        user::embeds::variables::EmbedVariableSummary,
        DisplayNameStyle,
        user::change_password::ChangePasswordRequest,
        user::redeem::RedeemRequest,
        user::totp::ReauthRequest,
        user::totp::confirm::ConfirmTotpRequest,
        user::passkeys::register_finish::FinishRegisterPasskeyRequest,
        user::passkeys::list::PasskeySummary,
        user::passkeys::require::RequirePasskeyRequest,
        user::files::list::FileSummary,
        user::files::update::UpdateFileRequest,
        user::folders::FolderSummary,
        user::folders::create::CreateFolderRequest,
        user::folders::update::UpdateFolderRequest,
        user::pastes::list::PasteSummary,
        user::pastes::update::UpdatePasteRequest,
        user::links::list::ShortLinkSummary,
        user::links::update::UpdateShortLinkRequest,
        user::sharex::DestinationKind,
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
