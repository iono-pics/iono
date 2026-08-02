pub mod api_keys;
pub mod change_password;
pub mod delete_account;
pub mod embeds;
pub mod files;
pub mod folders;
pub mod links;
pub mod me;
pub mod passkeys;
pub mod pastes;
pub mod settings;
pub mod sharex;
pub mod storage;
pub mod totp;

use actix_governor::Governor;
use actix_web::dev::HttpServiceFactory;
use actix_web::web;

use crate::routes::rate_limit::AUTH_GOVERNOR;

pub fn scope() -> impl HttpServiceFactory {
    web::scope("/user")
        .service(me::me)
        .service(api_keys::regenerate_apikey)
        .service(storage::get_storage)
        .service(settings::update::update_settings)
        .service(settings::domains::get_domain_settings)
        .service(settings::domains::update_domain_settings)
        .service(embeds::settings::get_embed_settings)
        .service(embeds::settings::update_embed_settings)
        .service(embeds::presets::list::list_embed_presets)
        .service(embeds::presets::create::create_embed_preset)
        .service(embeds::presets::update::update_embed_preset)
        .service(embeds::presets::delete::delete_embed_preset)
        .service(passkeys::list::list_passkeys)
        .service(files::list::list_files)
        .service(files::delete::delete_file)
        .service(files::update::update_file)
        .service(folders::create::create_folder)
        .service(folders::list::list_folders)
        .service(folders::update::update_folder)
        .service(folders::delete::delete_folder)
        .service(pastes::list::list_pastes)
        .service(pastes::delete::delete_paste)
        .service(pastes::update::update_paste)
        .service(links::list::list_short_links)
        .service(links::delete::delete_short_link)
        .service(links::update::update_short_link)
        .service(sharex::sharex_config)
        .service(
            web::scope("")
                .wrap(Governor::new(&AUTH_GOVERNOR))
                .service(change_password::change_password)
                .service(delete_account::delete_account)
                .service(totp::setup::setup_totp)
                .service(totp::confirm::confirm_totp)
                .service(totp::disable::disable_totp)
                .service(totp::recovery_codes::regenerate_recovery_codes)
                .service(passkeys::register_start::register_start)
                .service(passkeys::register_finish::register_finish)
                .service(passkeys::remove::remove_passkey)
                .service(passkeys::require::require_passkey),
        )
}
