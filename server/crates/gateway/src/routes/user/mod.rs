pub mod api_keys;
pub mod change_password;
pub mod links;
pub mod me;
pub mod passkeys;
pub mod pastes;
pub mod settings;
pub mod sharex;
pub mod totp;

use actix_governor::Governor;
use actix_web::dev::HttpServiceFactory;
use actix_web::web;

use crate::routes::rate_limit::AUTH_GOVERNOR;

pub fn scope() -> impl HttpServiceFactory {
    web::scope("/user")
        .service(me::me)
        .service(api_keys::regenerate_apikey)
        .service(settings::update_settings)
        .service(passkeys::list::list_passkeys)
        .service(pastes::list::list_pastes)
        .service(pastes::delete::delete_paste)
        .service(links::list::list_short_links)
        .service(links::delete::delete_short_link)
        .service(sharex::sharex_config)
        .service(
            web::scope("")
                .wrap(Governor::new(&AUTH_GOVERNOR))
                .service(change_password::change_password)
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
