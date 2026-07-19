pub mod login;
pub mod passkey_login_finish;
pub mod passkey_login_start;
pub mod signup;
pub mod verify_passkey_finish;
pub mod verify_passkey_start;
pub mod verify_totp;

use actix_governor::Governor;
use actix_web::dev::HttpServiceFactory;
use actix_web::web;

use crate::routes::rate_limit::AUTH_GOVERNOR;

pub fn scope() -> impl HttpServiceFactory {
    web::scope("/auth")
        .wrap(Governor::new(&AUTH_GOVERNOR))
        .service(signup::signup)
        .service(login::login)
        .service(verify_totp::verify_login_totp)
        .service(verify_passkey_start::verify_passkey_start)
        .service(verify_passkey_finish::verify_passkey_finish)
        .service(passkey_login_start::passkey_login_start)
        .service(passkey_login_finish::passkey_login_finish)
}
