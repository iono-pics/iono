pub mod login;
pub mod signup;
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
}
