pub mod api_keys;
pub mod login;
pub mod me;
pub mod signup;

use actix_governor::governor::middleware::NoOpMiddleware;
use actix_governor::{Governor, GovernorConfig, GovernorConfigBuilder, PeerIpKeyExtractor};
use actix_web::web;
use std::sync::LazyLock;

static AUTH_GOVERNOR: LazyLock<GovernorConfig<PeerIpKeyExtractor, NoOpMiddleware>> =
    LazyLock::new(|| {
        GovernorConfigBuilder::default()
            .seconds_per_request(2)
            .burst_size(5)
            .finish()
            .expect("governor ratelimit failed to build")
    });

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/auth")
            .wrap(Governor::new(&AUTH_GOVERNOR))
            .service(signup::signup)
            .service(login::login),
    )
    .service(
        web::scope("/user")
            .service(me::me)
            .service(api_keys::regenerate_apikey),
    );
}
