use actix_governor::governor::middleware::StateInformationMiddleware;
use actix_governor::{GovernorConfig, GovernorConfigBuilder};
use iono_core::rate_limit::ClientIpKeyExtractor;
use std::sync::LazyLock;

pub static AUTH_GOVERNOR: LazyLock<
    GovernorConfig<ClientIpKeyExtractor, StateInformationMiddleware>,
> = LazyLock::new(|| {
    GovernorConfigBuilder::default()
        .key_extractor(ClientIpKeyExtractor)
        .seconds_per_request(2)
        .burst_size(5)
        .use_headers()
        .finish()
        .expect("governor ratelimit failed to build")
});
