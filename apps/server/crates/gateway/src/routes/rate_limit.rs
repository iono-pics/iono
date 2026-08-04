use actix_governor::governor::middleware::StateInformationMiddleware;
use actix_governor::{GovernorConfig, GovernorConfigBuilder};
use iono_core::{config::Config, rate_limit::ClientIpKeyExtractor};

pub type AuthGovernor = GovernorConfig<ClientIpKeyExtractor, StateInformationMiddleware>;

pub fn auth_governor(config: &Config) -> AuthGovernor {
    GovernorConfigBuilder::default()
        .key_extractor(ClientIpKeyExtractor)
        .seconds_per_request(config.auth_rate_limit_seconds_per_request)
        .burst_size(config.auth_rate_limit_burst)
        .use_headers()
        .finish()
        .expect("governor ratelimit failed to build")
}
