use actix_governor::governor::middleware::StateInformationMiddleware;
use actix_governor::{GovernorConfig, GovernorConfigBuilder};
use iono_core::rate_limit::ClientKeyExtractor;

pub type IngestGovernor = GovernorConfig<ClientKeyExtractor, StateInformationMiddleware>;

pub fn ingest_governor(jwt_secret: &str) -> IngestGovernor {
    GovernorConfigBuilder::default()
        .key_extractor(ClientKeyExtractor::new(jwt_secret))
        .seconds_per_request(1)
        .burst_size(30)
        .use_headers()
        .finish()
        .expect("governor ratelimit failed to build")
}
