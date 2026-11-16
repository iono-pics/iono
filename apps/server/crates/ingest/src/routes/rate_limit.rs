use actix_governor::governor::middleware::StateInformationMiddleware;
use actix_governor::{GovernorConfig, GovernorConfigBuilder};
use iono_core::{config::Config, rate_limit::ClientKeyExtractor};

pub type IngestGovernor = GovernorConfig<ClientKeyExtractor, StateInformationMiddleware>;

pub fn ingest_governor(config: &Config, jwt_secret: &str) -> IngestGovernor {
    GovernorConfigBuilder::default()
        .key_extractor(ClientKeyExtractor::new(jwt_secret))
        .seconds_per_request(config.ingest_rate_limit_seconds_per_request)
        .burst_size(config.ingest_rate_limit_burst)
        .use_headers()
        .finish()
        .unwrap_or_else(|| {
            iono_core::bootstrap::fatal(
                "build the ingest rate limiter",
                &"INGEST_RATE_LIMIT_* values must be greater than zero",
            )
        })
}
