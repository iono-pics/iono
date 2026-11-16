use actix_governor::governor::middleware::StateInformationMiddleware;
use actix_governor::{GovernorConfig, GovernorConfigBuilder};
use iono_core::{
    config::Config,
    rate_limit::{ClientIpKeyExtractor, ClientKeyExtractor},
};

pub type IngestGovernor = GovernorConfig<ClientKeyExtractor, StateInformationMiddleware>;
pub type PartsGovernor = GovernorConfig<ClientIpKeyExtractor, StateInformationMiddleware>;

const PARTS_MILLISECONDS_PER_REQUEST: u64 = 100;
const PARTS_BURST: u32 = 200;

/// limits requests to the part route by client address. a large file is sent
/// as hundreds of parts, so the rate is high. it bounds requests that fail
/// authentication, and concurrent part uploads are capped separately
pub fn parts_governor() -> PartsGovernor {
    GovernorConfigBuilder::default()
        .key_extractor(ClientIpKeyExtractor)
        .milliseconds_per_request(PARTS_MILLISECONDS_PER_REQUEST)
        .burst_size(PARTS_BURST)
        .use_headers()
        .finish()
        .unwrap_or_else(|| {
            iono_core::bootstrap::fatal(
                "build the part upload rate limiter",
                &"the part upload limits must be greater than zero",
            )
        })
}

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
