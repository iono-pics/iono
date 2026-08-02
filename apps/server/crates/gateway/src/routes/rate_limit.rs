use actix_governor::governor::middleware::NoOpMiddleware;
use actix_governor::{
    GovernorConfig, GovernorConfigBuilder, KeyExtractor, SimpleKeyExtractionError,
};
use actix_web::dev::ServiceRequest;
use std::net::IpAddr;
use std::sync::LazyLock;

// container only sees cf's proxy as peer so we need to read from
// CF-Connecting-IP for ratelimiting otherwise all ips would be blocked
#[derive(Clone)]
pub struct ClientIpKeyExtractor;

impl KeyExtractor for ClientIpKeyExtractor {
    type Key = IpAddr;
    type KeyExtractionError = SimpleKeyExtractionError<&'static str>;

    fn extract(&self, req: &ServiceRequest) -> Result<Self::Key, Self::KeyExtractionError> {
        if let Some(ip) = req
            .headers()
            .get("cf-connecting-ip")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse::<IpAddr>().ok())
        {
            return Ok(ip);
        }
        req.peer_addr()
            .map(|addr| addr.ip())
            .ok_or_else(|| SimpleKeyExtractionError::new("could not determine client ip"))
    }
}

pub static AUTH_GOVERNOR: LazyLock<GovernorConfig<ClientIpKeyExtractor, NoOpMiddleware>> =
    LazyLock::new(|| {
        GovernorConfigBuilder::default()
            .key_extractor(ClientIpKeyExtractor)
            .seconds_per_request(2)
            .burst_size(5)
            .finish()
            .expect("governor ratelimit failed to build")
    });
