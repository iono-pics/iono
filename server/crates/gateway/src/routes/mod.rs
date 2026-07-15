pub mod api_keys;
pub mod login;
pub mod me;
pub mod settings;
pub mod signup;

use actix_governor::governor::middleware::NoOpMiddleware;
use actix_governor::{
    Governor, GovernorConfig, GovernorConfigBuilder, KeyExtractor, SimpleKeyExtractionError,
};
use actix_web::dev::ServiceRequest;
use actix_web::{get, web};
use iono_core::{entities::DisplayNameStyle, openapi::BearerSecurity};
use std::net::IpAddr;
use std::sync::LazyLock;
use utoipa::OpenApi;

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

static AUTH_GOVERNOR: LazyLock<GovernorConfig<ClientIpKeyExtractor, NoOpMiddleware>> =
    LazyLock::new(|| {
        GovernorConfigBuilder::default()
            .key_extractor(ClientIpKeyExtractor)
            .seconds_per_request(2)
            .burst_size(5)
            .finish()
            .expect("governor ratelimit failed to build")
    });

#[derive(OpenApi)]
#[openapi(
    info(title = "iono gateway", description = "auth and account management"),
    paths(
        signup::signup,
        login::login,
        me::me,
        api_keys::regenerate_apikey,
        settings::update_settings
    ),
    components(schemas(
        signup::SignupRequest,
        login::LoginRequest,
        settings::UpdateSettingsRequest,
        settings::SelfDestructDuration,
        DisplayNameStyle
    )),
    modifiers(&BearerSecurity)
)]
struct ApiDoc;

#[get("/openapi.json")]
async fn openapi_spec() -> web::Json<utoipa::openapi::OpenApi> {
    web::Json(ApiDoc::openapi())
}

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
            .service(api_keys::regenerate_apikey)
            .service(settings::update_settings),
    )
    .service(openapi_spec);
}
