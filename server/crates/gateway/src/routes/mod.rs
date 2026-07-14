pub mod api_keys;
pub mod login;
pub mod me;
pub mod signup;

use actix_governor::governor::middleware::NoOpMiddleware;
use actix_governor::{
    Governor, GovernorConfig, GovernorConfigBuilder, KeyExtractor, SimpleKeyExtractionError,
};
use actix_web::dev::ServiceRequest;
use actix_web::{get, web};
use std::net::IpAddr;
use std::sync::LazyLock;
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi};

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
        api_keys::regenerate_apikey
    ),
    components(schemas(signup::SignupRequest, login::LoginRequest)),
    modifiers(&BearerSecurity)
)]
struct ApiDoc;

struct BearerSecurity;

impl Modify for BearerSecurity {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        openapi
            .components
            .get_or_insert_with(Default::default)
            .add_security_scheme(
                "bearer_auth",
                SecurityScheme::Http(HttpBuilder::new().scheme(HttpAuthScheme::Bearer).build()),
            );
    }
}

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
            .service(api_keys::regenerate_apikey),
    )
    .service(openapi_spec);
}
