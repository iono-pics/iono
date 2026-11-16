use actix_cors::Cors;
use actix_web::{
    body::MessageBody,
    dev::{Payload, ServiceRequest, ServiceResponse},
    http::{header, Method, StatusCode},
    middleware::DefaultHeaders,
    web, Error, FromRequest, HttpRequest, HttpResponse, ResponseError,
};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::json;
use std::fmt;
use std::future::Future;
use tracing::Span;
use tracing_actix_web::{DefaultRootSpanBuilder, RootSpanBuilder};

use crate::config::Config;
use crate::error::AppError;

#[derive(Debug, Clone, Default)]
pub enum Patch<T> {
    #[default]
    Missing,
    Null,
    Set(T),
}

impl<T> Patch<T> {
    pub fn split(self) -> (bool, Option<T>) {
        match self {
            Self::Missing => (false, None),
            Self::Null => (true, None),
            Self::Set(v) => (true, Some(v)),
        }
    }

    pub fn is_provided(&self) -> bool {
        !matches!(self, Self::Missing)
    }

    pub fn as_set(&self) -> Option<&T> {
        match self {
            Self::Set(v) => Some(v),
            _ => None,
        }
    }
}

impl<T: std::ops::Deref> Patch<T> {
    pub fn as_deref(&self) -> Option<&T::Target> {
        self.as_set().map(|v| &**v)
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Patch<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<T>::deserialize(deserializer).map(|opt| match opt {
            Some(v) => Self::Set(v),
            None => Self::Null,
        })
    }
}

impl<T: Serialize> Serialize for Patch<T> {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Missing | Self::Null => ser.serialize_none(),
            Self::Set(v) => ser.serialize_some(v),
        }
    }
}

#[derive(Debug)]
pub struct ApiError(pub AppError);

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<AppError> for ApiError {
    fn from(e: AppError) -> Self {
        Self(e)
    }
}

impl ResponseError for ApiError {
    fn status_code(&self) -> StatusCode {
        match &self.0 {
            AppError::NotFound => StatusCode::NOT_FOUND,
            AppError::Unauthorized => StatusCode::UNAUTHORIZED,
            AppError::BadRequest(_) => StatusCode::BAD_REQUEST,
            AppError::Conflict(_) => StatusCode::CONFLICT,
            AppError::PaymentRequired(_) => StatusCode::PAYMENT_REQUIRED,
            AppError::PayloadTooLarge(_) => StatusCode::PAYLOAD_TOO_LARGE,
            AppError::RangeNotSatisfiable => StatusCode::RANGE_NOT_SATISFIABLE,
            AppError::Gone(_) => StatusCode::GONE,
            AppError::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            AppError::Database(_) | AppError::Io(_) | AppError::Internal { .. } => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    }

    fn error_response(&self) -> HttpResponse {
        let status = self.status_code();
        if status == StatusCode::INTERNAL_SERVER_ERROR {
            tracing::error!(error = %error_chain(&self.0), "internal error");
            return HttpResponse::build(status).json(json!({ "error": "internal server error" }));
        }
        HttpResponse::build(status).json(json!({ "error": self.0.to_string() }))
    }
}

/// the error and each of its sources, outermost first, so a log line shows
/// the root cause and not just the wrapper message
fn error_chain(error: &dyn std::error::Error) -> String {
    let mut out = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        out.push_str(": ");
        out.push_str(&cause.to_string());
        source = cause.source();
    }
    out
}

pub type ApiResult<T> = Result<T, ApiError>;

pub fn app_state<T: 'static>(req: &HttpRequest) -> Result<web::Data<T>, ApiError> {
    req.app_data::<web::Data<T>>()
        .cloned()
        .ok_or_else(|| ApiError(AppError::internal("AppState not registered")))
}

/// allows only `CORS_ALLOWED_ORIGINS`, and no origin when it is empty
pub fn cors(config: &Config, methods: impl IntoIterator<Item = Method>) -> Cors {
    config
        .cors_allowed_origins
        .iter()
        .fold(Cors::default(), |cors, origin| cors.allowed_origin(origin))
        .allowed_methods(methods)
        .allowed_headers(vec![header::AUTHORIZATION, header::CONTENT_TYPE])
        .max_age(3600)
}

/// headers for every response, including pages that set their own cache policy
pub fn baseline_headers() -> DefaultHeaders {
    DefaultHeaders::new()
        .add((header::X_CONTENT_TYPE_OPTIONS, "nosniff"))
        .add((header::REFERRER_POLICY, "no-referrer"))
}

/// headers for json api responses, which are never cached or rendered
pub fn security_headers() -> DefaultHeaders {
    baseline_headers()
        .add((header::CACHE_CONTROL, "no-store"))
        .add((
            header::CONTENT_SECURITY_POLICY,
            "default-src 'none'; frame-ancestors 'none'",
        ))
}

/// the largest json body any endpoint takes: a paste at the size limit with
/// every byte escaped to six, plus room for the other fields
pub fn max_json_body_bytes(config: &Config) -> usize {
    config
        .max_paste_content_bytes
        .saturating_mul(6)
        .saturating_add(64 * 1024)
}

/// json bodies over [`max_json_body_bytes`] are refused with 413
pub fn json_config(config: &Config) -> web::JsonConfig {
    web::JsonConfig::default().limit(max_json_body_bytes(config))
}

/// the same cap for the `Bytes` and `String` extractors
pub fn payload_config(config: &Config) -> web::PayloadConfig {
    web::PayloadConfig::new(max_json_body_bytes(config))
}

/// how long a client may take to send its request head
pub const CLIENT_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// how long a disconnecting client may keep a connection open
pub const CLIENT_DISCONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// open connections per worker
pub const MAX_CONNECTIONS_PER_WORKER: usize = 2048;

/// records the request path only, since query strings can carry passwords and
/// decryption keys
pub struct PathOnlyRootSpan;

impl RootSpanBuilder for PathOnlyRootSpan {
    fn on_request_start(request: &ServiceRequest) -> Span {
        tracing::info_span!(
            "HTTP request",
            http.method = %request.method(),
            http.target = %request.uri().path(),
            http.status_code = tracing::field::Empty,
            otel.status_code = tracing::field::Empty,
            exception.message = tracing::field::Empty,
            exception.details = tracing::field::Empty,
        )
    }

    fn on_request_end<B: MessageBody>(span: Span, outcome: &Result<ServiceResponse<B>, Error>) {
        DefaultRootSpanBuilder::on_request_end(span, outcome);
    }
}

pub fn append_password_query(base: &str, password: Option<&str>) -> String {
    append_query(base, &[("password", password)])
}

pub fn append_query(base: &str, params: &[(&str, Option<&str>)]) -> String {
    let mut url = base.to_string();
    for (name, value) in params {
        let Some(value) = value else { continue };
        url.push(if url.contains('?') { '&' } else { '?' });
        url.push_str(name);
        url.push('=');
        url.push_str(&utf8_percent_encode(value, NON_ALPHANUMERIC).to_string());
    }
    url
}

pub fn state_and_bearer<T: 'static>(
    req: &HttpRequest,
    payload: &mut Payload,
) -> impl Future<Output = Result<(web::Data<T>, BearerAuth), ApiError>> {
    let bearer = BearerAuth::from_request(req, payload);
    let req = req.clone();
    async move {
        let state = app_state::<T>(&req)?;
        let bearer = bearer.await.map_err(|_| ApiError(AppError::Unauthorized))?;
        Ok((state, bearer))
    }
}

#[derive(Default)]
pub struct MapDbError {
    unique: Option<AppError>,
    foreign_key: Option<AppError>,
    check: Option<AppError>,
}

impl MapDbError {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn on_unique(mut self, err: AppError) -> Self {
        self.unique = Some(err);
        self
    }

    pub fn on_unique_conflict(self, message: impl Into<String>) -> Self {
        self.on_unique(AppError::Conflict(message.into()))
    }

    pub fn on_foreign_key(mut self, err: AppError) -> Self {
        self.foreign_key = Some(err);
        self
    }

    pub fn on_foreign_key_not_found(self) -> Self {
        self.on_foreign_key(AppError::NotFound)
    }

    pub fn on_check(mut self, err: AppError) -> Self {
        self.check = Some(err);
        self
    }

    pub fn on_check_conflict(self, message: impl Into<String>) -> Self {
        self.on_check(AppError::Conflict(message.into()))
    }

    pub fn build(self) -> impl FnOnce(sqlx::Error) -> AppError {
        move |e| {
            if let sqlx::Error::Database(db_err) = &e {
                let mapped = match db_err.kind() {
                    sqlx::error::ErrorKind::UniqueViolation => self.unique,
                    sqlx::error::ErrorKind::ForeignKeyViolation => self.foreign_key,
                    sqlx::error::ErrorKind::CheckViolation => self.check,
                    _ => None,
                };
                if let Some(mapped) = mapped {
                    return mapped;
                }
            }
            AppError::from(e)
        }
    }
}

pub trait OptionExt<T> {
    fn ok_or_not_found(self) -> Result<T, AppError>;
}

impl<T> OptionExt<T> for Option<T> {
    fn ok_or_not_found(self) -> Result<T, AppError> {
        self.ok_or(AppError::NotFound)
    }
}

#[derive(Debug, Default, Deserialize)]
pub struct Page {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

impl Page {
    pub fn resolve(&self, default: i64, max: i64) -> (i64, i64) {
        let limit = self.limit.unwrap_or(default).clamp(1, max);
        let offset = self.offset.unwrap_or(0).max(0);
        (limit, offset)
    }
}
