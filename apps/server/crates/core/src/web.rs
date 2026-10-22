use actix_cors::Cors;
use actix_web::{
    dev::Payload,
    http::{header, Method, StatusCode},
    web, FromRequest, HttpRequest, HttpResponse, ResponseError,
};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::json;
use std::fmt;
use std::future::Future;

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
            tracing::error!(error = %self.0, "internal error");
            return HttpResponse::build(status).json(json!({ "error": "internal server error" }));
        }
        HttpResponse::build(status).json(json!({ "error": self.0.to_string() }))
    }
}

pub type ApiResult<T> = Result<T, ApiError>;

pub fn app_state<T: 'static>(req: &HttpRequest) -> Result<web::Data<T>, ApiError> {
    req.app_data::<web::Data<T>>()
        .cloned()
        .ok_or_else(|| ApiError(AppError::internal("AppState not registered")))
}

pub fn cors(methods: impl IntoIterator<Item = Method>) -> Cors {
    Cors::default()
        .allow_any_origin()
        .allowed_methods(methods)
        .allowed_headers(vec![header::AUTHORIZATION, header::CONTENT_TYPE])
        .max_age(3600)
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
