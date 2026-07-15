use actix_cors::Cors;
use actix_web::{
    dev::Payload,
    http::{header, Method, StatusCode},
    web, FromRequest, HttpRequest, HttpResponse, ResponseError,
};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use serde_json::json;
use std::fmt;
use std::future::Future;

use crate::error::AppError;

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
            AppError::RangeNotSatisfiable => StatusCode::RANGE_NOT_SATISFIABLE,
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
    match password {
        Some(p) => format!("{base}?password={}", utf8_percent_encode(p, NON_ALPHANUMERIC)),
        None => base.to_string(),
    }
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
