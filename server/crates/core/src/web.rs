use actix_web::{http::StatusCode, web, HttpRequest, HttpResponse, ResponseError};
use serde_json::json;
use std::fmt;

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
