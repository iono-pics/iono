use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("not found")]
    NotFound,

    #[error("unauthorized")]
    Unauthorized,

    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("payment required: {0}")]
    PaymentRequired(String),

    #[error("range not satisfiable")]
    RangeNotSatisfiable,

    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("internal error: {message}")]
    Internal {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
}

impl AppError {
    pub fn internal(message: impl Into<String>) -> Self {
        AppError::Internal {
            message: message.into(),
            source: None,
        }
    }

    pub fn internal_from(
        message: impl Into<String>,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        AppError::Internal {
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }
}

pub type AppResult<T> = Result<T, AppError>;
