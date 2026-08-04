use chrono::{DateTime, Utc};

use crate::error::AppError;

pub fn no_nul(value: &str, label: &str) -> Result<(), AppError> {
    if value.contains('\0') {
        return Err(AppError::BadRequest(format!(
            "{label} must not contain null bytes"
        )));
    }
    Ok(())
}

pub fn paste_content(value: &str, max_bytes: usize, label: &str) -> Result<(), AppError> {
    if value.is_empty() {
        return Err(AppError::BadRequest(format!("{label} must not be empty")));
    }
    if value.len() > max_bytes {
        return Err(AppError::BadRequest(format!(
            "{label} must be at most {} KiB",
            max_bytes / 1024
        )));
    }
    no_nul(value, label)
}

pub fn http_url(value: &str, max_len: usize) -> Result<(), AppError> {
    if value.len() > max_len {
        return Err(AppError::BadRequest(format!(
            "URL must be at most {max_len} characters"
        )));
    }
    no_nul(value, "URL")?;
    if !value.starts_with("http://") && !value.starts_with("https://") {
        return Err(AppError::BadRequest(
            "URL must start with http:// or https://".into(),
        ));
    }
    Ok(())
}

pub fn future_datetime(value: DateTime<Utc>) -> Result<(), AppError> {
    if value <= Utc::now() {
        return Err(AppError::BadRequest(
            "expiration must be in the future".into(),
        ));
    }
    Ok(())
}

pub fn password(value: &str, max_len: usize) -> Result<(), AppError> {
    if value.is_empty() || value.len() > max_len {
        return Err(AppError::BadRequest(format!(
            "password must be 1-{max_len} characters, or null to remove it"
        )));
    }
    no_nul(value, "password")
}

pub fn text_length(value: &str, max_chars: usize, label: &str) -> Result<(), AppError> {
    if value.chars().count() > max_chars {
        return Err(AppError::BadRequest(format!(
            "{label} must be at most {max_chars} characters"
        )));
    }
    no_nul(value, label)
}

pub fn hex_color(value: &str) -> Result<(), AppError> {
    if value.len() != 7
        || !value.starts_with('#')
        || !value[1..].chars().all(|c| c.is_ascii_hexdigit())
    {
        return Err(AppError::BadRequest("color must be #RRGGBB".into()));
    }
    Ok(())
}
