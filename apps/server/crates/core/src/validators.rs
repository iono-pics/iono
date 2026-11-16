use actix_web::http::Uri;
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
    let invalid = || AppError::BadRequest("URL must be an http:// or https:// address".into());
    if !value.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(invalid());
    }
    let uri: Uri = value.parse().map_err(|_| invalid())?;
    let has_credentials = uri
        .authority()
        .is_some_and(|authority| authority.as_str().contains('@'));
    if !matches!(uri.scheme_str(), Some("http" | "https"))
        || uri.host().is_none()
        || has_credentials
    {
        return Err(invalid());
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_http_and_https_urls_are_accepted() {
        for url in [
            "http://example.com",
            "https://example.com/a/b?c=d#e",
            "https://example.com:8443/x",
            "https://[2001:db8::1]/x",
            "https://example.com/%E2%9C%93",
        ] {
            assert!(http_url(url, 2048).is_ok(), "{url}");
        }
    }

    #[test]
    fn malformed_or_unsafe_urls_are_rejected() {
        for url in [
            "",
            "example.com",
            "//example.com",
            "ftp://example.com",
            "javascript:alert(1)",
            "https://",
            "https://user:pass@example.com",
            "https://user@example.com",
            "https://exa mple.com",
            "https://example.com/a b",
            "https://example.com/#frag\nment",
            "https://example.com/\u{e9}",
            "https://example.com/\r\nSet-Cookie: a=b",
        ] {
            assert!(http_url(url, 2048).is_err(), "{url:?}");
        }
    }

    #[test]
    fn long_urls_and_nul_bytes_are_rejected() {
        let long = format!("https://example.com/{}", "a".repeat(2048));
        assert!(http_url(&long, 2048).is_err());
        assert!(http_url("https://example.com/\0", 2048).is_err());
    }
}
