use argon2::password_hash::{rand_core::OsRng, SaltString};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};

use crate::error::{AppError, AppResult};

pub fn hash_password(plain: &str) -> Result<String, AppError> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(plain.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| AppError::internal(format!("password hash failed: {e}")))
}

pub fn verify_password(plain: &str, hash: &str) -> Result<bool, AppError> {
    let parsed = PasswordHash::new(hash)
        .map_err(|e| AppError::internal(format!("stored password hash malformed: {e}")))?;
    Ok(Argon2::default()
        .verify_password(plain.as_bytes(), &parsed)
        .is_ok())
}

pub async fn hash_password_async(plain: String) -> AppResult<String> {
    tokio::task::spawn_blocking(move || hash_password(&plain))
        .await
        .map_err(|e| AppError::internal_from("password hashing task panicked", e))?
}

pub async fn verify_password_async(plain: String, hash: String) -> AppResult<bool> {
    tokio::task::spawn_blocking(move || verify_password(&plain, &hash))
        .await
        .map_err(|e| AppError::internal_from("password verification task panicked", e))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn correct_password_verifies() {
        let hash = hash_password("evie").unwrap();
        assert!(verify_password("evie", &hash).unwrap());
    }

    #[test]
    fn incorrect_password_fails() {
        let hash = hash_password("evie").unwrap();
        assert!(!verify_password("elle", &hash).unwrap());
    }

    #[test]
    fn same_password_hashes_differently() {
        assert_ne!(
            hash_password("evie").unwrap(),
            hash_password("evie").unwrap()
        );
    }
}
