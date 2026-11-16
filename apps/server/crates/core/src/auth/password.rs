use argon2::password_hash::{rand_core::OsRng, SaltString};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};

use std::sync::LazyLock;
use subtle::ConstantTimeEq;
use tokio::sync::Semaphore;

use crate::auth::token::hash_api_token;
use crate::error::{AppError, AppResult};

// each argon2 run holds ~19MiB, so this bounds what a flood of password
// guesses can take from a small instance. excess callers queue
const MAX_CONCURRENT_HASHES: usize = 4;
static HASHING: LazyLock<Semaphore> = LazyLock::new(|| Semaphore::new(MAX_CONCURRENT_HASHES));

async fn bounded<T: Send + 'static>(
    work: impl FnOnce() -> AppResult<T> + Send + 'static,
    what: &'static str,
) -> AppResult<T> {
    let _permit = HASHING
        .acquire()
        .await
        .map_err(|e| AppError::internal_from("password hashing semaphore closed", e))?;
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|e| AppError::internal_from(what, e))?
}

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

static DUMMY_HASH: LazyLock<String> = LazyLock::new(|| {
    hash_password("iono-dummy-password").unwrap_or_else(|e| {
        tracing::error!(error = %e, "dummy password hash could not be built");
        String::new()
    })
});

/// spends the cost of a password check when there is no stored hash to check
/// against, so a missing account takes as long as a wrong password
pub async fn verify_against_dummy(plain: String) {
    // the result is irrelevant, only the time spent matters
    let _ = verify_password_async(plain, DUMMY_HASH.clone()).await;
}

pub async fn hash_password_async(plain: String) -> AppResult<String> {
    bounded(
        move || hash_password(&plain),
        "password hashing task panicked",
    )
    .await
}

pub async fn verify_password_async(plain: String, hash: String) -> AppResult<bool> {
    bounded(
        move || verify_password(&plain, &hash),
        "password verification task panicked",
    )
    .await
}

/// for secrets we generated (file keys, recovery codes). they have no
/// dictionary to guess from, so a slow hash only costs us time
pub fn hash_secret(plain: &str) -> String {
    hash_api_token(plain)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretMatch {
    No,
    Yes,
    /// matched an argon2 hash from before hash_secret, worth rewriting
    YesLegacy,
}

impl SecretMatch {
    pub fn matched(self) -> bool {
        self != Self::No
    }
}

pub fn is_legacy_secret_hash(stored: &str) -> bool {
    stored.starts_with("$argon2")
}

pub async fn verify_secret(plain: &str, stored: &str) -> AppResult<SecretMatch> {
    if is_legacy_secret_hash(stored) {
        let ok = verify_password_async(plain.to_owned(), stored.to_owned()).await?;
        return Ok(if ok {
            SecretMatch::YesLegacy
        } else {
            SecretMatch::No
        });
    }
    let equal: bool = hash_secret(plain)
        .as_bytes()
        .ct_eq(stored.as_bytes())
        .into();
    Ok(if equal {
        SecretMatch::Yes
    } else {
        SecretMatch::No
    })
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

    #[tokio::test]
    async fn a_secret_verifies_against_its_fast_hash() {
        let stored = hash_secret("key");
        assert!(!is_legacy_secret_hash(&stored));
        assert_eq!(
            verify_secret("key", &stored).await.unwrap(),
            SecretMatch::Yes
        );
        assert_eq!(
            verify_secret("nope", &stored).await.unwrap(),
            SecretMatch::No
        );
    }

    #[tokio::test]
    async fn an_argon_secret_still_verifies_and_asks_to_be_upgraded() {
        let stored = hash_password("key").unwrap();
        assert!(is_legacy_secret_hash(&stored));
        assert_eq!(
            verify_secret("key", &stored).await.unwrap(),
            SecretMatch::YesLegacy
        );
        assert_eq!(
            verify_secret("nope", &stored).await.unwrap(),
            SecretMatch::No
        );
    }

    #[test]
    fn same_password_hashes_differently() {
        assert_ne!(
            hash_password("evie").unwrap(),
            hash_password("evie").unwrap()
        );
    }
}
