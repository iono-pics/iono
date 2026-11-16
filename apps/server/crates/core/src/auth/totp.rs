use rand::Rng;
use sqlx::PgPool;
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use totp_rs::{Algorithm, Secret, TOTP};

use crate::crypto::{self, Keyring};
use crate::error::{AppError, AppResult};

const STEP_SECONDS: u64 = 30;
/// failed codes in a row before the account stops taking codes for a while.
/// a six digit code with a step of drift either side is about a 1 in 333k
/// guess, so this keeps a stolen password from turning into a login
const MAX_FAILURES: i16 = 5;
const LOCKOUT_MINUTES: i64 = 15;
const SEALED_PREFIX: &str = "sealed";

pub struct TotpSetup {
    pub secret_base32: String,
    pub otpauth_url: String,
}

fn build_totp(secret_base32: &str, account_name: String) -> Result<TOTP, AppError> {
    let secret_bytes = Secret::Encoded(secret_base32.to_string())
        .to_bytes()
        .map_err(|e| AppError::internal(format!("invalid totp secret: {e}")))?;
    TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        STEP_SECONDS,
        secret_bytes,
        Some("Iono".to_string()),
        account_name,
    )
    .map_err(|e| AppError::internal(format!("totp construction failed: {e}")))
}

pub fn generate_totp_setup(account_label: &str) -> Result<TotpSetup, AppError> {
    let mut raw = vec![0u8; 20];
    rand::rng().fill_bytes(&mut raw);
    let secret_base32 = Secret::Raw(raw).to_encoded().to_string();

    let totp = build_totp(&secret_base32, account_label.to_string())?;
    Ok(TotpSetup {
        secret_base32,
        otpauth_url: totp.get_url(),
    })
}

/// the time step `code` belongs to, allowing a step of clock drift either
/// side. knowing the step is what lets a used code be refused next time
pub fn matching_step(secret_base32: &str, code: &str, now_secs: u64) -> AppResult<Option<u64>> {
    let totp = build_totp(secret_base32, String::new())?;
    let current = now_secs / STEP_SECONDS;
    for step in [current.saturating_sub(1), current, current + 1] {
        let expected = totp.generate(step * STEP_SECONDS);
        if bool::from(expected.as_bytes().ct_eq(code.as_bytes())) {
            return Ok(Some(step));
        }
    }
    Ok(None)
}

pub fn verify_totp_code(secret_base32: &str, code: &str) -> Result<bool, AppError> {
    Ok(matching_step(secret_base32, code, now_secs())?.is_some())
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn secret_aad(user_id: &str) -> Vec<u8> {
    [b"iono totp secret\0".as_slice(), user_id.as_bytes()].concat()
}

/// what goes in users.totp_secret. bound to the user, so a sealed secret
/// copied onto another account will not open there
pub fn seal_secret(keyring: &Keyring, user_id: &str, secret_base32: &str) -> AppResult<String> {
    let version = keyring.current_version();
    let (sealed, nonce) = crypto::seal_bytes(
        keyring.current(),
        secret_base32.as_bytes(),
        &secret_aad(user_id),
    )?;
    Ok(format!(
        "{SEALED_PREFIX}:{version}:{}:{}",
        hex::encode(nonce),
        hex::encode(sealed)
    ))
}

/// the base32 secret, and whether it was stored unsealed
pub fn reveal_secret(keyring: &Keyring, user_id: &str, stored: &str) -> AppResult<(String, bool)> {
    let Some(rest) = stored
        .strip_prefix(SEALED_PREFIX)
        .and_then(|r| r.strip_prefix(':'))
    else {
        return Ok((stored.to_owned(), true));
    };
    let malformed = || AppError::internal("stored totp secret is malformed");
    let mut parts = rest.splitn(3, ':');
    let (Some(version), Some(nonce), Some(sealed)) = (parts.next(), parts.next(), parts.next())
    else {
        return Err(malformed());
    };
    let version: i16 = version.parse().map_err(|_| malformed())?;
    let nonce = hex::decode(nonce).map_err(|_| malformed())?;
    let sealed = hex::decode(sealed).map_err(|_| malformed())?;
    let plain = crypto::open_bytes(keyring.get(version)?, &nonce, &sealed, &secret_aad(user_id))?;
    let secret = String::from_utf8(plain).map_err(|_| malformed())?;
    Ok((secret, false))
}

/// refuses while the account is locked out from too many wrong codes
pub async fn ensure_not_locked(db: &PgPool, user_id: &str) -> AppResult<()> {
    let locked: Option<bool> =
        sqlx::query_scalar("SELECT totp_locked_until > now() FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(db)
            .await?
            .flatten();
    if locked == Some(true) {
        return Err(AppError::RateLimited);
    }
    Ok(())
}

/// counts a wrong code or recovery code, locking the account at the limit
pub async fn record_failure(db: &PgPool, user_id: &str) -> AppResult<()> {
    sqlx::query(
        r#"
        UPDATE users SET
            totp_locked_until = CASE WHEN totp_failed_attempts + 1 >= $2
                THEN now() + make_interval(mins => $3) ELSE totp_locked_until END,
            totp_failed_attempts = CASE WHEN totp_failed_attempts + 1 >= $2
                THEN 0 ELSE totp_failed_attempts + 1 END
        WHERE id = $1
        "#,
    )
    .bind(user_id)
    .bind(MAX_FAILURES)
    .bind(LOCKOUT_MINUTES as i32)
    .execute(db)
    .await?;
    Ok(())
}

pub async fn record_success(db: &PgPool, user_id: &str) -> AppResult<()> {
    sqlx::query(
        "UPDATE users SET totp_failed_attempts = 0, totp_locked_until = NULL WHERE id = $1",
    )
    .bind(user_id)
    .execute(db)
    .await?;
    Ok(())
}

/// checks a code the way every caller should: locked accounts are refused,
/// each time step is accepted once so a code seen over a shoulder or in a log
/// cannot be replayed, misses count toward the lockout, and a secret still
/// stored in the clear gets sealed
pub async fn accept_code(
    db: &PgPool,
    keyring: &Keyring,
    user_id: &str,
    stored_secret: &str,
    code: &str,
) -> AppResult<bool> {
    ensure_not_locked(db, user_id).await?;
    let (secret, legacy) = reveal_secret(keyring, user_id, stored_secret)?;

    let accepted = match matching_step(&secret, code, now_secs())? {
        Some(step) => {
            sqlx::query(
                r#"
                UPDATE users SET totp_last_step = $2
                WHERE id = $1 AND (totp_last_step IS NULL OR totp_last_step < $2)
                "#,
            )
            .bind(user_id)
            .bind(step as i64)
            .execute(db)
            .await?
            .rows_affected()
                == 1
        }
        None => false,
    };

    if !accepted {
        record_failure(db, user_id).await?;
        return Ok(false);
    }
    record_success(db, user_id).await?;

    if legacy {
        let sealed = seal_secret(keyring, user_id, &secret)?;
        sqlx::query("UPDATE users SET totp_secret = $1 WHERE id = $2 AND totp_secret = $3")
            .bind(sealed)
            .bind(user_id)
            .bind(stored_secret)
            .execute(db)
            .await?;
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keyring() -> Keyring {
        Keyring::new(1, &crypto::encode_key(&crypto::random_key()), "").unwrap()
    }

    #[test]
    fn correct_code_verifies() {
        let setup = generate_totp_setup("evie@iono.pics").unwrap();
        let totp = build_totp(&setup.secret_base32, String::new()).unwrap();
        let code = totp.generate_current().unwrap();
        assert!(verify_totp_code(&setup.secret_base32, &code).unwrap());
    }

    #[test]
    fn wrong_code_fails() {
        let setup = generate_totp_setup("evie@iono.pics").unwrap();
        assert!(!verify_totp_code(&setup.secret_base32, "000000").unwrap());
    }

    #[test]
    fn a_code_names_its_own_step_and_its_neighbours_are_allowed() {
        let setup = generate_totp_setup("evie@iono.pics").unwrap();
        let totp = build_totp(&setup.secret_base32, String::new()).unwrap();
        let now = 1_800_000_000;
        let step = now / STEP_SECONDS;

        for drift in [step - 1, step, step + 1] {
            let code = totp.generate(drift * STEP_SECONDS);
            assert_eq!(
                matching_step(&setup.secret_base32, &code, now).unwrap(),
                Some(drift)
            );
        }
        let stale = totp.generate((step - 2) * STEP_SECONDS);
        assert_eq!(
            matching_step(&setup.secret_base32, &stale, now).unwrap(),
            None
        );
    }

    #[test]
    fn a_sealed_secret_opens_only_for_its_user() {
        let ring = keyring();
        let sealed = seal_secret(&ring, "u1", "JBSWY3DPEHPK3PXP").unwrap();
        assert!(!sealed.contains("JBSWY3DPEHPK3PXP"));
        assert_eq!(
            reveal_secret(&ring, "u1", &sealed).unwrap(),
            ("JBSWY3DPEHPK3PXP".to_owned(), false)
        );
        assert!(reveal_secret(&ring, "u2", &sealed).is_err());
    }

    #[test]
    fn a_secret_from_before_sealing_still_reads_and_asks_to_be_sealed() {
        assert_eq!(
            reveal_secret(&keyring(), "u1", "JBSWY3DPEHPK3PXP").unwrap(),
            ("JBSWY3DPEHPK3PXP".to_owned(), true)
        );
    }

    #[test]
    fn otpauth_url_has_issuer_and_label() {
        let setup = generate_totp_setup("evie@iono.pics").unwrap();
        assert!(setup.otpauth_url.contains("Iono"));
        assert!(setup.otpauth_url.contains("evie%40iono.pics"));
    }

    #[test]
    fn secrets_are_different_each_time() {
        assert_ne!(
            generate_totp_setup("evie@iono.pics").unwrap().secret_base32,
            generate_totp_setup("evie@iono.pics").unwrap().secret_base32
        );
    }
}
