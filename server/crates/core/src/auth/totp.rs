use rand::Rng;
use totp_rs::{Algorithm, Secret, TOTP};

use crate::error::AppError;

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
        30,
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

pub fn verify_totp_code(secret_base32: &str, code: &str) -> Result<bool, AppError> {
    let totp = build_totp(secret_base32, String::new())?;
    totp.check_current(code)
        .map_err(|e| AppError::internal(format!("totp check failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

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
