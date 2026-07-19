use webauthn_rs::prelude::{
    AuthenticationResult, CreationChallengeResponse, CredentialID, Passkey, PasskeyAuthentication,
    PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse, Url, Uuid,
};
use webauthn_rs::{Webauthn, WebauthnBuilder};

use crate::error::AppError;

pub const PASSKEY_REG_PURPOSE: &str = "passkey_reg";
pub const PASSKEY_AUTH_PURPOSE: &str = "passkey_auth";
pub const PASSKEY_LOGIN_PURPOSE: &str = "passkey_login";

pub fn build_webauthn(rp_id: &str, rp_origin: &str) -> Result<Webauthn, AppError> {
    let origin = Url::parse(rp_origin)
        .map_err(|e| AppError::internal(format!("invalid webauthn rp origin: {e}")))?;
    WebauthnBuilder::new(rp_id, &origin)
        .map_err(|e| AppError::internal(format!("invalid webauthn config: {e}")))?
        .rp_name("iono")
        .build()
        .map_err(|e| AppError::internal(format!("failed to build webauthn: {e}")))
}

pub fn start_registration(
    webauthn: &Webauthn,
    user_id: Uuid,
    username: &str,
    display_name: &str,
    exclude_credentials: Vec<CredentialID>,
) -> Result<(CreationChallengeResponse, PasskeyRegistration), AppError> {
    webauthn
        .start_passkey_registration(user_id, username, display_name, Some(exclude_credentials))
        .map_err(|e| AppError::internal(format!("webauthn registration start failed: {e}")))
}

pub fn finish_registration(
    webauthn: &Webauthn,
    reg: &RegisterPublicKeyCredential,
    state: &PasskeyRegistration,
) -> Result<Passkey, AppError> {
    webauthn
        .finish_passkey_registration(reg, state)
        .map_err(|e| AppError::BadRequest(format!("passkey registration failed: {e}")))
}

pub fn start_authentication(
    webauthn: &Webauthn,
    creds: &[Passkey],
) -> Result<(RequestChallengeResponse, PasskeyAuthentication), AppError> {
    webauthn
        .start_passkey_authentication(creds)
        .map_err(|e| AppError::internal(format!("webauthn authentication start failed: {e}")))
}

pub fn finish_authentication(
    webauthn: &Webauthn,
    cred: &PublicKeyCredential,
    state: &PasskeyAuthentication,
) -> Result<AuthenticationResult, AppError> {
    webauthn
        .finish_passkey_authentication(cred, state)
        .map_err(|_| AppError::Unauthorized)
}

pub fn encode_credential_id(bytes: &[u8]) -> String {
    hex::encode(bytes)
}
