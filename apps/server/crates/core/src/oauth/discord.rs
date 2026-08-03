use serde::Deserialize;

use crate::oauth::OAuthError;

const USER_URL: &str = "https://discord.com/api/users/@me";

#[derive(Debug, Deserialize)]
pub struct DiscordUser {
    pub id: String,
    pub username: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub verified: Option<bool>,
    #[serde(default)]
    pub avatar: Option<String>,
    #[serde(default)]
    pub global_name: Option<String>,
}

pub async fn fetch_discord_user(
    http: &reqwest::Client,
    access_token: &str,
) -> Result<DiscordUser, OAuthError> {
    let response = http.get(USER_URL).bearer_auth(access_token).send().await?;

    let status = response.status();
    let bytes = response.bytes().await?;

    if !status.is_success() {
        return Err(OAuthError::Http {
            status: status.as_u16(),
            body: String::from_utf8_lossy(&bytes).into_owned(),
        });
    }

    serde_json::from_slice(&bytes).map_err(|e| OAuthError::Malformed(e.to_string()))
}
