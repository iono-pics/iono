use oauth2::{
    basic::BasicClient, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, RefreshToken, Scope, TokenResponse, TokenUrl,
};
use secrecy::{ExposeSecret, SecretString};
use thiserror::Error;

const DISCORD_AUTH_URL: &str = "https://discord.com/oauth2/authorize";
const DISCORD_TOKEN_URL: &str = "https://discord.com/api/oauth2/token";
const DISCORD_SCOPES: &[&str] = &["identify", "email"];

pub const DISCORD_PROVIDER: ProviderConfig = ProviderConfig {
    name: "discord",
    authorize_url: DISCORD_AUTH_URL,
    token_url: DISCORD_TOKEN_URL,
    default_scopes: DISCORD_SCOPES,
};

#[derive(Debug, Clone, Copy)]
pub struct ProviderConfig {
    pub name: &'static str,
    pub authorize_url: &'static str,
    pub token_url: &'static str,
    pub default_scopes: &'static [&'static str],
}

#[derive(Debug, Error)]
pub enum OAuthError {
    #[error("oauth provider not configured")]
    NotConfigured,
    #[error("invalid provider url: {0}")]
    InvalidUrl(String),
    #[error("http request failed: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("token exchange failed: {0}")]
    Exchange(String),
    #[error("provider returned malformed response: {0}")]
    Malformed(String),
    #[error("provider returned HTTP {status}: {body}")]
    Http { status: u16, body: String },
}

#[derive(Debug)]
pub struct StartFlow {
    pub authorize_url: String,
    pub csrf_token: String,
    pub pkce_verifier: String,
}

#[derive(Debug)]
pub struct Tokens {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: Option<i64>,
}

pub struct OAuthClient {
    provider: ProviderConfig,
    http: reqwest::Client,
    client_id: Option<String>,
    client_secret: Option<SecretString>,
    redirect_uri: Option<String>,
}

impl OAuthClient {
    pub fn new(
        provider: ProviderConfig,
        client_id: Option<String>,
        client_secret: Option<SecretString>,
        redirect_uri: Option<String>,
    ) -> Self {
        let http = reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("failed to build reqwest client for oauth");
        Self {
            provider,
            http,
            client_id,
            client_secret,
            redirect_uri,
        }
    }

    pub fn provider_name(&self) -> &'static str {
        self.provider.name
    }

    pub fn http(&self) -> &reqwest::Client {
        &self.http
    }

    pub fn is_configured(&self) -> bool {
        self.client_id.is_some() && self.client_secret.is_some() && self.redirect_uri.is_some()
    }

    pub fn start_flow(&self) -> Result<StartFlow, OAuthError> {
        let (client_id, client_secret, redirect_uri) = self.require_config()?;

        let client = BasicClient::new(ClientId::new(client_id.to_string()))
            .set_client_secret(ClientSecret::new(client_secret.expose_secret().to_string()))
            .set_auth_uri(
                AuthUrl::new(self.provider.authorize_url.to_string())
                    .map_err(|e| OAuthError::InvalidUrl(e.to_string()))?,
            )
            .set_token_uri(
                TokenUrl::new(self.provider.token_url.to_string())
                    .map_err(|e| OAuthError::InvalidUrl(e.to_string()))?,
            )
            .set_redirect_uri(
                RedirectUrl::new(redirect_uri.to_string())
                    .map_err(|e| OAuthError::InvalidUrl(e.to_string()))?,
            );

        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();

        let mut request = client.authorize_url(CsrfToken::new_random);
        for scope in self.provider.default_scopes {
            request = request.add_scope(Scope::new((*scope).to_string()));
        }
        let (url, csrf) = request.set_pkce_challenge(challenge).url();

        Ok(StartFlow {
            authorize_url: url.to_string(),
            csrf_token: csrf.secret().clone(),
            pkce_verifier: verifier.secret().clone(),
        })
    }

    pub async fn exchange_code(&self, code: &str, verifier: &str) -> Result<Tokens, OAuthError> {
        let (client_id, client_secret, redirect_uri) = self.require_config()?;

        let client = BasicClient::new(ClientId::new(client_id.to_string()))
            .set_client_secret(ClientSecret::new(client_secret.expose_secret().to_string()))
            .set_auth_uri(
                AuthUrl::new(self.provider.authorize_url.to_string())
                    .map_err(|e| OAuthError::InvalidUrl(e.to_string()))?,
            )
            .set_token_uri(
                TokenUrl::new(self.provider.token_url.to_string())
                    .map_err(|e| OAuthError::InvalidUrl(e.to_string()))?,
            )
            .set_redirect_uri(
                RedirectUrl::new(redirect_uri.to_string())
                    .map_err(|e| OAuthError::InvalidUrl(e.to_string()))?,
            );

        let response = client
            .exchange_code(AuthorizationCode::new(code.to_string()))
            .set_pkce_verifier(PkceCodeVerifier::new(verifier.to_string()))
            .request_async(&self.http)
            .await
            .map_err(|e| OAuthError::Exchange(e.to_string()))?;

        Ok(tokens_from(response))
    }

    pub async fn refresh(&self, refresh_token: &str) -> Result<Tokens, OAuthError> {
        let (client_id, client_secret, redirect_uri) = self.require_config()?;

        let client = BasicClient::new(ClientId::new(client_id.to_string()))
            .set_client_secret(ClientSecret::new(client_secret.expose_secret().to_string()))
            .set_auth_uri(
                AuthUrl::new(self.provider.authorize_url.to_string())
                    .map_err(|e| OAuthError::InvalidUrl(e.to_string()))?,
            )
            .set_token_uri(
                TokenUrl::new(self.provider.token_url.to_string())
                    .map_err(|e| OAuthError::InvalidUrl(e.to_string()))?,
            )
            .set_redirect_uri(
                RedirectUrl::new(redirect_uri.to_string())
                    .map_err(|e| OAuthError::InvalidUrl(e.to_string()))?,
            );

        let response = client
            .exchange_refresh_token(&RefreshToken::new(refresh_token.to_string()))
            .request_async(&self.http)
            .await
            .map_err(|e| OAuthError::Exchange(e.to_string()))?;

        Ok(tokens_from(response))
    }

    fn require_config(&self) -> Result<(&str, &SecretString, &str), OAuthError> {
        let client_id = self.client_id.as_deref().ok_or(OAuthError::NotConfigured)?;
        let client_secret = self
            .client_secret
            .as_ref()
            .ok_or(OAuthError::NotConfigured)?;
        let redirect_uri = self
            .redirect_uri
            .as_deref()
            .ok_or(OAuthError::NotConfigured)?;
        Ok((client_id, client_secret, redirect_uri))
    }
}

fn tokens_from<TT: oauth2::TokenType, EF: oauth2::ExtraTokenFields>(
    response: oauth2::StandardTokenResponse<EF, TT>,
) -> Tokens {
    Tokens {
        access_token: response.access_token().secret().clone(),
        refresh_token: response.refresh_token().map(|t| t.secret().clone()),
        expires_in: response.expires_in().map(|d| d.as_secs() as i64),
    }
}
