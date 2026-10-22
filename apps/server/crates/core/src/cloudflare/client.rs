use reqwest::Method;
use secrecy::{ExposeSecret, SecretString};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use thiserror::Error;

use crate::cloudflare::endpoints::purge::{PurgeCache, PurgeTarget};

const API_BASE: &str = "https://api.cloudflare.com/client/v4";

#[derive(Clone)]
pub enum Credentials {
    UserAuthToken(SecretString),
}

impl Credentials {
    fn apply(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match self {
            Self::UserAuthToken(token) => req.bearer_auth(token.expose_secret()),
        }
    }
}

pub trait Endpoint {
    type Response: DeserializeOwned;

    fn method(&self) -> Method;
    fn path(&self) -> String;
    fn body(&self) -> Option<serde_json::Value> {
        None
    }
}

#[derive(Debug, Deserialize)]
struct ApiEnvelope<T> {
    success: bool,
    result: Option<T>,
    #[serde(default)]
    errors: Vec<ApiErrorInfo>,
}

#[derive(Debug, Deserialize)]
pub struct ApiErrorInfo {
    pub code: u32,
    pub message: String,
}

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("cloudflare returned HTTP {status}: {errors:?}")]
    Http {
        status: reqwest::StatusCode,
        errors: Vec<ApiErrorInfo>,
    },
    #[error("cloudflare responded success=false: {errors:?}")]
    Api { errors: Vec<ApiErrorInfo> },
    #[error("cloudflare request failed: {0}")]
    Transport(#[from] reqwest::Error),
}

pub struct CloudflareClient {
    http: reqwest::Client,
    credentials: Option<Credentials>,
    zone_id: Option<String>,
}

impl CloudflareClient {
    pub fn new(zone_id: Option<String>, api_token: Option<SecretString>) -> Self {
        Self {
            http: reqwest::Client::new(),
            credentials: api_token.map(Credentials::UserAuthToken),
            zone_id,
        }
    }

    pub fn is_configured(&self) -> bool {
        self.credentials.is_some() && self.zone_id.is_some()
    }

    pub async fn purge_urls(&self, urls: Vec<String>) -> Result<(), ApiError> {
        self.purge(urls, PurgeTarget::Files).await
    }

    pub async fn purge_tags(&self, tags: Vec<String>) -> Result<(), ApiError> {
        self.purge(tags, PurgeTarget::Tags).await
    }

    async fn purge(
        &self,
        items: Vec<String>,
        target: fn(Vec<String>) -> PurgeTarget,
    ) -> Result<(), ApiError> {
        const CHUNK: usize = 30;

        if items.is_empty() {
            return Ok(());
        }
        let Some(zone_id) = &self.zone_id else {
            tracing::debug!(
                count = items.len(),
                "cloudflare not configured; skipping purge"
            );
            return Ok(());
        };

        for chunk in items.chunks(CHUNK) {
            let endpoint = PurgeCache {
                zone_id,
                target: target(chunk.to_vec()),
            };
            self.request(&endpoint).await?;
        }
        Ok(())
    }

    pub async fn request<E: Endpoint>(&self, endpoint: &E) -> Result<E::Response, ApiError> {
        let Some(creds) = &self.credentials else {
            return Err(ApiError::Api {
                errors: vec![ApiErrorInfo {
                    code: 0,
                    message: "cloudflare client not configured".into(),
                }],
            });
        };

        let url = format!("{API_BASE}/{}", endpoint.path());
        let mut req = self.http.request(endpoint.method(), &url);
        req = creds.apply(req);
        if let Some(body) = endpoint.body() {
            req = req.json(&body);
        }

        let response = req.send().await?;
        let status = response.status();
        let bytes = response.bytes().await?;

        let envelope: ApiEnvelope<E::Response> = match serde_json::from_slice(&bytes) {
            Ok(env) => env,
            Err(_) if !status.is_success() => {
                return Err(ApiError::Http {
                    status,
                    errors: Vec::new(),
                });
            }
            Err(e) => {
                return Err(ApiError::Api {
                    errors: vec![ApiErrorInfo {
                        code: 0,
                        message: format!("failed to parse cloudflare response: {e}"),
                    }],
                });
            }
        };

        if !status.is_success() {
            return Err(ApiError::Http {
                status,
                errors: envelope.errors,
            });
        }
        if !envelope.success {
            return Err(ApiError::Api {
                errors: envelope.errors,
            });
        }

        envelope.result.ok_or_else(|| ApiError::Api {
            errors: vec![ApiErrorInfo {
                code: 0,
                message: "cloudflare returned success but no result".into(),
            }],
        })
    }
}
