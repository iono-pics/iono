use reqwest::Method;
use serde::Deserialize;
use serde_json::json;

use crate::cloudflare::client::Endpoint;

pub struct PurgeCache<'a> {
    pub zone_id: &'a str,
    pub files: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct PurgeResult {
    pub id: String,
}

impl Endpoint for PurgeCache<'_> {
    type Response = PurgeResult;

    fn method(&self) -> Method {
        Method::POST
    }

    fn path(&self) -> String {
        format!("zones/{}/purge_cache", self.zone_id)
    }

    fn body(&self) -> Option<serde_json::Value> {
        Some(json!({ "files": self.files }))
    }
}
