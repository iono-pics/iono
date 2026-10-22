use reqwest::Method;
use serde::Deserialize;
use serde_json::json;

use crate::cloudflare::client::Endpoint;

pub struct PurgeCache<'a> {
    pub zone_id: &'a str,
    pub target: PurgeTarget,
}

pub enum PurgeTarget {
    Files(Vec<String>),
    /// reaches every data center, unlike a worker's cache.delete
    Tags(Vec<String>),
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
        Some(match &self.target {
            PurgeTarget::Files(files) => json!({ "files": files }),
            PurgeTarget::Tags(tags) => json!({ "tags": tags }),
        })
    }
}
