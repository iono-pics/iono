use actix_governor::{KeyExtractor, SimpleKeyExtractionError};
use actix_web::{dev::ServiceRequest, http::header};
use sha2::{Digest, Sha256};
use std::net::IpAddr;
use std::sync::Arc;

use crate::auth::jwt;

pub fn client_ip(req: &ServiceRequest) -> Option<IpAddr> {
    if let Some(ip) = req
        .headers()
        .get("cf-connecting-ip")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<IpAddr>().ok())
    {
        return Some(ip);
    }
    req.peer_addr().map(|addr| addr.ip())
}

#[derive(Clone)]
pub struct ClientIpKeyExtractor;

impl KeyExtractor for ClientIpKeyExtractor {
    type Key = IpAddr;
    type KeyExtractionError = SimpleKeyExtractionError<&'static str>;

    fn extract(&self, req: &ServiceRequest) -> Result<Self::Key, Self::KeyExtractionError> {
        client_ip(req).ok_or_else(|| SimpleKeyExtractionError::new("could not determine client ip"))
    }
}

#[derive(Clone)]
pub struct ClientKeyExtractor {
    jwt_secret: Arc<str>,
}

impl ClientKeyExtractor {
    pub fn new(jwt_secret: &str) -> Self {
        Self {
            jwt_secret: Arc::from(jwt_secret),
        }
    }
}

impl KeyExtractor for ClientKeyExtractor {
    type Key = String;
    type KeyExtractionError = SimpleKeyExtractionError<&'static str>;

    fn extract(&self, req: &ServiceRequest) -> Result<Self::Key, Self::KeyExtractionError> {
        if let Some(credential) = bearer_token(req) {
            if let Ok(claims) = jwt::verify_access_token(credential, &self.jwt_secret) {
                return Ok(format!("u:{}", claims.sub));
            }

            let mut hasher = Sha256::new();
            hasher.update(credential.as_bytes());
            return Ok(format!("c:{}", hex::encode(hasher.finalize())));
        }

        client_ip(req)
            .map(|ip| format!("i:{ip}"))
            .ok_or_else(|| SimpleKeyExtractionError::new("could not determine client ip"))
    }
}

fn bearer_token(req: &ServiceRequest) -> Option<&str> {
    let value = req.headers().get(header::AUTHORIZATION)?.to_str().ok()?;
    let token = value.strip_prefix("Bearer ")?.trim();
    (!token.is_empty()).then_some(token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test::TestRequest;

    const SECRET: &str = "test-secret";

    fn key(req: TestRequest) -> String {
        ClientKeyExtractor::new(SECRET)
            .extract(&req.to_srv_request())
            .unwrap()
    }

    fn jwt_for(user_id: &str) -> String {
        jwt::issue_access_token(user_id, 0, SECRET, 15).unwrap()
    }

    fn jwt_for_version(user_id: &str, token_version: i32) -> String {
        jwt::issue_access_token(user_id, token_version, SECRET, 15).unwrap()
    }

    fn bearer(token: &str) -> TestRequest {
        TestRequest::default().insert_header((header::AUTHORIZATION, format!("Bearer {token}")))
    }

    #[test]
    fn same_credential_shares_a_bucket_across_ips() {
        let a = key(TestRequest::default()
            .insert_header((header::AUTHORIZATION, "Bearer abc"))
            .insert_header(("cf-connecting-ip", "1.1.1.1")));
        let b = key(TestRequest::default()
            .insert_header((header::AUTHORIZATION, "Bearer abc"))
            .insert_header(("cf-connecting-ip", "2.2.2.2")));

        assert_eq!(a, b);
    }

    #[test]
    fn different_credentials_get_different_buckets() {
        let a = key(TestRequest::default().insert_header((header::AUTHORIZATION, "Bearer abc")));
        let b = key(TestRequest::default().insert_header((header::AUTHORIZATION, "Bearer def")));

        assert_ne!(a, b);
    }

    #[test]
    fn raw_credentials_are_not_used_as_keys() {
        let key = key(TestRequest::default().insert_header((header::AUTHORIZATION, "Bearer abc")));

        assert!(!key.contains("abc"), "{key}");
    }

    #[test]
    fn unauthenticated_requests_fall_back_to_ip() {
        let a = key(TestRequest::default().insert_header(("cf-connecting-ip", "1.1.1.1")));
        let b = key(TestRequest::default().insert_header(("cf-connecting-ip", "2.2.2.2")));

        assert_eq!(a, "i:1.1.1.1");
        assert_ne!(a, b);
    }

    #[test]
    fn an_empty_bearer_is_not_a_credential() {
        let key = key(TestRequest::default()
            .insert_header((header::AUTHORIZATION, "Bearer "))
            .insert_header(("cf-connecting-ip", "1.1.1.1")));

        assert_eq!(key, "i:1.1.1.1");
    }

    #[test]
    fn every_token_a_user_holds_shares_one_bucket() {
        let old = jwt_for_version("user-1", 0);
        let new = jwt_for_version("user-1", 1);
        assert_ne!(
            old, new,
            "the tokens must differ for this to prove anything"
        );

        assert_eq!(key(bearer(&old)), key(bearer(&new)));
        assert_eq!(key(bearer(&old)), "u:user-1");
    }

    #[test]
    fn different_users_get_different_buckets() {
        assert_ne!(
            key(bearer(&jwt_for("user-1"))),
            key(bearer(&jwt_for("user-2")))
        );
    }

    #[test]
    fn a_jwt_signed_with_another_secret_is_not_trusted() {
        let foreign = jwt::issue_access_token("user-1", 0, "other-secret", 15).unwrap();

        let key = key(bearer(&foreign));

        assert!(!key.starts_with("u:"), "{key}");
    }

    #[test]
    fn api_keys_fall_back_to_hashing() {
        let key = key(bearer("iono_pk_abc123"));

        assert!(key.starts_with("c:"), "{key}");
    }

    #[test]
    fn cf_connecting_ip_wins_over_peer_addr() {
        let key = key(TestRequest::default()
            .insert_header(("cf-connecting-ip", "9.9.9.9"))
            .peer_addr("1.2.3.4:5678".parse().unwrap()));

        assert_eq!(key, "i:9.9.9.9");
    }
}
