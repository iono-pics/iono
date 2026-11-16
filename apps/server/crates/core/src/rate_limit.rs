use actix_governor::{KeyExtractor, SimpleKeyExtractionError};
use actix_web::{
    dev::ServiceRequest,
    http::header::{self, HeaderMap},
    web, HttpRequest,
};
use sha2::{Digest, Sha256};
use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;

use crate::auth::jwt;
use crate::trusted_proxy::TrustedProxies;

/// the client address. `cf-connecting-ip` is read only when the socket peer is
/// in the [`TrustedProxies`] registered as app data
pub fn client_ip(req: &ServiceRequest) -> Option<IpAddr> {
    let proxies = req.app_data::<web::Data<TrustedProxies>>();
    ip_from(req.headers(), req.peer_addr(), proxies.map(|p| p.get_ref()))
}

/// client_ip for handlers, which see an HttpRequest
pub fn request_ip(req: &HttpRequest) -> Option<IpAddr> {
    let proxies = req.app_data::<web::Data<TrustedProxies>>();
    ip_from(req.headers(), req.peer_addr(), proxies.map(|p| p.get_ref()))
}

/// the address limits are counted against. one ipv6 client usually controls a
/// whole /64, so its addresses share a budget
pub fn network_bucket(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & (u128::MAX << 64))),
        v4 => v4,
    }
}

fn ip_from(
    headers: &HeaderMap,
    peer: Option<std::net::SocketAddr>,
    proxies: Option<&TrustedProxies>,
) -> Option<IpAddr> {
    let peer = peer?.ip();
    if proxies.is_some_and(|p| p.is_trusted(peer)) {
        if let Some(ip) = headers
            .get("cf-connecting-ip")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse::<IpAddr>().ok())
        {
            return Some(ip);
        }
    }
    Some(peer)
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

    fn behind_proxy() -> TestRequest {
        TestRequest::default()
            .peer_addr("10.0.0.1:443".parse().unwrap())
            .app_data(web::Data::new(TrustedProxies::parse("10.0.0.0/8").unwrap()))
    }

    #[test]
    fn unauthenticated_requests_fall_back_to_ip() {
        let a = key(behind_proxy().insert_header(("cf-connecting-ip", "1.1.1.1")));
        let b = key(behind_proxy().insert_header(("cf-connecting-ip", "2.2.2.2")));

        assert_eq!(a, "i:1.1.1.1");
        assert_ne!(a, b);
    }

    #[test]
    fn an_empty_bearer_is_not_a_credential() {
        let key = key(behind_proxy()
            .insert_header((header::AUTHORIZATION, "Bearer "))
            .insert_header(("cf-connecting-ip", "1.1.1.1")));

        assert_eq!(key, "i:1.1.1.1");
    }

    #[test]
    fn a_forwarded_ip_from_an_untrusted_peer_is_ignored() {
        let key = key(TestRequest::default()
            .peer_addr("203.0.113.7:5000".parse().unwrap())
            .app_data(web::Data::new(TrustedProxies::parse("10.0.0.0/8").unwrap()))
            .insert_header(("cf-connecting-ip", "9.9.9.9")));

        assert_eq!(key, "i:203.0.113.7");
    }

    #[test]
    fn no_configured_proxies_means_no_forwarded_ip_is_trusted() {
        let key = key(TestRequest::default()
            .peer_addr("10.0.0.1:443".parse().unwrap())
            .insert_header(("cf-connecting-ip", "9.9.9.9")));

        assert_eq!(key, "i:10.0.0.1");
    }

    #[test]
    fn a_trusted_proxy_with_a_malformed_header_keys_by_the_peer() {
        let key = key(behind_proxy().insert_header(("cf-connecting-ip", "not-an-ip")));

        assert_eq!(key, "i:10.0.0.1");
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
    fn cf_connecting_ip_wins_over_a_trusted_peer_addr() {
        let key = key(behind_proxy().insert_header(("cf-connecting-ip", "9.9.9.9")));

        assert_eq!(key, "i:9.9.9.9");
    }

    #[test]
    fn addresses_in_one_ipv6_64_share_a_bucket() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();

        assert_eq!(
            network_bucket(ip("2001:db8:1:2::1")),
            network_bucket(ip("2001:db8:1:2:ffff::9"))
        );
        assert_ne!(
            network_bucket(ip("2001:db8:1:2::1")),
            network_bucket(ip("2001:db8:1:3::1"))
        );
        assert_eq!(network_bucket(ip("203.0.113.7")), ip("203.0.113.7"));
        assert_eq!(network_bucket(ip("::ffff:203.0.113.7")), ip("203.0.113.7"));
    }
}
