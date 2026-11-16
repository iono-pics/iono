use actix_web::http::header::{HeaderName, CONTENT_SECURITY_POLICY};
use iono_core::crypto;

pub struct Nonce(String);

impl Nonce {
    pub fn new() -> Self {
        Self(crypto::random_nonce())
    }

    pub fn value(&self) -> &str {
        &self.0
    }
}

const LOCKED_DOWN: &str = "default-src 'none'; base-uri 'none'; form-action 'none'; \
                           frame-ancestors 'none'";

pub fn paste_policy(nonce: Option<&Nonce>) -> String {
    match nonce {
        Some(nonce) => format!("{LOCKED_DOWN}; script-src 'nonce-{}'", nonce.value()),
        None => LOCKED_DOWN.to_owned(),
    }
}

pub fn view_policy(nonce: &Nonce) -> String {
    format!(
        "{LOCKED_DOWN}; style-src 'nonce-{}'; img-src 'self'; media-src 'self'",
        nonce.value()
    )
}

pub fn raw_policy() -> &'static str {
    "default-src 'none'; sandbox"
}

pub fn header(policy: &str) -> (HeaderName, String) {
    (CONTENT_SECURITY_POLICY, policy.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonces_are_unguessable_and_never_repeat() {
        let a = Nonce::new();
        let b = Nonce::new();
        assert_ne!(a.value(), b.value());
        assert_eq!(a.value().len(), 32);
        assert!(a.value().chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn no_policy_ever_allows_unsafe_inline_or_eval() {
        let nonce = Nonce::new();
        for policy in [
            paste_policy(None),
            paste_policy(Some(&nonce)),
            view_policy(&nonce),
            raw_policy().to_owned(),
        ] {
            assert!(!policy.contains("unsafe-inline"), "{policy}");
            assert!(!policy.contains("unsafe-eval"), "{policy}");
        }
    }

    #[test]
    fn a_plain_paste_may_not_run_scripts_at_all() {
        let policy = paste_policy(None);
        assert!(!policy.contains("script-src"), "{policy}");
        assert!(policy.contains("default-src 'none'"), "{policy}");
    }

    #[test]
    fn an_encrypted_paste_allows_only_the_nonced_script() {
        let nonce = Nonce::new();
        let policy = paste_policy(Some(&nonce));
        assert!(
            policy.contains(&format!("script-src 'nonce-{}'", nonce.value())),
            "{policy}"
        );
    }

    #[test]
    fn the_embed_page_can_load_its_own_media_but_no_third_party() {
        let policy = view_policy(&Nonce::new());
        assert!(policy.contains("img-src 'self'"), "{policy}");
        assert!(policy.contains("media-src 'self'"), "{policy}");
        assert!(policy.contains("default-src 'none'"), "{policy}");
    }

    #[test]
    fn every_policy_blocks_framing_and_base_tag_hijacking() {
        let nonce = Nonce::new();
        for policy in [
            paste_policy(None),
            paste_policy(Some(&nonce)),
            view_policy(&nonce),
        ] {
            assert!(policy.contains("frame-ancestors 'none'"), "{policy}");
            assert!(policy.contains("base-uri 'none'"), "{policy}");
        }
    }

    #[test]
    fn policies_are_valid_header_values() {
        use actix_web::http::header::HeaderValue;

        let nonce = Nonce::new();
        for policy in [
            paste_policy(Some(&nonce)),
            view_policy(&nonce),
            raw_policy().to_owned(),
        ] {
            let (name, value) = header(&policy);
            assert_eq!(name, CONTENT_SECURITY_POLICY);
            assert!(HeaderValue::from_str(&value).is_ok(), "{policy}");
        }
    }
}
