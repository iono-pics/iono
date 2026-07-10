use rand::Rng;
use sha2::{Digest, Sha256};

pub fn generate_api_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    format!("iono_{}", hex::encode(bytes))
}

pub fn hash_api_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_are_consistent() {
        let token = generate_api_token();
        assert_eq!(hash_api_token(&token), hash_api_token(&token));
    }

    #[test]
    fn hashes_are_different() {
        assert_ne!(
            hash_api_token(&generate_api_token()),
            hash_api_token(&generate_api_token())
        );
    }

    #[test]
    fn tokens_have_prefix() {
        assert!(generate_api_token().starts_with("iono_"));
    }
}
