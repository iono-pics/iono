use aes::Aes256;
use ctr::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use rand::Rng;

use crate::error::{AppError, AppResult};

type Aes256Ctr = ctr::Ctr64BE<Aes256>;

pub const KEY_LEN: usize = 32;
pub const IV_LEN: usize = 16;

pub fn random_key() -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    rand::rng().fill_bytes(&mut key);
    key
}

pub fn random_iv() -> [u8; IV_LEN] {
    let mut iv = [0u8; IV_LEN];
    rand::rng().fill_bytes(&mut iv);
    iv
}

pub fn encode_key(key: &[u8; KEY_LEN]) -> String {
    hex::encode(key)
}

pub fn random_nonce() -> String {
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

pub fn parse_key(hex_key: &str) -> AppResult<[u8; KEY_LEN]> {
    let bytes = hex::decode(hex_key.trim())
        .map_err(|_| AppError::BadRequest("encryption key must be hex".into()))?;
    bytes
        .try_into()
        .map_err(|_| AppError::BadRequest(format!("encryption key must be {KEY_LEN} bytes")))
}

pub struct Keystream(Aes256Ctr);

impl Keystream {
    pub fn at(key: &[u8; KEY_LEN], iv: &[u8; IV_LEN], byte_offset: u64) -> AppResult<Self> {
        let mut cipher = Aes256Ctr::new(key.into(), iv.into());
        cipher
            .try_seek(byte_offset)
            .map_err(|e| AppError::internal(format!("cannot seek keystream: {e}")))?;
        Ok(Self(cipher))
    }

    pub fn apply(&mut self, buf: &mut [u8]) {
        self.0.apply_keystream(buf);
    }
}

pub struct Layers(Vec<Keystream>);

impl Layers {
    pub fn new(layers: Vec<Keystream>) -> Self {
        Self(layers)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn apply(&mut self, buf: &mut [u8]) {
        for layer in self.0.iter_mut() {
            layer.apply(buf);
        }
    }
}

pub fn encrypt_buffer(key: &[u8; KEY_LEN], iv: &[u8; IV_LEN], buf: &mut [u8]) -> AppResult<()> {
    Keystream::at(key, iv, 0)?.apply(buf);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let (key, iv) = (random_key(), random_iv());
        let plain = b"the quick brown fox jumps over the lazy dog".to_vec();

        let mut buf = plain.clone();
        encrypt_buffer(&key, &iv, &mut buf).unwrap();
        assert_ne!(buf, plain);

        encrypt_buffer(&key, &iv, &mut buf).unwrap();
        assert_eq!(buf, plain);
    }

    #[test]
    fn ciphertext_is_the_same_length_as_plaintext() {
        let (key, iv) = (random_key(), random_iv());
        for len in [0usize, 1, 15, 16, 17, 4096, 100_000] {
            let mut buf = vec![7u8; len];
            encrypt_buffer(&key, &iv, &mut buf).unwrap();
            assert_eq!(buf.len(), len, "length changed for {len}");
        }
    }

    #[test]
    fn a_slice_decrypts_without_the_bytes_before_it() {
        let (key, iv) = (random_key(), random_iv());
        let plain: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();

        let mut cipher = plain.clone();
        encrypt_buffer(&key, &iv, &mut cipher).unwrap();

        let (start, end) = (307usize, 500usize);
        let mut slice = cipher[start..end].to_vec();
        Keystream::at(&key, &iv, start as u64)
            .unwrap()
            .apply(&mut slice);

        assert_eq!(slice, plain[start..end]);
    }

    #[test]
    fn a_slice_decrypts_the_same_across_chunk_boundaries() {
        let (key, iv) = (random_key(), random_iv());
        let plain: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
        let mut cipher = plain.clone();
        encrypt_buffer(&key, &iv, &mut cipher).unwrap();

        let mut stream = Keystream::at(&key, &iv, 0).unwrap();
        let mut out = Vec::new();
        for chunk in cipher.chunks(37) {
            let mut chunk = chunk.to_vec();
            stream.apply(&mut chunk);
            out.extend_from_slice(&chunk);
        }

        assert_eq!(out, plain);
    }

    #[test]
    fn two_layers_undo_in_either_order() {
        let (k1, iv1) = (random_key(), random_iv());
        let (k2, iv2) = (random_key(), random_iv());
        let plain = b"layered".to_vec();

        let mut buf = plain.clone();
        encrypt_buffer(&k1, &iv1, &mut buf).unwrap();
        encrypt_buffer(&k2, &iv2, &mut buf).unwrap();
        assert_ne!(buf, plain);

        let mut layers = Layers::new(vec![
            Keystream::at(&k2, &iv2, 0).unwrap(),
            Keystream::at(&k1, &iv1, 0).unwrap(),
        ]);
        layers.apply(&mut buf);

        assert_eq!(buf, plain);
    }

    #[test]
    fn a_wrong_key_does_not_recover_the_plaintext() {
        let (key, iv) = (random_key(), random_iv());
        let plain = b"secret".to_vec();
        let mut buf = plain.clone();
        encrypt_buffer(&key, &iv, &mut buf).unwrap();

        encrypt_buffer(&random_key(), &iv, &mut buf).unwrap();

        assert_ne!(buf, plain);
    }

    #[test]
    fn keys_parse_from_hex_and_reject_bad_input() {
        let key = random_key();
        assert_eq!(parse_key(&hex::encode(key)).unwrap(), key);
        assert!(parse_key("nothex").is_err());
        assert!(parse_key(&hex::encode([0u8; 16])).is_err());
    }
}
