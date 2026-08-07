use aes::Aes256;
use ctr::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use rand::Rng;
use std::collections::HashMap;

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

#[derive(Debug, Clone)]
pub struct Keyring {
    current_version: i16,
    keys: HashMap<i16, [u8; KEY_LEN]>,
}

impl Keyring {
    pub fn new(current_version: i16, current: &str, previous: &str) -> AppResult<Self> {
        let mut keys = HashMap::new();
        keys.insert(current_version, parse_key(current)?);

        for entry in previous.split(',').map(str::trim).filter(|e| !e.is_empty()) {
            let (version, key) = entry.split_once(':').ok_or_else(|| {
                AppError::internal("previous encryption keys must be version:hexkey pairs")
            })?;
            let version: i16 = version.trim().parse().map_err(|_| {
                AppError::internal("previous encryption key version is not a number")
            })?;
            if keys.insert(version, parse_key(key)?).is_some() {
                return Err(AppError::internal(format!(
                    "encryption key version {version} is defined twice"
                )));
            }
        }

        Ok(Self {
            current_version,
            keys,
        })
    }

    pub fn current_version(&self) -> i16 {
        self.current_version
    }

    pub fn current(&self) -> &[u8; KEY_LEN] {
        &self.keys[&self.current_version]
    }

    pub fn get(&self, version: i16) -> AppResult<&[u8; KEY_LEN]> {
        self.keys.get(&version).ok_or_else(|| {
            AppError::internal(format!(
                "no encryption key configured for version {version}"
            ))
        })
    }
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

pub fn wrap_key(
    kek: &[u8; KEY_LEN],
    iv: &[u8; IV_LEN],
    key: &[u8; KEY_LEN],
) -> AppResult<[u8; KEY_LEN]> {
    let mut wrapped = *key;
    encrypt_buffer(kek, iv, &mut wrapped)?;
    Ok(wrapped)
}

pub fn unwrap_key(
    kek: &[u8; KEY_LEN],
    iv: &[u8; IV_LEN],
    wrapped: &[u8],
) -> AppResult<[u8; KEY_LEN]> {
    let wrapped: [u8; KEY_LEN] = wrapped
        .try_into()
        .map_err(|_| AppError::internal("stored data key is the wrong length"))?;
    wrap_key(kek, iv, &wrapped)
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
    fn layering_chunk_by_chunk_matches_encrypting_the_whole_buffer() {
        let (user_key, user_iv) = (random_key(), random_iv());
        let (dek, dek_iv) = (random_key(), random_iv());
        let plain: Vec<u8> = (0..9001u32).map(|i| (i % 251) as u8).collect();

        let mut whole = plain.clone();
        encrypt_buffer(&user_key, &user_iv, &mut whole).unwrap();
        encrypt_buffer(&dek, &dek_iv, &mut whole).unwrap();

        let mut layers = Layers::new(vec![
            Keystream::at(&dek, &dek_iv, 0).unwrap(),
            Keystream::at(&user_key, &user_iv, 0).unwrap(),
        ]);
        let mut streamed = Vec::new();
        for chunk in plain.chunks(1000) {
            let mut chunk = chunk.to_vec();
            layers.apply(&mut chunk);
            streamed.extend_from_slice(&chunk);
        }

        assert_eq!(streamed, whole);
    }

    #[test]
    fn layering_is_independent_of_chunk_size() {
        let (key, iv) = (random_key(), random_iv());
        let plain: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();

        let encrypt_in_chunks = |size: usize| {
            let mut layers = Layers::new(vec![Keystream::at(&key, &iv, 0).unwrap()]);
            let mut out = Vec::new();
            for chunk in plain.chunks(size) {
                let mut chunk = chunk.to_vec();
                layers.apply(&mut chunk);
                out.extend_from_slice(&chunk);
            }
            out
        };

        let reference = encrypt_in_chunks(plain.len());
        for size in [1usize, 15, 16, 17, 64, 4096] {
            assert_eq!(
                encrypt_in_chunks(size),
                reference,
                "differed at chunk {size}"
            );
        }
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
    fn a_wrapped_data_key_round_trips() {
        let (kek, iv, dek) = (random_key(), random_iv(), random_key());

        let wrapped = wrap_key(&kek, &iv, &dek).unwrap();
        assert_ne!(wrapped, dek, "the key must not be stored in the clear");
        assert_eq!(unwrap_key(&kek, &iv, &wrapped).unwrap(), dek);
    }

    #[test]
    fn rewrapping_under_a_new_kek_recovers_the_same_data_key() {
        let (old_kek, new_kek, dek) = (random_key(), random_key(), random_key());
        let old_iv = random_iv();

        let wrapped = wrap_key(&old_kek, &old_iv, &dek).unwrap();

        let recovered = unwrap_key(&old_kek, &old_iv, &wrapped).unwrap();
        let new_iv = random_iv();
        let rewrapped = wrap_key(&new_kek, &new_iv, &recovered).unwrap();

        assert_eq!(unwrap_key(&new_kek, &new_iv, &rewrapped).unwrap(), dek);
        let mut object = b"object bytes".to_vec();
        let object_iv = random_iv();
        encrypt_buffer(&dek, &object_iv, &mut object).unwrap();
        encrypt_buffer(
            &unwrap_key(&new_kek, &new_iv, &rewrapped).unwrap(),
            &object_iv,
            &mut object,
        )
        .unwrap();
        assert_eq!(object, b"object bytes");
    }

    #[test]
    fn unwrapping_with_the_wrong_kek_does_not_yield_the_data_key() {
        let (kek, iv, dek) = (random_key(), random_iv(), random_key());
        let wrapped = wrap_key(&kek, &iv, &dek).unwrap();

        assert_ne!(unwrap_key(&random_key(), &iv, &wrapped).unwrap(), dek);
    }

    #[test]
    fn a_truncated_stored_key_is_rejected() {
        let (kek, iv) = (random_key(), random_iv());
        assert!(unwrap_key(&kek, &iv, &[0u8; 16]).is_err());
    }

    #[test]
    fn a_keyring_serves_the_current_key_and_older_ones() {
        let (k1, k2) = (random_key(), random_key());
        let ring = Keyring::new(2, &encode_key(&k2), &format!("1:{}", encode_key(&k1))).unwrap();

        assert_eq!(ring.current_version(), 2);
        assert_eq!(ring.current(), &k2);
        assert_eq!(ring.get(2).unwrap(), &k2);
        assert_eq!(ring.get(1).unwrap(), &k1);
    }

    #[test]
    fn a_keyring_needs_no_previous_keys() {
        let key = random_key();
        let ring = Keyring::new(1, &encode_key(&key), "").unwrap();
        assert_eq!(ring.current(), &key);
    }

    #[test]
    fn an_unknown_version_is_an_error_not_a_wrong_decrypt() {
        let ring = Keyring::new(1, &encode_key(&random_key()), "").unwrap();
        assert!(ring.get(7).is_err());
    }

    #[test]
    fn a_keyring_rejects_malformed_or_duplicated_entries() {
        let key = encode_key(&random_key());
        assert!(Keyring::new(1, &key, "nocolon").is_err());
        assert!(Keyring::new(1, &key, "x:meow").is_err());
        assert!(Keyring::new(1, &key, &format!("2:{}", "zz".repeat(32))).is_err());
        assert!(Keyring::new(1, &key, &format!("1:{key}")).is_err());
    }

    #[test]
    fn keys_parse_from_hex_and_reject_bad_input() {
        let key = random_key();
        assert_eq!(parse_key(&hex::encode(key)).unwrap(), key);
        assert!(parse_key("nothex").is_err());
        assert!(parse_key(&hex::encode([0u8; 16])).is_err());
    }
}
