use aes::Aes256;
use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce, Tag};
use ctr::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use rand::Rng;
use sha2::{Digest, Sha256};
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

/// the key new files are encrypted under, plus the previous keys needed to
/// read older files
#[derive(Clone)]
pub struct Keyring {
    current_version: i16,
    keys: HashMap<i16, [u8; KEY_LEN]>,
}

// written by hand so a stray `{:?}` can never print key material
impl std::fmt::Debug for Keyring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut versions: Vec<_> = self.keys.keys().copied().collect();
        versions.sort_unstable();
        f.debug_struct("Keyring")
            .field("current_version", &self.current_version)
            .field("versions", &versions)
            .finish_non_exhaustive()
    }
}

impl Keyring {
    /// `previous` is a comma separated list of `version:hexkey` pairs
    ///
    /// # Errors
    ///
    /// Returns an internal error when a key is not a valid 256 bit hex key,
    /// a pair is malformed, or a version appears twice.
    pub fn new(current_version: i16, current: &str, previous: &str) -> AppResult<Self> {
        let key_error = |e| AppError::internal_from("encryption key is invalid", e);
        let mut keys = HashMap::new();
        keys.insert(current_version, parse_key(current).map_err(key_error)?);

        for entry in previous.split(',').map(str::trim).filter(|e| !e.is_empty()) {
            let (version, key) = entry.split_once(':').ok_or_else(|| {
                AppError::internal("previous encryption keys must be version:hexkey pairs")
            })?;
            let version: i16 = version.trim().parse().map_err(|e| {
                AppError::internal_from("previous encryption key version is not a number", e)
            })?;
            if keys
                .insert(version, parse_key(key).map_err(key_error)?)
                .is_some()
            {
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

    /// the version new files are encrypted under
    pub fn current_version(&self) -> i16 {
        self.current_version
    }

    /// the key new files are encrypted under
    pub fn current(&self) -> &[u8; KEY_LEN] {
        // `new` always inserts the current version
        &self.keys[&self.current_version]
    }

    /// the key a file written under `version` needs
    ///
    /// # Errors
    ///
    /// Returns an internal error when no key is configured for `version`.
    pub fn get(&self, version: i16) -> AppResult<&[u8; KEY_LEN]> {
        self.keys.get(&version).ok_or_else(|| {
            AppError::internal(format!(
                "no encryption key configured for version {version}"
            ))
        })
    }
}

/// why a hex encoded key could not be used
#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("encryption key must be hex")]
    NotHex(#[source] hex::FromHexError),

    #[error("encryption key must be 32 bytes")]
    WrongLength,
}

/// a key sent by a client is a bad request. startup code maps keys from config
/// itself instead of using this conversion
impl From<KeyError> for AppError {
    fn from(error: KeyError) -> Self {
        AppError::BadRequest(error.to_string())
    }
}

/// decodes a hex encoded 256 bit key
///
/// # Errors
///
/// Returns [`KeyError`] when the text is not hex or does not decode to
/// [`KEY_LEN`] bytes.
pub fn parse_key(hex_key: &str) -> Result<[u8; KEY_LEN], KeyError> {
    let bytes = hex::decode(hex_key.trim()).map_err(KeyError::NotHex)?;
    bytes.try_into().map_err(|_| KeyError::WrongLength)
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

/// several keystreams applied one after another, for format 1 files that
/// were encrypted under both a server key and a user key
pub struct Layers(Vec<Keystream>);

impl Layers {
    pub fn new(layers: Vec<Keystream>) -> Self {
        Self(layers)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// applies every layer to `buf` in place
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

/// wraps a data key under a kek with unauthenticated ctr. [`seal_key`] is the
/// authenticated form used for new keys
///
/// # Errors
///
/// Returns an internal error when the keystream cannot be set up.
pub fn wrap_key(
    kek: &[u8; KEY_LEN],
    iv: &[u8; IV_LEN],
    key: &[u8; KEY_LEN],
) -> AppResult<[u8; KEY_LEN]> {
    let mut wrapped = *key;
    encrypt_buffer(kek, iv, &mut wrapped)?;
    Ok(wrapped)
}

/// reverses [`wrap_key`]
///
/// # Errors
///
/// Returns an internal error when `wrapped` is not [`KEY_LEN`] bytes long.
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

/// format 1 is aes-ctr with no integrity: a flipped ciphertext bit flips the
/// same plaintext bit. it is read only
pub const FORMAT_CTR: i16 = 1;
/// aes-256-gcm over fixed size segments, see Sealer
pub const FORMAT_SEGMENTED_GCM: i16 = 2;

/// plaintext bytes per segment. small enough that a range read wastes little,
/// big enough that the 16 byte tags cost 0.02%
pub const SEGMENT_LEN: usize = 64 * 1024;
pub const TAG_LEN: usize = 16;
pub const SEALED_SEGMENT_LEN: usize = SEGMENT_LEN + TAG_LEN;
pub const WRAP_NONCE_LEN: usize = 12;

/// the key a format 2 object is sealed under. a file with a user key needs
/// both secrets
///
/// this derivation is frozen: every stored format 2 object was sealed under
/// its output, so changing it (to hkdf, say) makes them unreadable. a better
/// kdf needs a new format number and a rewrite of existing objects
pub fn content_key(
    dek: &[u8; KEY_LEN],
    salt: &[u8],
    user_key: Option<&[u8; KEY_LEN]>,
) -> [u8; KEY_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(b"iono file content key v2\0");
    hasher.update((salt.len() as u64).to_be_bytes());
    hasher.update(salt);
    hasher.update(dek);
    match user_key {
        Some(key) => {
            hasher.update([1]);
            hasher.update(key);
        }
        None => hasher.update([0]),
    }
    hasher.finalize().into()
}

pub fn segment_count(plain_len: u64) -> u64 {
    plain_len.div_ceil(SEGMENT_LEN as u64).max(1)
}

pub fn sealed_len(plain_len: u64) -> u64 {
    plain_len + segment_count(plain_len) * TAG_LEN as u64
}

// the per file key makes a counter nonce safe. the last flag means dropping
// trailing segments fails to open instead of quietly truncating the file
fn segment_nonce(index: u64, last: bool) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..8].copy_from_slice(&index.to_be_bytes());
    nonce[11] = u8::from(last);
    nonce
}

fn gcm(key: &[u8; KEY_LEN]) -> Aes256Gcm {
    Aes256Gcm::new(key.into())
}

/// seals plaintext into consecutive segments as it arrives
pub struct Sealer {
    cipher: Aes256Gcm,
    next: u64,
    pending: Vec<u8>,
}

impl Sealer {
    pub fn new(key: &[u8; KEY_LEN]) -> Self {
        Self::starting_at(key, 0)
    }

    /// for sealing one slice of a file, like one part of a chunked upload
    pub fn starting_at(key: &[u8; KEY_LEN], segment: u64) -> Self {
        Self {
            cipher: gcm(key),
            next: segment,
            pending: Vec::with_capacity(SEGMENT_LEN),
        }
    }

    pub fn push(&mut self, mut data: &[u8]) -> AppResult<Vec<u8>> {
        let mut out = Vec::with_capacity(data.len() + (data.len() / SEGMENT_LEN + 1) * TAG_LEN);
        loop {
            // a full segment waits until more data proves it is not the last
            if self.pending.len() == SEGMENT_LEN && !data.is_empty() {
                let segment = std::mem::replace(&mut self.pending, Vec::with_capacity(SEGMENT_LEN));
                self.seal_into(segment, false, &mut out)?;
            }
            if data.is_empty() {
                return Ok(out);
            }
            let take = (SEGMENT_LEN - self.pending.len()).min(data.len());
            self.pending.extend_from_slice(&data[..take]);
            data = &data[take..];
        }
    }

    /// seals what is left as the file's final segment
    pub fn finish(mut self) -> AppResult<Vec<u8>> {
        let mut out = Vec::with_capacity(self.pending.len() + TAG_LEN);
        let segment = std::mem::take(&mut self.pending);
        self.seal_into(segment, true, &mut out)?;
        Ok(out)
    }

    /// seals what is left when more of the file follows elsewhere, which
    /// only works on a segment boundary
    pub fn finish_not_last(mut self) -> AppResult<Vec<u8>> {
        if self.pending.is_empty() {
            return Ok(Vec::new());
        }
        if self.pending.len() != SEGMENT_LEN {
            return Err(AppError::internal(
                "a slice that is not the end of a file must end on a segment boundary",
            ));
        }
        let mut out = Vec::with_capacity(SEALED_SEGMENT_LEN);
        let segment = std::mem::take(&mut self.pending);
        self.seal_into(segment, false, &mut out)?;
        Ok(out)
    }

    fn seal_into(&mut self, mut segment: Vec<u8>, last: bool, out: &mut Vec<u8>) -> AppResult<()> {
        let tag = self
            .cipher
            .encrypt_in_place_detached(
                &Nonce::from(segment_nonce(self.next, last)),
                b"",
                &mut segment,
            )
            .map_err(|_| AppError::internal("sealing a segment failed"))?;
        out.extend_from_slice(&segment);
        out.extend_from_slice(&tag);
        self.next += 1;
        Ok(())
    }
}

/// which sealed bytes hold a plaintext range, and how to cut it back out
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SealedRange {
    pub first_segment: u64,
    /// plaintext bytes to drop from the front of the first segment
    pub skip: usize,
    /// plaintext bytes to yield
    pub len: u64,
    pub sealed_start: u64,
    pub sealed_end_inclusive: u64,
}

/// `start..=end` is a plaintext range inside a file of `plain_len` bytes
///
/// # Errors
///
/// Returns an internal error unless `start <= end < plain_len`. callers
/// validate the range against the file first, as the viewer's range parser
/// does, so this only fires on a bug.
pub fn sealed_range(plain_len: u64, start: u64, end: u64) -> AppResult<SealedRange> {
    if start > end || end >= plain_len {
        return Err(AppError::internal("range is outside the file"));
    }
    let seg = SEGMENT_LEN as u64;
    let first_segment = start / seg;
    let last_segment = end / seg;
    // the remainder is below SEGMENT_LEN, so it always fits a usize
    #[allow(clippy::cast_possible_truncation)]
    let skip = (start % seg) as usize;
    Ok(SealedRange {
        first_segment,
        skip,
        len: end - start + 1,
        sealed_start: first_segment * SEALED_SEGMENT_LEN as u64,
        sealed_end_inclusive: ((last_segment + 1) * SEALED_SEGMENT_LEN as u64)
            .min(sealed_len(plain_len))
            - 1,
    })
}

/// opens sealed segments as they arrive. any tampered, reordered or missing
/// segment is an error, never wrong plaintext
pub struct Opener {
    cipher: Aes256Gcm,
    next: u64,
    last: u64,
    last_sealed_len: usize,
    pending: Vec<u8>,
    skip: usize,
    remaining: u64,
}

impl Opener {
    pub fn new(key: &[u8; KEY_LEN], plain_len: u64, range: &SealedRange) -> Self {
        let last = segment_count(plain_len) - 1;
        // the last segment holds at most SEGMENT_LEN bytes, so it fits a usize
        #[allow(clippy::cast_possible_truncation)]
        let last_plain_len = (plain_len - last * SEGMENT_LEN as u64) as usize;
        Self {
            cipher: gcm(key),
            next: range.first_segment,
            last,
            last_sealed_len: last_plain_len + TAG_LEN,
            pending: Vec::new(),
            skip: range.skip,
            remaining: range.len,
        }
    }

    pub fn push(&mut self, data: &[u8]) -> AppResult<Vec<u8>> {
        self.pending.extend_from_slice(data);
        let mut out = Vec::new();
        let mut at = 0;
        while self.remaining > 0 {
            let need = if self.next == self.last {
                self.last_sealed_len
            } else {
                SEALED_SEGMENT_LEN
            };
            if self.pending.len() - at < need {
                break;
            }
            let start = at;
            let body_end = start + need - TAG_LEN;
            let tag: [u8; TAG_LEN] = self.pending[body_end..start + need]
                .try_into()
                .map_err(|_| AppError::internal("segment tag is the wrong length"))?;
            self.cipher
                .decrypt_in_place_detached(
                    &Nonce::from(segment_nonce(self.next, self.next == self.last)),
                    b"",
                    &mut self.pending[start..body_end],
                    &Tag::from(tag),
                )
                .map_err(|_| AppError::internal("stored object failed authentication"))?;
            at += need;
            self.next += 1;

            let segment_len = body_end - start;
            let from = std::mem::take(&mut self.skip).min(segment_len);
            let upto = (from as u64 + self.remaining).min(segment_len as u64) as usize;
            out.extend_from_slice(&self.pending[start + from..start + upto]);
            self.remaining -= (upto - from) as u64;
        }
        self.pending.drain(..at);
        Ok(out)
    }

    pub fn finish(&self) -> AppResult<()> {
        if self.remaining > 0 {
            return Err(AppError::internal(
                "stored object ended before the range did",
            ));
        }
        Ok(())
    }
}

pub fn file_key_aad(file_id: &str) -> Vec<u8> {
    [b"iono file dek\0".as_slice(), file_id.as_bytes()].concat()
}

/// wraps a data key under a kek, bound to `aad` so a wrapped key copied onto
/// another row will not open there. returns (wrapped, nonce)
pub fn seal_key(
    kek: &[u8; KEY_LEN],
    key: &[u8; KEY_LEN],
    aad: &[u8],
) -> AppResult<(Vec<u8>, Vec<u8>)> {
    seal_bytes(kek, key, aad)
}

/// aes-gcm for a small secret kept in the database. returns (sealed, nonce)
pub fn seal_bytes(kek: &[u8; KEY_LEN], plain: &[u8], aad: &[u8]) -> AppResult<(Vec<u8>, Vec<u8>)> {
    let mut nonce = [0u8; WRAP_NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce);
    let mut sealed = plain.to_vec();
    let tag = gcm(kek)
        .encrypt_in_place_detached(&Nonce::from(nonce), aad, &mut sealed)
        .map_err(|_| AppError::internal("sealing a secret failed"))?;
    sealed.extend_from_slice(&tag);
    Ok((sealed, nonce.to_vec()))
}

pub fn open_bytes(
    kek: &[u8; KEY_LEN],
    nonce: &[u8],
    sealed: &[u8],
    aad: &[u8],
) -> AppResult<Vec<u8>> {
    let malformed = || AppError::internal("stored secret is malformed");
    let nonce: [u8; WRAP_NONCE_LEN] = nonce.try_into().map_err(|_| malformed())?;
    let body_len = sealed.len().checked_sub(TAG_LEN).ok_or_else(malformed)?;
    let (body, tag) = sealed.split_at(body_len);
    let tag: [u8; TAG_LEN] = tag.try_into().map_err(|_| malformed())?;
    let mut plain = body.to_vec();
    gcm(kek)
        .decrypt_in_place_detached(&Nonce::from(nonce), aad, &mut plain, &Tag::from(tag))
        .map_err(|_| AppError::internal("stored secret failed authentication"))?;
    Ok(plain)
}

/// opens a key from seal_key or from the unauthenticated ctr wrap
pub fn open_key(
    kek: &[u8; KEY_LEN],
    nonce: &[u8],
    wrapped: &[u8],
    aad: &[u8],
) -> AppResult<[u8; KEY_LEN]> {
    if is_legacy_wrap(wrapped) {
        let iv: &[u8; IV_LEN] = nonce
            .try_into()
            .map_err(|_| AppError::internal("stored data key iv is the wrong length"))?;
        return unwrap_key(kek, iv, wrapped);
    }
    if wrapped.len() != KEY_LEN + TAG_LEN {
        return Err(AppError::internal("stored data key is malformed"));
    }
    open_bytes(kek, nonce, wrapped, aad)?
        .try_into()
        .map_err(|_| AppError::internal("stored data key is the wrong length"))
}

pub fn is_legacy_wrap(wrapped: &[u8]) -> bool {
    wrapped.len() == KEY_LEN
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seal_all(key: &[u8; KEY_LEN], plain: &[u8], chunk: usize) -> Vec<u8> {
        let mut sealer = Sealer::new(key);
        let mut out = Vec::new();
        for piece in plain.chunks(chunk.max(1)) {
            out.extend(sealer.push(piece).unwrap());
        }
        out.extend(sealer.finish().unwrap());
        out
    }

    fn open_range(
        key: &[u8; KEY_LEN],
        sealed: &[u8],
        plain_len: u64,
        start: u64,
        end: u64,
    ) -> AppResult<Vec<u8>> {
        let range = sealed_range(plain_len, start, end)?;
        let slice = &sealed[range.sealed_start as usize..=range.sealed_end_inclusive as usize];
        let mut opener = Opener::new(key, plain_len, &range);
        let mut out = Vec::new();
        for piece in slice.chunks(7919) {
            out.extend(opener.push(piece)?);
        }
        opener.finish()?;
        Ok(out)
    }

    fn sample(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn sealing_round_trips_at_every_awkward_length() {
        let key = random_key();
        for len in [
            0,
            1,
            SEGMENT_LEN - 1,
            SEGMENT_LEN,
            SEGMENT_LEN + 1,
            3 * SEGMENT_LEN,
            200_001,
        ] {
            let plain = sample(len);
            let sealed = seal_all(&key, &plain, 4096);
            assert_eq!(
                sealed.len() as u64,
                sealed_len(len as u64),
                "sealed length for {len}"
            );
            if len > 0 {
                let opened = open_range(&key, &sealed, len as u64, 0, len as u64 - 1).unwrap();
                assert_eq!(opened, plain, "round trip for {len}");
            }
        }
    }

    #[test]
    fn sealing_does_not_depend_on_how_the_input_was_chunked() {
        let key = random_key();
        let plain = sample(3 * SEGMENT_LEN + 99);
        let reference = seal_all(&key, &plain, plain.len());
        for chunk in [1usize, 17, SEGMENT_LEN - 1, SEGMENT_LEN, SEGMENT_LEN + 1] {
            assert_eq!(seal_all(&key, &plain, chunk), reference, "chunk {chunk}");
        }
    }

    #[test]
    fn any_range_opens_to_the_same_bytes() {
        let key = random_key();
        let plain = sample(3 * SEGMENT_LEN + 1234);
        let sealed = seal_all(&key, &plain, 65_000);
        let len = plain.len() as u64;
        let seg = SEGMENT_LEN as u64;
        for (start, end) in [
            (0, 0),
            (5, 5),
            (seg - 1, seg),
            (seg, 2 * seg - 1),
            (100, len - 1),
            (len - 1, len - 1),
        ] {
            assert_eq!(
                open_range(&key, &sealed, len, start, end).unwrap(),
                plain[start as usize..=end as usize],
                "range {start}-{end}"
            );
        }
    }

    #[test]
    fn slices_sealed_separately_join_into_the_same_object() {
        let key = random_key();
        let plain = sample(5 * SEGMENT_LEN + 10);
        let split = 2 * SEGMENT_LEN;

        let mut first = Sealer::starting_at(&key, 0);
        let mut joined = first.push(&plain[..split]).unwrap();
        joined.extend(first.finish_not_last().unwrap());
        let mut second = Sealer::starting_at(&key, (split / SEGMENT_LEN) as u64);
        joined.extend(second.push(&plain[split..]).unwrap());
        joined.extend(second.finish().unwrap());

        assert_eq!(joined, seal_all(&key, &plain, 1000));
    }

    #[test]
    fn a_slice_off_a_segment_boundary_cannot_be_left_open() {
        let mut sealer = Sealer::new(&random_key());
        sealer.push(&[1, 2, 3]).unwrap();
        assert!(sealer.finish_not_last().is_err());
    }

    #[test]
    fn a_flipped_bit_fails_instead_of_decrypting_wrong() {
        let key = random_key();
        let plain = sample(2 * SEGMENT_LEN);
        let mut sealed = seal_all(&key, &plain, 4096);
        sealed[10] ^= 1;
        let len = plain.len() as u64;
        assert!(open_range(&key, &sealed, len, 0, len - 1).is_err());
    }

    #[test]
    fn dropping_the_last_segment_is_detected() {
        let key = random_key();
        let plain = sample(2 * SEGMENT_LEN + 5);
        let sealed = seal_all(&key, &plain, 4096);
        // a row claiming the file ended after two full segments
        let shorter = (2 * SEGMENT_LEN) as u64;
        let truncated = &sealed[..2 * SEALED_SEGMENT_LEN];
        assert!(open_range(&key, truncated, shorter, 0, shorter - 1).is_err());
    }

    #[test]
    fn swapping_segments_is_detected() {
        let key = random_key();
        let plain = sample(3 * SEGMENT_LEN);
        let mut sealed = seal_all(&key, &plain, 4096);
        let (a, b) = sealed.split_at_mut(SEALED_SEGMENT_LEN);
        a.swap_with_slice(&mut b[..SEALED_SEGMENT_LEN]);
        let len = plain.len() as u64;
        assert!(open_range(&key, &sealed, len, 0, len - 1).is_err());
    }

    #[test]
    fn opening_does_not_depend_on_how_the_sealed_bytes_arrive() {
        let key = random_key();
        let plain = sample(SEGMENT_LEN + 100);
        let sealed = seal_all(&key, &plain, 4096);
        let len = plain.len() as u64;
        let range = sealed_range(len, 10, len - 1).unwrap();
        let slice = &sealed[range.sealed_start as usize..=range.sealed_end_inclusive as usize];

        for chunk in [
            1usize,
            17,
            SEALED_SEGMENT_LEN - 1,
            SEALED_SEGMENT_LEN,
            slice.len(),
        ] {
            let mut opener = Opener::new(&key, len, &range);
            let mut out = Vec::new();
            for piece in slice.chunks(chunk) {
                out.extend(opener.push(piece).unwrap());
            }
            opener.finish().unwrap();
            assert_eq!(out, plain[10..], "chunk {chunk}");
        }
    }

    #[test]
    fn the_wrong_key_fails() {
        let plain = sample(1000);
        let sealed = seal_all(&random_key(), &plain, 100);
        assert!(open_range(&random_key(), &sealed, 1000, 0, 999).is_err());
    }

    #[test]
    fn a_content_key_needs_the_user_key_when_there_is_one() {
        let (dek, salt, user) = (random_key(), random_iv(), random_key());
        assert_ne!(
            content_key(&dek, &salt, Some(&user)),
            content_key(&dek, &salt, None)
        );
        assert_ne!(
            content_key(&dek, &salt, Some(&user)),
            content_key(&dek, &salt, Some(&random_key()))
        );
        assert_eq!(
            content_key(&dek, &salt, None),
            content_key(&dek, &salt, None)
        );
    }

    #[test]
    fn a_sealed_key_round_trips_only_under_its_aad() {
        let (kek, dek) = (random_key(), random_key());
        let (wrapped, nonce) = seal_key(&kek, &dek, &file_key_aad("f1")).unwrap();
        assert!(!is_legacy_wrap(&wrapped));
        assert_eq!(
            open_key(&kek, &nonce, &wrapped, &file_key_aad("f1")).unwrap(),
            dek
        );
        assert!(open_key(&kek, &nonce, &wrapped, &file_key_aad("f2")).is_err());
        assert!(open_key(&random_key(), &nonce, &wrapped, &file_key_aad("f1")).is_err());
    }

    #[test]
    fn a_legacy_ctr_wrap_still_opens() {
        let (kek, iv, dek) = (random_key(), random_iv(), random_key());
        let wrapped = wrap_key(&kek, &iv, &dek).unwrap();
        assert!(is_legacy_wrap(&wrapped));
        assert_eq!(
            open_key(&kek, &iv, &wrapped, &file_key_aad("any")).unwrap(),
            dek
        );
    }

    #[test]
    fn range_math_points_at_whole_segments() {
        let seg = SEGMENT_LEN as u64;
        let plain_len = 3 * seg + 10;
        let range = sealed_range(plain_len, seg + 3, seg + 7).unwrap();
        assert_eq!(range.first_segment, 1);
        assert_eq!(range.skip, 3);
        assert_eq!(range.len, 5);
        assert_eq!(range.sealed_start, SEALED_SEGMENT_LEN as u64);
        assert_eq!(
            range.sealed_end_inclusive,
            2 * SEALED_SEGMENT_LEN as u64 - 1
        );

        let tail = sealed_range(plain_len, plain_len - 1, plain_len - 1).unwrap();
        assert_eq!(tail.sealed_end_inclusive, sealed_len(plain_len) - 1);
    }

    #[test]
    fn a_range_outside_the_file_is_an_error() {
        assert!(sealed_range(10, 5, 4).is_err());
        assert!(sealed_range(10, 0, 10).is_err());
        assert!(sealed_range(0, 0, 0).is_err());
        assert!(sealed_range(10, 0, 9).is_ok());
    }

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
