use std::fmt;

use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

const DOMAIN_SEPARATOR: &[u8] = b"no-clone-secret-fingerprint-v1\0";
const TOKEN_PREFIX: &str = "nc-fp-v1";
pub const KEY_LENGTH: usize = 32;
pub const KEY_ID_LENGTH: usize = 16;
pub const TAG_LENGTH: usize = 32;

type HmacSha256 = Hmac<Sha256>;

/// The secret key used to create fingerprints. The key material is kept
/// zeroizing while it is held in memory and is never included in Debug output.
pub struct FingerprintKey {
    key: Zeroizing<[u8; KEY_LENGTH]>,
    key_id: [u8; KEY_ID_LENGTH],
}

impl fmt::Debug for FingerprintKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FingerprintKey")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

impl FingerprintKey {
    pub fn generate() -> Self {
        let mut key = [0u8; KEY_LENGTH];
        let mut key_id = [0u8; KEY_ID_LENGTH];
        let mut rng = OsRng;
        rng.fill_bytes(&mut key);
        rng.fill_bytes(&mut key_id);
        Self {
            key: Zeroizing::new(key),
            key_id,
        }
    }

    pub fn from_parts(key: Vec<u8>, key_id: Vec<u8>) -> Result<Self> {
        let key = key
            .try_into()
            .map_err(|_| anyhow::anyhow!("vault fingerprint key has an invalid length"))?;
        let key_id = key_id
            .try_into()
            .map_err(|_| anyhow::anyhow!("vault fingerprint key id has an invalid length"))?;
        Ok(Self {
            key: Zeroizing::new(key),
            key_id,
        })
    }

    pub fn key_bytes(&self) -> &[u8] {
        &self.key[..]
    }

    pub fn key_id(&self) -> &[u8; KEY_ID_LENGTH] {
        &self.key_id
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStatus {
    Match,
    Mismatch,
    Stale,
    Missing,
}

pub fn token_for(key: &FingerprintKey, profile: &str, secret: &str, value: &[u8]) -> String {
    let tag = tag_for(key, profile, secret, value);
    format!(
        "{TOKEN_PREFIX}.{}.{}",
        URL_SAFE_NO_PAD.encode(key.key_id()),
        URL_SAFE_NO_PAD.encode(tag)
    )
}

pub fn verify_token(
    key: &FingerprintKey,
    profile: &str,
    secret: &str,
    value: &[u8],
    token: &str,
) -> Result<VerificationStatus> {
    let parsed = parse_token(token)?;
    if parsed.key_id != *key.key_id() {
        return Ok(VerificationStatus::Stale);
    }

    let mac = new_mac(key, profile, secret, value);
    Ok(if mac.verify_slice(&parsed.tag).is_ok() {
        VerificationStatus::Match
    } else {
        VerificationStatus::Mismatch
    })
}

struct ParsedToken {
    key_id: [u8; KEY_ID_LENGTH],
    tag: [u8; TAG_LENGTH],
}

fn parse_token(token: &str) -> Result<ParsedToken> {
    let mut parts = token.split('.');
    let prefix = parts.next();
    let encoded_key_id = parts.next();
    let encoded_tag = parts.next();
    if prefix != Some(TOKEN_PREFIX)
        || encoded_key_id.is_none()
        || encoded_tag.is_none()
        || parts.next().is_some()
    {
        bail!("invalid fingerprint token")
    }

    let key_id = URL_SAFE_NO_PAD
        .decode(encoded_key_id.expect("checked above"))
        .context("invalid fingerprint key id encoding")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid fingerprint key id length"))?;
    let tag = URL_SAFE_NO_PAD
        .decode(encoded_tag.expect("checked above"))
        .context("invalid fingerprint tag encoding")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid fingerprint tag length"))?;
    Ok(ParsedToken { key_id, tag })
}

fn tag_for(key: &FingerprintKey, profile: &str, secret: &str, value: &[u8]) -> [u8; TAG_LENGTH] {
    let mac = new_mac(key, profile, secret, value);
    mac.finalize().into_bytes().into()
}

fn new_mac(key: &FingerprintKey, profile: &str, secret: &str, value: &[u8]) -> HmacSha256 {
    let mut mac = HmacSha256::new_from_slice(key.key_bytes()).expect("fixed-size HMAC key");
    mac.update(DOMAIN_SEPARATOR);
    mac.update(key.key_id());
    update_length_prefixed(&mut mac, profile.as_bytes());
    update_length_prefixed(&mut mac, secret.as_bytes());
    update_length_prefixed(&mut mac, value);
    mac
}

fn update_length_prefixed(mac: &mut HmacSha256, value: &[u8]) {
    mac.update(&(value.len() as u64).to_be_bytes());
    mac.update(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> FingerprintKey {
        FingerprintKey::from_parts(vec![7; KEY_LENGTH], vec![9; KEY_ID_LENGTH]).unwrap()
    }

    #[test]
    fn tokens_are_deterministic_and_verify() {
        let key = key();
        let token = token_for(&key, "production", "token", b"value");
        assert!(matches!(
            verify_token(&key, "production", "token", b"value", &token).unwrap(),
            VerificationStatus::Match
        ));
        assert!(matches!(
            verify_token(&key, "production", "token", b"other", &token).unwrap(),
            VerificationStatus::Mismatch
        ));
    }

    #[test]
    fn tokens_bind_profile_and_secret_name() {
        let key = key();
        let token = token_for(&key, "production", "token", b"value");
        assert!(matches!(
            verify_token(&key, "staging", "token", b"value", &token).unwrap(),
            VerificationStatus::Mismatch
        ));
        assert!(matches!(
            verify_token(&key, "production", "password", b"value", &token).unwrap(),
            VerificationStatus::Mismatch
        ));
    }

    #[test]
    fn old_key_ids_are_stale() {
        let old_key = key();
        let token = token_for(&old_key, "production", "token", b"value");
        let new_key =
            FingerprintKey::from_parts(vec![8; KEY_LENGTH], vec![10; KEY_ID_LENGTH]).unwrap();
        assert!(matches!(
            verify_token(&new_key, "production", "token", b"value", &token).unwrap(),
            VerificationStatus::Stale
        ));
    }

    #[test]
    fn arbitrary_bytes_are_supported() {
        let key = key();
        let value = [0, 1, 2, 255, b'\n'];
        let token = token_for(&key, "production", "binary", &value);
        assert!(matches!(
            verify_token(&key, "production", "binary", &value, &token).unwrap(),
            VerificationStatus::Match
        ));
    }

    #[test]
    fn malformed_tokens_are_rejected() {
        let key = key();
        for token in ["", "sha512:abc", "nc-fp-v1.a.b.c", "nc-fp-v1.abc.abc"] {
            assert!(verify_token(&key, "production", "token", b"value", token).is_err());
        }
    }
}
