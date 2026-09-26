//! Encryption at rest for the wallet store (spec §10.3, SDK-P9, SDK-M18): XChaCha20-Poly1305
//! under the pool's store key, with associated data binding each record to its place, and opaque
//! record keys.
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac};
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;

use crate::felt::Felt32;
use crate::keys::StoreKeys;
use crate::{Error, Result};

pub const SCHEMA: u32 = 1;

fn ad(chain: &Felt32, pool: &Felt32, record_type: &str, record_key: &str) -> Vec<u8> {
    let mut v = b"TEMPLAR_STORE_V1".to_vec();
    v.extend_from_slice(&SCHEMA.to_be_bytes());
    v.extend_from_slice(chain);
    v.extend_from_slice(pool);
    for part in [record_type, record_key] {
        v.extend_from_slice(&(part.len() as u32).to_be_bytes());
        v.extend_from_slice(part.as_bytes());
    }
    v
}

/// `nonce₂₄ ‖ ciphertext`.
pub fn seal(seed: &dyn StoreKeys, chain: &Felt32, pool: &Felt32, record_type: &str, record_key: &str, plaintext: &[u8], rng: &mut (impl RngCore + CryptoRng)) -> Result<Vec<u8>> {
    let key = seed.store_key(chain, pool);
    let cipher = XChaCha20Poly1305::new(key.as_ref().into());
    let mut nonce = [0u8; 24];
    rng.fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad: &ad(chain, pool, record_type, record_key) })
        .map_err(|_| Error::new("internal", "store encryption"))?;
    Ok([nonce.as_slice(), &ct].concat())
}

pub fn open(seed: &dyn StoreKeys, chain: &Felt32, pool: &Felt32, record_type: &str, record_key: &str, sealed: &[u8]) -> Result<Vec<u8>> {
    if sealed.len() < 24 + 16 {
        return Err(Error::new("store_corrupt", "record too short"));
    }
    let key = seed.store_key(chain, pool);
    let cipher = XChaCha20Poly1305::new(key.as_ref().into());
    cipher
        .decrypt(XNonce::from_slice(&sealed[..24]), Payload { msg: &sealed[24..], aad: &ad(chain, pool, record_type, record_key) })
        .map_err(|_| Error::new("store_corrupt", "record does not authenticate"))
}

/// The opaque name a record is stored under: `HMAC-SHA256(id key, len ‖ type ‖ len ‖ key)`, hex,
/// with its own key and a length-prefixed (injective) encoding (SDK-IM11).
pub fn record_id(seed: &dyn StoreKeys, chain: &Felt32, pool: &Felt32, record_type: &str, record_key: &str) -> String {
    let key = seed.store_id_key(chain, pool);
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key.as_ref()).expect("any key length");
    for part in [record_type, record_key] {
        m.update(&(part.len() as u32).to_be_bytes());
        m.update(part.as_bytes());
    }
    hex::encode(m.finalize().into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{BoundSeed, Seed};
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    #[test]
    fn records_are_bound_to_their_place() {
        let s = Seed::from_bytes(&[2u8; 32]).unwrap();
        let (c, p) = ([1u8; 32], [2u8; 32]);
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let sealed = seal(&s, &c, &p, "note", "7", b"hello", &mut rng).unwrap();
        assert_eq!(open(&s, &c, &p, "note", "7", &sealed).unwrap(), b"hello");
        assert!(open(&s, &c, &p, "note", "8", &sealed).is_err());
        assert!(open(&s, &c, &p, "record", "7", &sealed).is_err());
        assert!(open(&s, &c, &[3u8; 32], "note", "7", &sealed).is_err());
        assert_ne!(record_id(&s, &c, &p, "note", "7"), record_id(&s, &c, &p, "note", "8"));
        // A bound wallet's store is its own: it cannot open the Templar wallet's records.
        let mut account = [0u8; 32];
        account[31] = 4;
        let b = BoundSeed::from_bytes(&[2u8; 28]).unwrap().wallet(&account).unwrap();
        assert!(open(&b, &c, &p, "note", "7", &sealed).is_err());
        let sealed_b = seal(&b, &c, &p, "note", "7", b"hello", &mut rng).unwrap();
        assert_eq!(open(&b, &c, &p, "note", "7", &sealed_b).unwrap(), b"hello");
        assert_ne!(record_id(&b, &c, &p, "note", "7"), record_id(&s, &c, &p, "note", "7"));
    }
}
