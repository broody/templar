//! libsodium sealed boxes (`crypto_box_seal`: X25519, HSalsa20, XSalsa20-Poly1305) and the
//! pool's ciphertext words (spec §5). Both directions reject a non-contributory X25519 result
//! (an all-zero shared secret), as libsodium does (SDK-M6).
use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use rand_core::{CryptoRng, RngCore};
use salsa20::cipher::consts::U10;
use x25519_dalek::{PublicKey, StaticSecret};
use xsalsa20poly1305::aead::{AeadInPlace, KeyInit};
use xsalsa20poly1305::{Tag, XSalsa20Poly1305};

use crate::felt::{self, Felt32};
use crate::{Error, Result};

pub const PLAINTEXT: usize = 256;
pub const SEALED: usize = 304;
const OVERHEAD: usize = 48;

fn nonce(epk: &[u8; 32], pk: &[u8; 32]) -> [u8; 24] {
    let mut h = Blake2bVar::new(24).expect("24 is a valid BLAKE2b length");
    h.update(epk);
    h.update(pk);
    let mut out = [0u8; 24];
    h.finalize_variable(&mut out).expect("24 bytes");
    out
}

/// `crypto_box_beforenm`: HSalsa20 of the shared secret with a zero input.
fn box_key(secret: &StaticSecret, public: &[u8; 32]) -> Option<XSalsa20Poly1305> {
    let shared = secret.diffie_hellman(&PublicKey::from(*public));
    if !shared.was_contributory() {
        return None;
    }
    let k = salsa20::hsalsa::<U10>(shared.as_bytes().into(), &[0u8; 16].into());
    Some(XSalsa20Poly1305::new(&k))
}

/// `epk ‖ tag ‖ ciphertext` of `message` to `pk`, with a fresh ephemeral key.
pub fn seal(pk: &[u8; 32], message: &[u8], rng: &mut (impl RngCore + CryptoRng)) -> Result<Vec<u8>> {
    let esk = StaticSecret::random_from_rng(&mut *rng);
    seal_with(pk, message, &esk)
}

/// A sealed box with a given ephemeral secret (tests and known-answer vectors).
pub fn seal_with(pk: &[u8; 32], message: &[u8], esk: &StaticSecret) -> Result<Vec<u8>> {
    let epk = PublicKey::from(esk).to_bytes();
    let cipher = box_key(esk, pk).ok_or_else(|| Error::input("sealing to a low-order key"))?;
    let mut body = message.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(&nonce(&epk, pk).into(), b"", &mut body)
        .map_err(|_| Error::new("internal", "sealing"))?;
    let mut out = Vec::with_capacity(OVERHEAD + body.len());
    out.extend_from_slice(&epk);
    out.extend_from_slice(&tag);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Opens a sealed box with the recipient's (clamped) secret; `None` if it is not for this key.
pub fn open(ivk: &[u8; 32], sealed: &[u8]) -> Option<Vec<u8>> {
    if sealed.len() < OVERHEAD {
        return None;
    }
    let secret = StaticSecret::from(*ivk);
    let pk = PublicKey::from(&secret).to_bytes();
    let epk: [u8; 32] = sealed[..32].try_into().ok()?;
    let cipher = box_key(&secret, &epk)?;
    let tag = Tag::from_slice(&sealed[32..48]);
    let mut body = sealed[48..].to_vec();
    cipher.decrypt_in_place_detached(&nonce(&epk, &pk).into(), b"", &mut body, tag).ok()?;
    Some(body)
}

/// 304 bytes as nine 31-byte and one 25-byte big-endian felts (the pool's payload words).
pub fn to_words(sealed: &[u8]) -> Result<[Felt32; 10]> {
    if sealed.len() != SEALED {
        return Err(Error::input("sealed box: not 304 bytes"));
    }
    Ok(std::array::from_fn(|i| {
        let chunk = if i < 9 { &sealed[31 * i..31 * i + 31] } else { &sealed[279..] };
        let mut f = [0u8; 32];
        f[32 - chunk.len()..].copy_from_slice(chunk);
        f
    }))
}

/// The inverse of [`to_words`]; words out of range (nine below 2^248, the last below 2^200) are
/// rejected, never reduced.
pub fn from_words(words: &[Felt32]) -> Result<[u8; SEALED]> {
    if words.len() != 10 {
        return Err(Error::input("ciphertext: not ten words"));
    }
    let mut out = [0u8; SEALED];
    for (i, w) in words.iter().enumerate() {
        let width = if i < 9 { 31 } else { 25 };
        if w[..32 - width].iter().any(|b| *b != 0) {
            return Err(Error::input("ciphertext: word out of range"));
        }
        let at = 31 * i;
        out[at..at + width].copy_from_slice(&w[32 - width..]);
    }
    Ok(out)
}

/// `Poseidon('CTRL_DELIVERY_V1', 304, words)`: the delivery digest the pool binds.
pub fn delivery(words: &[Felt32; 10]) -> Felt32 {
    let mut v = vec![felt::from_short_string("CTRL_DELIVERY_V1").expect("label"), felt::from_u128(SEALED as u128)];
    v.extend_from_slice(words);
    felt::poseidon(&v)
}

/// The public key of a clamped secret.
pub fn public_key(ivk: &[u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(*ivk)).to_bytes()
}

/// RFC 7748 clamping.
pub fn clamp(mut k: [u8; 32]) -> [u8; 32] {
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    k
}

/// libsodium's blocked u-coordinates below p (little-endian): 0, 1, the two order-8 points and
/// p − 1. `p` and `p + 1` are excluded by the range check (spec §4.1, SDK-M6).
const BLOCKED: [[u8; 32]; 5] = [
    [0; 32],
    [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [
        0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb,
        0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00,
    ],
    [
        0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4,
        0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57,
    ],
    [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
    ],
];

/// A public key an address may carry: bit 255 clear, `u < 2^255 − 19`, not blocked.
pub fn public_key_ok(pk: &[u8; 32]) -> bool {
    if pk[31] & 0x80 != 0 {
        return false;
    }
    // u ≥ p = 2^255 − 19 ⇔ the top 31 bytes are all 0xff/0x7f and the low byte is ≥ 0xed.
    let at_least_p = pk[31] == 0x7f && pk[1..31].iter().all(|b| *b == 0xff) && pk[0] >= 0xed;
    !at_least_p && !BLOCKED.contains(pk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    #[test]
    fn round_trip_and_words() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let ivk = clamp([7u8; 32]);
        let pk = public_key(&ivk);
        let m = [9u8; PLAINTEXT];
        let sealed = seal(&pk, &m, &mut rng).unwrap();
        assert_eq!(sealed.len(), SEALED);
        assert_eq!(open(&ivk, &sealed).unwrap(), m);
        assert!(open(&clamp([8u8; 32]), &sealed).is_none());
        let words = to_words(&sealed).unwrap();
        assert_eq!(from_words(&words).unwrap().to_vec(), sealed);
        let mut bad = words;
        bad[9][6] = 1;
        assert!(from_words(&bad).is_err());
    }

    #[test]
    fn blocked_keys() {
        for k in BLOCKED {
            assert!(!public_key_ok(&k));
            assert!(seal(&k, b"x", &mut ChaCha20Rng::seed_from_u64(2)).is_err());
        }
        let mut p = [0xffu8; 32];
        p[31] = 0x7f;
        p[0] = 0xed;
        assert!(!public_key_ok(&p));
        p[0] = 0xec;
        assert!(!public_key_ok(&p));
        assert!(public_key_ok(&public_key(&clamp([3u8; 32]))));
    }
}
