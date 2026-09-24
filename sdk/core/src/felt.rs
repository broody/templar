//! Felts as 32 big-endian bytes, with fallible parsing and the encoders the relation uses
//! (nine 28-bit limbs), so no input can reach the relation's panicking `felt_limbs` (SDK-M2).
use starknet_types_core::felt::Felt;
use starknet_types_core::hash::{Poseidon, StarkHash};

use crate::{Error, Result};

pub type Felt32 = [u8; 32];

/// The Starknet field modulus, big-endian: 2^251 + 17·2^192 + 1.
const MODULUS: Felt32 = {
    let mut m = [0u8; 32];
    m[0] = 0x08;
    m[7] = 0x11;
    m[31] = 0x01;
    m
};

/// A `0x` hex felt below the field modulus.
pub fn parse(hex: &str) -> Result<Felt32> {
    let digits = hex.strip_prefix("0x").ok_or_else(|| Error::input("felt: missing 0x"))?;
    if digits.is_empty() || digits.len() > 64 || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::input("felt: not hex"));
    }
    let padded = format!("{digits:0>64}");
    let mut out = [0u8; 32];
    hex::decode_to_slice(padded, &mut out).map_err(|_| Error::input("felt: not hex"))?;
    if out >= MODULUS {
        return Err(Error::input("felt: not below the field modulus"));
    }
    Ok(out)
}

/// The canonical text form: lowercase, `0x`, no leading zeros (`0x0` for zero).
pub fn to_hex(f: &Felt32) -> String {
    let s = hex::encode(f);
    let t = s.trim_start_matches('0');
    format!("0x{}", if t.is_empty() { "0" } else { t })
}

pub fn from_u128(v: u128) -> Felt32 {
    let mut out = [0u8; 32];
    out[16..].copy_from_slice(&v.to_be_bytes());
    out
}

pub fn from_short_string(s: &str) -> Result<Felt32> {
    if s.len() > 31 || !s.is_ascii() {
        return Err(Error::input("short string"));
    }
    let mut out = [0u8; 32];
    out[32 - s.len()..].copy_from_slice(s.as_bytes());
    Ok(out)
}

pub fn is_zero(f: &Felt32) -> bool {
    f.iter().all(|b| *b == 0)
}

/// Below 2^251 (addresses, asset identifiers).
pub fn below_2_251(f: &Felt32) -> bool {
    f[0] < 0x08
}

/// A nonzero value below 2^251: a contract address or an asset identifier.
pub fn check_address(f: &Felt32, what: &str) -> Result<()> {
    if is_zero(f) || !below_2_251(f) {
        return Err(Error::input(&format!("{what}: zero or not below 2^251")));
    }
    Ok(())
}

/// Nine 28-bit little-endian limbs (the relation's `felt_limbs`), for a value below 2^252.
pub fn limbs(f: &Felt32) -> Result<[u32; 9]> {
    if f[0] >= 0x10 {
        return Err(Error::input("felt: not below 2^252"));
    }
    let bit = |k: usize| -> u32 { ((f[31 - k / 8] >> (k % 8)) & 1) as u32 };
    Ok(std::array::from_fn(|l| (0..28).map(|b| bit(l * 28 + b) << b).sum()))
}

pub fn to_felt(f: &Felt32) -> Felt {
    Felt::from_bytes_be(f)
}

pub fn from_felt(f: &Felt) -> Felt32 {
    f.to_bytes_be()
}

/// Starknet `poseidon_hash_span`.
pub fn poseidon(values: &[Felt32]) -> Felt32 {
    let v: Vec<Felt> = values.iter().map(to_felt).collect();
    from_felt(&Poseidon::hash_array(&v))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limbs_match_the_relation() {
        for h in ["0x0", "0x1", "0x534e5f5345504f4c4941", "0x7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"] {
            assert_eq!(limbs(&parse(h).unwrap()).unwrap(), templar_client_verifier_circuit::payment::felt_limbs(h), "{h}");
        }
        assert!(limbs(&parse("0x800000000000011000000000000000000000000000000000000000000000000").unwrap()).is_ok());
    }

    #[test]
    fn parse_rejects() {
        for h in ["1", "0x", "0xg", "0x800000000000011000000000000000000000000000000000000000000000001", &format!("0x{}", "f".repeat(65))] {
            assert!(parse(h).is_err(), "{h}");
        }
        assert_eq!(to_hex(&parse("0x00ab").unwrap()), "0xab");
    }
}
