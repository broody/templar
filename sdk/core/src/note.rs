//! Notes (spec §5): asset identifiers, `inner`, commitments and nullifiers through the relation's
//! own hashes with fallible encoders, and the 256-byte plaintexts `M301` and `PS01`.
use templar_client_verifier_circuit::payment::{self, INNER, h};

use crate::felt::{self, Felt32};
use crate::{Digest, Error, Result, digest_ok};

pub const ERC20: u16 = 20;
pub const ERC721: u16 = 721;
pub const ERC1155: u16 = 1155;

/// An asset identifier: an ERC20 address, or `Poseidon('TEMPLAR_ASSET_V1', standard, contract,
/// id.low, id.high)` for ERC721 and ERC1155, which must be below 2^251 (hidden-asset spec §3.1).
pub fn asset_id(standard: u16, contract: &Felt32, id: u128x2) -> Result<Felt32> {
    felt::check_address(contract, "contract")?;
    match standard {
        ERC20 => Ok(*contract),
        ERC721 | ERC1155 => {
            let a = felt::poseidon(&[
                felt::from_short_string("TEMPLAR_ASSET_V1")?,
                felt::from_u128(standard as u128),
                *contract,
                felt::from_u128(id.0),
                felt::from_u128(id.1),
            ]);
            if !felt::below_2_251(&a) {
                return Err(Error::new("asset_range", "this (contract, id) has an identifier at or above 2^251 and cannot be deposited"));
            }
            Ok(a)
        }
        _ => Err(Error::input("standard: not 20, 721 or 1155")),
    }
}

/// A u256 as `(low, high)` 128-bit halves.
#[allow(non_camel_case_types)]
pub type u128x2 = (u128, u128);

pub fn inner(receiver: &Digest, rho: &Digest) -> Digest {
    h(INNER, 0, &[*receiver, *rho].concat())
}

/// `cm = H(NOTE, chain₉ ‖ pool₉ ‖ asset₉ ‖ amount₈ ‖ inner)`; every input range-checked first.
pub fn commitment(chain: &Felt32, pool: &Felt32, asset: &Felt32, amount: u128, receiver: &Digest, rho: &Digest) -> Result<Digest> {
    if !digest_ok(receiver) || !digest_ok(rho) {
        return Err(Error::input("receiver or rho: not canonical and nonzero"));
    }
    let context = [felt::limbs(chain)?, felt::limbs(pool)?, felt::limbs(asset)?].concat();
    Ok(payment::commitment(&context, amount, receiver, rho))
}

/// What the pool computes on a deposit: `H(NOTE, chain₉ ‖ pool₉ ‖ asset₉ ‖ amount₈ ‖ inner)`.
pub fn commitment_of_inner(chain: &Felt32, pool: &Felt32, asset: &Felt32, amount: u128, inner: &Digest) -> Result<Digest> {
    if inner.iter().any(|w| *w >= crate::P) {
        return Err(Error::input("inner: not canonical"));
    }
    let context = [felt::limbs(chain)?, felt::limbs(pool)?, felt::limbs(asset)?].concat();
    Ok(h(templar_client_verifier_circuit::payment::NOTE, 0, &[context, payment::amount_limbs(amount).to_vec(), inner.to_vec()].concat()))
}

/// `nf = H(NF, nk ‖ cm ‖ pos_lo ‖ pos_hi)`.
pub fn nullifier(nk: &Digest, cm: &Digest, position: u32) -> Digest {
    payment::nullifier(nk, cm, position)
}

fn words_bytes(d: &Digest) -> [u8; 36] {
    let mut out = [0u8; 36];
    for (i, w) in d.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&w.to_be_bytes());
    }
    out
}

fn bytes_words(b: &[u8]) -> Digest {
    std::array::from_fn(|i| u32::from_be_bytes(b[4 * i..4 * i + 4].try_into().unwrap()))
}

/// An ordinary note's plaintext: `'M301' ‖ asset₃₂ ‖ receiver₃₆ ‖ rho₃₆ ‖ amount₁₆`, zero padded.
pub fn m301(asset: &Felt32, receiver: &Digest, rho: &Digest, amount: u128) -> [u8; 256] {
    let mut x = [0u8; 256];
    x[..4].copy_from_slice(b"M301");
    x[4..36].copy_from_slice(asset);
    x[36..72].copy_from_slice(&words_bytes(receiver));
    x[72..108].copy_from_slice(&words_bytes(rho));
    x[108..124].copy_from_slice(&amount.to_be_bytes());
    x
}

/// A decoded plaintext, before any hashing: every field is range-checked (spec §6 rules 3–4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plaintext {
    pub asset: Felt32,
    pub receiver: Digest,
    pub rho: Digest,
    /// `M301`: the amount. `PS01`: the note amount (side 1) or zero (side 0).
    pub amount: u128,
    /// `PS01` only: 0 (the settled `x` side) or 1 (the remainder side).
    pub side: Option<u8>,
}

pub fn parse(x: &[u8]) -> Option<Plaintext> {
    if x.len() != 256 {
        return None;
    }
    let side = match &x[..4] {
        b"M301" => {
            if x[124..].iter().any(|b| *b != 0) {
                return None;
            }
            None
        }
        b"PS01" => {
            if x[124] > 1 || x[125..].iter().any(|b| *b != 0) {
                return None;
            }
            Some(x[124])
        }
        _ => return None,
    };
    let asset: Felt32 = x[4..36].try_into().unwrap();
    let receiver = bytes_words(&x[36..72]);
    let rho = bytes_words(&x[72..108]);
    let amount = u128::from_be_bytes(x[108..124].try_into().unwrap());
    if felt::check_address(&asset, "asset").is_err() || !digest_ok(&receiver) || !digest_ok(&rho) {
        return None;
    }
    Some(Plaintext { asset, receiver, rho, amount, side })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plaintext_rules() {
        let a = felt::parse("0x49d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7").unwrap();
        let (r, rho) = ([1u32; 9], [2u32; 9]);
        let x = m301(&a, &r, &rho, 5);
        assert_eq!(parse(&x).unwrap(), Plaintext { asset: a, receiver: r, rho, amount: 5, side: None });
        let mut bad = x;
        bad[200] = 1;
        assert!(parse(&bad).is_none(), "nonzero padding");
        let mut bad = x;
        bad[72..76].copy_from_slice(&0x7fff_ffffu32.to_be_bytes());
        assert!(parse(&bad).is_none(), "rho word = p");
        let mut bad = x;
        bad[72..108].fill(0);
        assert!(parse(&bad).is_none(), "zero rho");
        let mut bad = x;
        bad[4] = 0x10;
        assert!(parse(&bad).is_none(), "asset at or above 2^252");
    }

    #[test]
    fn asset_ids() {
        let c = felt::parse("0x535ca4").unwrap();
        assert_eq!(asset_id(ERC20, &c, (0, 0)).unwrap(), c);
        assert_ne!(asset_id(ERC721, &c, (2, 0)).unwrap(), asset_id(ERC1155, &c, (2, 0)).unwrap());
        assert!(asset_id(7, &c, (0, 0)).is_err());
    }
}
