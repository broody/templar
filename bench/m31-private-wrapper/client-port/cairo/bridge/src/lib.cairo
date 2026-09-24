//! Circuit-A bridge: verifies one server proof that a TMPZK002 private-membership proof
//! is valid, and checks its statement. No private note or key is accepted by this API.
//!
//! The vendored verifier pins circuit A's topology, preprocessed root, PCS config and
//! 17 outputs (generated from its trusted build manifest). Outputs 0..8 are the words of
//! `Blake2s(x)`, outputs 8..17 the membership root. `x` is rebuilt here byte-exactly as
//! `proof::public_bytes`: MAGIC, the client-circuit digest, then
//! `{"chain":"0x..","pool":"0x..","root":[..]}`.
use core::blake::{blake2s_compress, blake2s_finalize};
use core::box::BoxTrait;
use stwo_circuit_air::{CircuitProof, verify_circuit};
use stwo_verifier_core::fields::qm31::QM31Trait;

pub mod statement_consts;

const BLAKE2S_256_INITIAL_STATE: [u32; 8] = [
    0x6B08E647, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];
pub const N_ROOT: u32 = 9;

/// Verifies exactly one encoded circuit-A proof. Returns `(Blake2s(x) words, root)`.
pub fn verify_membership(mut proof_data: Span<felt252>) -> (Array<u32>, Array<u32>) {
    let proof: CircuitProof = Serde::deserialize(ref proof_data).expect('INVALID_PROOF_ENCODING');
    assert!(proof_data.is_empty(), "trailing proof data");
    let mut digest = array![];
    let mut root = array![];
    let mut k: u32 = 0;
    for value in proof.claim.public_data.output_values.span() {
        let [c0, c1, c2, c3] = QM31Trait::to_fixed_array(*value);
        let (c0, c1, c2, c3): (u32, u32, u32, u32) = (c0.into(), c1.into(), c2.into(), c3.into());
        assert!(c2 == 0 && c3 == 0, "output encoding");
        if k < 8 {
            assert!(c0 < 0x10000 && c1 < 0x10000, "digest word encoding");
            digest.append(c0 + c1 * 0x10000);
        } else {
            assert!(c1 == 0, "root encoding");
            root.append(c0);
        }
        k += 1;
    }
    assert!(k == 8 + N_ROOT, "output count");
    verify_circuit(proof);
    (digest, root)
}

fn push_str(ref out: Array<u8>, s: ByteArray) {
    let mut i = 0;
    while i < s.len() {
        out.append(s.at(i).unwrap());
        i += 1;
    }
}

/// Lowercase hexadecimal with `0x` and no leading zeros, as the client's canonical context.
fn push_hex(ref out: Array<u8>, value: felt252) {
    let v: u256 = value.into();
    push_str(ref out, "0x");
    let mut started = false;
    let mut shift: u32 = 64;
    while shift > 0 {
        shift -= 1;
        let limb = if shift >= 32 { v.high } else { v.low };
        let nibble_shift: u128 = if shift >= 32 { (shift - 32).into() } else { shift.into() };
        let nibble: u8 = ((limb / pow16(nibble_shift)) % 16).try_into().unwrap();
        if nibble != 0 || started || shift == 0 {
            started = true;
            out.append(if nibble < 10 { 48 + nibble } else { 87 + nibble });
        }
    }
}

fn pow16(n: u128) -> u128 {
    let mut r: u128 = 1;
    let mut i: u128 = 0;
    while i < n {
        r *= 16;
        i += 1;
    }
    r
}

fn push_decimal(ref out: Array<u8>, mut v: u32) {
    let mut digits = array![];
    loop {
        digits.append((v % 10).try_into().unwrap());
        v /= 10;
        if v == 0 {
            break;
        }
    }
    let mut i = digits.len();
    while i > 0 {
        i -= 1;
        out.append(48 + *digits.at(i));
    }
}

/// `proof::public_bytes(Public { chain, pool, root })`.
pub fn statement_bytes(chain: felt252, pool: felt252, root: Span<u32>) -> Array<u8> {
    assert!(root.len() == N_ROOT, "root length");
    let mut out = statement_consts::statement_prefix();
    push_str(ref out, "{\"chain\":\"");
    push_hex(ref out, chain);
    push_str(ref out, "\",\"pool\":\"");
    push_hex(ref out, pool);
    push_str(ref out, "\",\"root\":[");
    let mut first = true;
    for r in root {
        if !first {
            out.append(44);
        }
        first = false;
        push_decimal(ref out, *r);
    }
    push_str(ref out, "]}");
    out
}

/// Unkeyed Blake2s-256 of an arbitrary byte string; output words little-endian.
pub fn blake2s_bytes(bytes: Span<u8>) -> [u32; 8] {
    let n = bytes.len();
    let mut words: Array<u32> = array![];
    let mut i = 0;
    while i < n {
        let mut w: u32 = 0;
        let mut k = 4;
        while k > 0 {
            k -= 1;
            let b: u32 = if i + k < n { (*bytes.at(i + k)).into() } else { 0 };
            w = w * 256 + b;
        }
        words.append(w);
        i += 4;
    }
    let n_blocks = if n == 0 { 1 } else { (n + 63) / 64 };
    while words.len() < n_blocks * 16 {
        words.append(0);
    }
    let mut state = BoxTrait::new(BLAKE2S_256_INITIAL_STATE);
    let mut span = words.span();
    let mut block = 0;
    let mut result = state;
    while let Some(msg) = span.multi_pop_front::<16>() {
        block += 1;
        if block == n_blocks {
            result = blake2s_finalize(state, n, *msg);
        } else {
            state = blake2s_compress(state, block * 64, *msg);
        }
    }
    result.unbox()
}

/// Verifies the proof and its statement for the given chain and pool. Returns the root.
pub fn verify_statement(chain: felt252, pool: felt252, proof_data: Span<felt252>) -> Array<u32> {
    let (digest, root) = verify_membership(proof_data);
    let x = statement_bytes(chain, pool, root.span());
    let [h0, h1, h2, h3, h4, h5, h6, h7] = blake2s_bytes(x.span());
    assert!(digest.span() == array![h0, h1, h2, h3, h4, h5, h6, h7].span(), "statement digest");
    root
}

#[executable]
fn main(chain: felt252, pool: felt252, proof_data: Span<felt252>) -> Array<felt252> {
    let root = verify_statement(chain, pool, proof_data);
    let mut out = array![chain, pool];
    for r in root.span() {
        out.append((*r).into());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    // Blake2s-256 of "abc", the empty message and the 64/65-byte block boundaries (hashlib).
    #[test]
    fn blake2s_known_answers() {
        let abc = array![97_u8, 98, 99];
        assert!(
            blake2s_bytes(abc.span()) == [
                0x8c5e8c50, 0xe2147c32, 0xa32ba7e1, 0x2f45eb4e, 0x208b4537, 0x293ad69e, 0x4c9b994d,
                0x82596786,
            ],
        );
        let empty: Array<u8> = array![];
        assert!(
            blake2s_bytes(empty.span()) == [
                0x307a2169, 0x94809079, 0xd02111e1, 0x7c4a3542, 0x48b6551f, 0x1ea5a12c, 0xfd0d251b,
                0xf9eed01e,
            ],
        );
        let mut b64: Array<u8> = array![];
        let mut i: u8 = 0;
        while i < 64 {
            b64.append(i);
            i += 1;
        }
        assert!(
            blake2s_bytes(b64.span()) == [
                0x8b4ef356, 0x907e5596, 0x524bf2c1, 0x519dc8d0, 0x1bcf6a08, 0xcf34f600, 0x3392de1d,
                0x3eaaeab8,
            ],
        );
        b64.append(64);
        assert!(
            blake2s_bytes(b64.span()) == [
                0x94ee531b, 0x4b4ef3aa, 0xde489d15, 0x067f2c35, 0x0ea4d061, 0x0b5af9df, 0x09b43916,
                0x7244970e,
            ],
        );
    }
    #[test]
    fn hex_and_decimal_are_canonical() {
        let mut out = array![];
        push_hex(ref out, 0x534e5f5345504f4c4941);
        push_str(ref out, ",");
        push_hex(ref out, 0x123);
        push_str(ref out, ",");
        push_decimal(ref out, 0);
        push_str(ref out, ",");
        push_decimal(ref out, 2147483646);
        let mut expected = array![];
        push_str(ref expected, "0x534e5f5345504f4c4941,0x123,0,2147483646");
        assert!(out == expected);
    }
}
