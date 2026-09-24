//! The client's hashes (`client-port/src/payment.rs`) in Cairo: the framed rate-15 sponge over
//! the width-24 permutation, both tree-node formats, note commitments and the felt/amount limb
//! encodings. Digests are nine canonical M31 words.
use core::poseidon::poseidon_hash_span;
use crate::perm::permutation;

pub const P: u32 = 0x7fffffff;
/// Frame tag `TMR0`.
pub const TAG: felt252 = 0x544d5230;
pub const INNER: felt252 = 4;
pub const NOTE: felt252 = 5;
pub const NODE: felt252 = 6;
pub const NODE1: felt252 = 8;

pub type Digest = [felt252; 9];

/// Tree-node format: `SPONGE` is `H(NODE, level, l ‖ r)` (two permutations); `COMPRESS` is one
/// truncated permutation over `l ‖ r ‖ [TAG, 1, NODE1, level, 0, 0]`.
pub const SPONGE: u8 = 0;
pub const COMPRESS: u8 = 1;

fn to_state(a: Array<felt252>) -> [felt252; 24] {
    (*a.span().try_into().unwrap()).unbox()
}

fn digest_of(s: [felt252; 24]) -> Digest {
    let [s0, s1, s2, s3, s4, s5, s6, s7, s8, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _] = s;
    [s0, s1, s2, s3, s4, s5, s6, s7, s8]
}

/// `membership::sponge`: overwrite the first `n ≤ 15` rate words; a short last block is padded
/// with a 1 then zeros up to 15; a full last block adds 1 to word 15 (the first capacity word).
pub fn sponge(message: Span<felt252>) -> Digest {
    let mut state: [felt252; 24] = [0; 24];
    let mut rest = message;
    loop {
        let n = if rest.len() < 15 { rest.len() } else { 15 };
        let block = rest.slice(0, n);
        rest = rest.slice(n, rest.len() - n);
        let done = rest.is_empty();
        let old = state.span();
        let mut next: Array<felt252> = array![];
        let mut i = 0;
        while i < 15 {
            if i < n {
                next.append(*block.at(i));
            } else if i == n {
                next.append(1);
            } else {
                next.append(0);
            }
            i += 1;
        }
        while i < 24 {
            let c = *old.at(i);
            next.append(if i == 15 && n == 15 && done { c + 1 } else { c });
            i += 1;
        }
        state = permutation(to_state(next));
        if done {
            break;
        }
    }
    digest_of(state)
}

/// `H(kind, level, payload) = sponge([TAG, 1, kind, level] ++ payload)`.
pub fn h(kind: felt252, level: felt252, payload: Span<felt252>) -> Digest {
    let mut m = array![TAG, 1, kind, level];
    m.append_span(payload);
    sponge(m.span())
}

/// A tree node at `level` from its children, in the given format.
pub fn node(format: u8, level: felt252, l: Digest, r: Digest) -> Digest {
    let [l0, l1, l2, l3, l4, l5, l6, l7, l8] = l;
    let [r0, r1, r2, r3, r4, r5, r6, r7, r8] = r;
    if format == COMPRESS {
        digest_of(
            permutation(
                [
                    l0, l1, l2, l3, l4, l5, l6, l7, l8, r0, r1, r2, r3, r4, r5, r6, r7, r8, TAG, 1,
                    NODE1, level, 0, 0,
                ],
            ),
        )
    } else {
        h(NODE, level, array![l0, l1, l2, l3, l4, l5, l6, l7, l8, r0, r1, r2, r3, r4, r5, r6, r7, r8].span())
    }
}

/// A felt as nine 28-bit little-endian limbs (`payment::felt_limbs`).
pub fn felt_limbs(v: felt252, ref out: Array<felt252>) {
    let mut x: u256 = v.into();
    let mut i: u32 = 0;
    while i < 9 {
        out.append((x % 0x10000000).try_into().unwrap());
        x = x / 0x10000000;
        i += 1;
    }
}

/// A u128 amount as eight 16-bit little-endian limbs (`payment::amount_limbs`).
pub fn amount_limbs(a: u128, ref out: Array<felt252>) {
    let mut x = a;
    let mut i: u32 = 0;
    while i < 8 {
        out.append((x % 0x10000).into());
        x = x / 0x10000;
        i += 1;
    }
}

/// `cm = H(NOTE, chain ‖ pool ‖ token ‖ amount₈ ‖ inner)`, the ordinary note commitment.
pub fn commitment(chain: felt252, pool: felt252, token: felt252, amount: u128, inner: Digest) -> Digest {
    let mut payload = array![];
    felt_limbs(chain, ref payload);
    felt_limbs(pool, ref payload);
    felt_limbs(token, ref payload);
    amount_limbs(amount, ref payload);
    payload.append_span(inner.span());
    h(NOTE, 0, payload.span())
}

/// A digest from calldata: exactly nine canonical M31 words.
pub fn read_digest(words: Span<felt252>) -> Digest {
    assert(words.len() == 9, 'DIGEST_LENGTH');
    for w in words {
        let v: u32 = (*w).try_into().expect('DIGEST_WORD');
        assert(v < P, 'DIGEST_WORD');
    }
    (*words.try_into().unwrap()).unbox()
}

pub fn is_zero(d: Digest) -> bool {
    let mut zero = true;
    for w in d.span() {
        if *w != 0 {
            zero = false;
        }
    }
    zero
}

/// A felt key for maps (root history, nullifier set): Poseidon over the nine words.
pub fn key(d: Digest) -> felt252 {
    poseidon_hash_span(d.span())
}

/// Nine words packed losslessly into two felts: words 0..8 in base 2^31, then word 8.
pub fn pack(d: Digest) -> (felt252, felt252) {
    let [w0, w1, w2, w3, w4, w5, w6, w7, w8] = d;
    let b: felt252 = 0x80000000;
    let lo = ((((((w7 * b + w6) * b + w5) * b + w4) * b + w3) * b + w2) * b + w1) * b + w0;
    (lo, w8)
}

pub fn unpack(lo: felt252, hi: felt252) -> Digest {
    let mut x: u256 = lo.into();
    let mut w: Array<felt252> = array![];
    let mut i: u32 = 0;
    while i < 8 {
        w.append((x % 0x80000000).try_into().unwrap());
        x = x / 0x80000000;
        i += 1;
    }
    w.append(hi);
    (*w.span().try_into().unwrap()).unbox()
}
