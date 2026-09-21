// felt252 (Starknet prime p = 2^251 + 17*2^192 + 1) Poseidon over noir-bignum.
// ADR-0016 benchmark: non-native Starknet-Poseidon in a Noir/UltraHonk stack.
// Byte-behavior validated against the Cairo VM vector (poseidon_hash_span([1,2])).

mod ark_constants;

use bignum::bignum::BigNum;
use bignum::bignum::derive_bignum;
use bignum::params::BigNumParams;
use ark_constants::ARK_LIMBS;

pub global FELT252_PARAMS: BigNumParams<3, 252> = BigNumParams {
    has_multiplicative_inverse: true,
    modulus: [0x1, 0x11000000000000000000, 0x800],
    double_modulus: [
        0x1000000000000000000000000000002,
        0x1000000000021ffffffffffffffffff,
        0xfff,
    ],
    redc_param: [
        0xffffffb33c0000000000a3207ffeff,
        0xffffffffef000000000000241fffff,
        0x7ffff,
    ],
};

#[derive_bignum(3, 252, quote { FELT252_PARAMS })]
pub struct Felt252 {
    limbs: [u128; 3],
}

fn felt252_from_limbs(limbs: [u128; 3]) -> Felt252 {
    Felt252 { limbs }
}

fn cube(x: Felt252) -> Felt252 {
    x * x * x
}

/// Canonical Starknet Poseidon permutation: x^3 S-box, r_f=8, r_p=83,
/// sha256-derived round constants, MDS [[3,1,1],[1,-1,1],[1,1,-2]].
fn hades(mut st: [Felt252; 3]) -> [Felt252; 3] {
    for r in 0..91 {
        for j in 0..3 {
            st[j] = st[j] + felt252_from_limbs(ARK_LIMBS[r][j]);
        }
        if (r < 4) | (r >= 87) {
            // full round: cube all three
            st[0] = cube(st[0]);
            st[1] = cube(st[1]);
            st[2] = cube(st[2]);
        } else {
            // partial round: cube the last element only
            st[2] = cube(st[2]);
        }
        let a = st[0];
        let b = st[1];
        let c = st[2];
        st[0] = a + a + a + b + c;
        st[1] = a - b + c;
        st[2] = a + b - c - c;
    }
    st
}

/// poseidon_hash_span([a, b]): absorb pair into the zero state, then the
/// even-length finalize permutation.
fn hash_pair(a: Felt252, b: Felt252) -> Felt252 {
    let st = hades([a, b, Felt252::zero()]);
    let st2 = hades([st[0] + Felt252::one(), st[1], st[2]]);
    st2[0]
}

fn main(a: Field, b: Field) -> pub Felt252 {
    let mut acc = Felt252::from(a);
    let mut cur = Felt252::from(b);
    for _ in 0..16 {
        acc = hash_pair(acc, cur);
        cur = cur + Felt252::one();
    }
    acc
}
