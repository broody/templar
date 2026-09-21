// Scaling measurement for ADR-0016: N chained felt252-Poseidon hash_pairs
// (2 permutations each) to size Honk prove time against the full M2 statement
// (~358 permutations, ~14.6M gates at the measured ~40.9k gates/permutation).

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

fn hades(mut st: [Felt252; 3]) -> [Felt252; 3] {
    for r in 0..91 {
        for j in 0..3 {
            st[j] = st[j] + felt252_from_limbs(ARK_LIMBS[r][j]);
        }
        if (r < 4) | (r >= 87) {
            st[0] = cube(st[0]);
            st[1] = cube(st[1]);
            st[2] = cube(st[2]);
        } else {
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

fn hash_pair(a: Felt252, b: Felt252) -> Felt252 {
    let st = hades([a, b, Felt252::zero()]);
    let st2 = hades([st[0] + Felt252::one(), st[1], st[2]]);
    st2[0]
}

/// N chained hash_pairs = 2N permutations.
fn main(a: Field, b: Field) -> pub Felt252 {
    let mut acc = Felt252::from(a);
    let mut cur = Felt252::from(b);
    for _ in 0..64 {
        acc = hash_pair(acc, cur);
        cur = cur + Felt252::one();
    }
    acc
}
