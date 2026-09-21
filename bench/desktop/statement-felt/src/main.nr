// Experimental ordinary 2/2/1 statement; not a production format.
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

fn hash<let N: u32>(values: [Field; N]) -> Field {
    let mut s = [Felt252::zero(); 3];
    for block in 0..(N / 2) {
        Felt252::from(values[block*2]).validate_in_field();
        Felt252::from(values[block*2+1]).validate_in_field();
        s[0] = s[0] + Felt252::from(values[block*2]);
        s[1] = s[1] + Felt252::from(values[block*2+1]);
        s = hades(s);
    }
    if N % 2 == 1 {
        Felt252::from(values[N-1]).validate_in_field();
        s[0] = s[0] + Felt252::from(values[N-1]); s[1] = s[1] + Felt252::one();
    } else { s[0] = s[0] + Felt252::one(); }
    bignum::bignum::to_field(hades(s)[0])
}
global VERSION: Field = 112014988236564148666166936915858640945;
global BIND: Field = 1710723966219209225703245517313586;
global NF: Field = 104122676411346503581809280092728874547;
global CM: Field = 22904328969783278087854131930810541561395;
global NI: Field = 26647471191471950591998022714362800264755;
global NS: Field = 6821752625017608834574514217474175520101939;

struct Input { salt: u128, owner: Field, amount: u128, index: u32, path: [Field; 32] }
struct Invoice { inner: Field, amount: u128 }
fn main(chain: Field, pool: Field, root: Field, token: Field,
        n_in: u32, inputs: [Input; 2], n_out: u32, outputs: [Invoice; 2],
        withdrawal: u128, recipient: Field) -> pub [Field; 8] {
    assert(n_in > 0 & n_in <= 2); assert(n_out <= 2); assert(token != 0);
    if withdrawal == 0 { assert(recipient == 0); } else { assert(recipient != 0); }
    let mut nullifiers = [0; 2]; let mut commitments = [0; 2];
    let mut sum_in: Field = 0; let mut sum_out: Field = withdrawal as Field;
    for i in 0..2 {
        if i < n_in {
            let note = inputs[i]; assert(note.amount > 0);
            let secret = hash([NS, note.salt as Field, note.owner]);
            let inner = hash([NI, secret]);
            let mut node = hash([CM, token, note.amount as Field, 0, 0, inner]);
            for level in 0..32 {
                let right = ((note.index >> level) & 1) == 1;
                let left = if right { note.path[level] } else { node };
                let r = if right { node } else { note.path[level] };
                node = hash([left,r]);
            }
            assert(node == root);
            nullifiers[i] = hash([NF,secret]); assert(nullifiers[i] != 0);
            sum_in = sum_in + note.amount as Field;
        }
        if i < n_out {
            let invoice = outputs[i]; assert(invoice.inner != 0); assert(invoice.amount > 0);
            commitments[i] = hash([CM,token,invoice.amount as Field,0,0,invoice.inner]);
            assert(commitments[i] != 0);
            sum_out = sum_out + invoice.amount as Field;
        }
    }
    if n_in == 2 { assert(nullifiers[0] != nullifiers[1]); }
    assert(sum_in == sum_out);
    let binding = hash([BIND, VERSION,chain,pool,root,n_in as Field,nullifiers[0],nullifiers[1],
                        n_out as Field,commitments[0],commitments[1],token,withdrawal as Field,recipient]);
    [VERSION,chain,pool,root,0,0,0,binding]
}
