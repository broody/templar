//! Client bridge for the R0 payment on the arithmetic-only stwo-circuits route (fork
//! `templar/arithmetic-profile`). Verifies one blinded client payment proof and decodes its
//! public statement; pins the client circuit's hash (`pinned.cairo`).
//!
//! The 23 outputs carry 92 M31 limbs, four per QM31 in coordinate order: tag `TMPZ` `R0V1`,
//! chain, pool, token (28-bit LE felt limbs), root, nullifier₀, nullifier₁, commitment₀,
//! delivery₀ (felt limbs), commitment₁, delivery₁ (felt limbs); digests are nine M31 words.
//! The account binds the decoded statement with `binding` (felt252 Poseidon), which the pool
//! recomputes from its spend data, as the reference ordinary pool does.
use core::poseidon::poseidon_hash_span;
use stwo_circuit_air::{CircuitProof, compute_circuit_hash, verify_circuit};
use stwo_verifier_core::Hash;
use stwo_verifier_core::fields::qm31::QM31Trait;

pub mod pinned;

const N_OUTPUTS: u32 = 23;
const N_WORDS: u32 = 9;
const TAG_0: u32 = 0x544d505a;
const TAG_1: u32 = 0x52305631;
const LIMB_SHIFT: u256 = 0x10000000;

#[derive(Drop, Serde, PartialEq, Debug)]
pub struct Statement {
    pub chain: felt252,
    pub pool: felt252,
    pub token: felt252,
    pub root: Span<u32>,
    pub nullifiers: [Span<u32>; 2],
    pub commitments: [Span<u32>; 2],
    pub deliveries: [felt252; 2],
}

/// Nine 28-bit little-endian limbs as a canonical felt252 (value below the field prime).
fn felt_from_limbs(limbs: Span<u32>) -> felt252 {
    assert!(limbs.len() == N_WORDS, "limb count");
    let mut acc: u256 = 0;
    let mut i = limbs.len();
    while i > 0 {
        i -= 1;
        let limb: u256 = (*limbs.at(i)).into();
        assert!(limb < LIMB_SHIFT, "limb range");
        acc = acc * LIMB_SHIFT + limb;
    }
    acc.try_into().expect('non-canonical felt')
}

/// Verifies exactly one encoded client proof and returns the payment statement it proves.
pub fn verify_payment(mut proof_data: Span<felt252>) -> Statement {
    let proof: CircuitProof = Serde::deserialize(ref proof_data).expect('INVALID_PROOF_ENCODING');
    assert!(proof_data.is_empty(), "trailing proof data");
    let commitments: @Box<[Hash; 4]> = proof
        .stark_proof
        .commitment_scheme_proof
        .commitments
        .try_into()
        .unwrap();
    let [preprocessed_commitment, _, _, _] = commitments.unbox();
    let circuit_hash = compute_circuit_hash(
        proof.stark_proof.commitment_scheme_proof.config.log_blowup_factor, preprocessed_commitment,
    );
    assert!(circuit_hash == pinned::circuit_hash(), "not the client circuit");
    let outputs = proof.claim.public_data.output_values.span();
    assert!(outputs.len() == N_OUTPUTS, "output count");
    let mut limbs: Array<u32> = array![];
    for value in outputs {
        let [c0, c1, c2, c3] = QM31Trait::to_fixed_array(*value);
        limbs.append(c0.into());
        limbs.append(c1.into());
        limbs.append(c2.into());
        limbs.append(c3.into());
    }
    let x = limbs.span();
    assert!(*x.at(0) == TAG_0 && *x.at(1) == TAG_1, "statement tag");
    let nf0 = x.slice(38, N_WORDS);
    let nf1 = x.slice(47, N_WORDS);
    assert!(nf0 != nf1, "duplicate nullifier");
    let statement = Statement {
        chain: felt_from_limbs(x.slice(2, N_WORDS)),
        pool: felt_from_limbs(x.slice(11, N_WORDS)),
        token: felt_from_limbs(x.slice(20, N_WORDS)),
        root: x.slice(29, N_WORDS),
        nullifiers: [nf0, nf1],
        commitments: [x.slice(56, N_WORDS), x.slice(74, N_WORDS)],
        deliveries: [felt_from_limbs(x.slice(65, N_WORDS)), felt_from_limbs(x.slice(83, N_WORDS))],
    };
    verify_circuit(:proof, :circuit_hash);
    statement
}

/// `Poseidon('TMR0_BIND_V1', chain, pool, token, root₉, nf₀₉, nf₁₉, cm₀₉, delivery₀, cm₁₉,
/// delivery₁)`: what the pool recomputes from its spend data.
pub fn binding(s: @Statement) -> felt252 {
    let mut b: Array<felt252> = array!['TMR0_BIND_V1', *s.chain, *s.pool, *s.token];
    let [nf0, nf1] = *s.nullifiers;
    let [cm0, cm1] = *s.commitments;
    let [d0, d1] = *s.deliveries;
    for part in array![*s.root, nf0, nf1].span() {
        for w in *part {
            b.append((*w).into());
        }
    }
    for w in cm0 {
        b.append((*w).into());
    }
    b.append(d0);
    for w in cm1 {
        b.append((*w).into());
    }
    b.append(d1);
    poseidon_hash_span(b.span())
}

/// The full check a pool performs on the decoded statement, for standalone execution.
#[executable]
fn main(
    chain: felt252,
    pool: felt252,
    token: felt252,
    root: Span<u32>,
    nullifiers: Span<u32>,
    commitments: Span<u32>,
    deliveries: Span<felt252>,
    proof_data: Span<felt252>,
) -> Array<felt252> {
    let s = verify_payment(proof_data);
    assert!(s.chain == chain && s.pool == pool && s.token == token, "context");
    assert!(s.root == root, "root");
    let [nf0, nf1] = s.nullifiers;
    assert!(nf0 == nullifiers.slice(0, N_WORDS) && nf1 == nullifiers.slice(N_WORDS, N_WORDS), "nullifiers");
    assert!(nullifiers.len() == 2 * N_WORDS && commitments.len() == 2 * N_WORDS, "lengths");
    let [cm0, cm1] = s.commitments;
    assert!(cm0 == commitments.slice(0, N_WORDS) && cm1 == commitments.slice(N_WORDS, N_WORDS), "commitments");
    let [d0, d1] = s.deliveries;
    assert!(deliveries.len() == 2 && d0 == *deliveries.at(0) && d1 == *deliveries.at(1), "deliveries");
    array![chain, pool, token, binding(@s)]
}

#[cfg(test)]
mod tests {
    use super::felt_from_limbs;

    #[test]
    fn limbs_recombine_little_endian() {
        let limbs = array![0x534e5f5, 0x45504f4, 0x4c4941, 0, 0, 0, 0, 0, 0];
        assert!(felt_from_limbs(limbs.span()) == 0x4c4941_45504f4_534e5f5);
    }

    #[test]
    #[should_panic(expected: 'non-canonical felt')]
    fn felt_must_be_canonical() {
        let m = 0xfffffff;
        let limbs = array![m, m, m, m, m, m, m, m, m];
        felt_from_limbs(limbs.span());
    }
}
