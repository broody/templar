//! Client bridge for the arithmetic-only stwo-circuits route (fork `templar/arithmetic-profile`).
//!
//! Verifies one blinded client membership proof whose circuit uses only the `eq` and `qm31_ops`
//! components. The vendored `circuit_air` skips the absent components and rejects a nonzero
//! claimed sum for them; this bridge pins the circuit hash (`pinned.cairo`, generated from the
//! trusted build manifest), which commits the profile through the absent components' log size 0.
//!
//! There is no statement hash. The eight outputs carry 32 M31 limbs, four per QM31 in coordinate
//! order: limbs 0..2 the tag `TMPZ` `SA01`, 2..11 the chain id and 11..20 the pool address as
//! 28-bit little-endian limbs, 20..29 the membership root, 29..32 zero.
use stwo_circuit_air::{CircuitProof, compute_circuit_hash, verify_circuit};
use stwo_verifier_core::Hash;
use stwo_verifier_core::fields::qm31::QM31Trait;

pub mod pinned;

pub const N_ROOT: u32 = 9;
const N_OUTPUTS: u32 = 8;
const N_FELT_LIMBS: u32 = 9;
const TAG_0: u32 = 0x544d505a;
const TAG_1: u32 = 0x53413031;
const LIMB_SHIFT: u256 = 0x10000000;

#[derive(Drop, Serde, PartialEq, Debug)]
pub struct Statement {
    pub chain: felt252,
    pub pool: felt252,
    pub root: Array<u32>,
}

/// Nine 28-bit little-endian limbs as a canonical felt252 (value below the field prime).
fn felt_from_limbs(limbs: Span<u32>) -> felt252 {
    assert!(limbs.len() == N_FELT_LIMBS, "limb count");
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

/// Verifies exactly one encoded client proof and returns the statement it proves.
pub fn verify_membership(mut proof_data: Span<felt252>) -> Statement {
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
    let limbs = limbs.span();
    assert!(*limbs.at(0) == TAG_0 && *limbs.at(1) == TAG_1, "statement tag");
    assert!(*limbs.at(29) == 0 && *limbs.at(30) == 0 && *limbs.at(31) == 0, "statement padding");
    let chain = felt_from_limbs(limbs.slice(2, N_FELT_LIMBS));
    let pool = felt_from_limbs(limbs.slice(11, N_FELT_LIMBS));
    let mut root = array![];
    for r in limbs.slice(20, N_ROOT) {
        root.append(*r);
    }
    verify_circuit(:proof, :circuit_hash);
    Statement { chain, pool, root }
}

/// The full check a pool performs, for standalone execution.
#[executable]
fn main(chain: felt252, pool: felt252, root: Span<u32>, proof_data: Span<felt252>) -> Array<felt252> {
    let statement = verify_membership(proof_data);
    assert!(statement.chain == chain, "chain");
    assert!(statement.pool == pool, "pool");
    assert!(statement.root.span() == root, "root");
    let mut out = array![chain, pool];
    for r in root {
        out.append((*r).into());
    }
    out
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
    #[should_panic(expected: "limb range")]
    fn limb_range_is_checked() {
        let limbs = array![0x10000000, 0, 0, 0, 0, 0, 0, 0, 0];
        felt_from_limbs(limbs.span());
    }

    #[test]
    #[should_panic(expected: 'non-canonical felt')]
    fn felt_must_be_canonical() {
        let m = 0xfffffff;
        let limbs = array![m, m, m, m, m, m, m, m, m];
        felt_from_limbs(limbs.span());
    }
}
