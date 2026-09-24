//! Client bridge for the P1 policy settlement (`docs/policy-note-spec.md` §5–6) on the
//! arithmetic-only stwo-circuits route (fork `templar/arithmetic-profile`). Verifies one blinded
//! client proof and decodes its public statement; pins the P1 circuit's hash and statement tag
//! (`pinned.cairo`), which differ from R0's.
//!
//! The 41 outputs carry 164 M31 limbs, four per QM31 in coordinate order: tag (`TMPZ`, `P1V1` or
//! `P1C1`), chain, pool, token (28-bit LE felt limbs), root, nullifier, commitment₀,
//! commitment₁ (nine words each), delivery₀, delivery₁, withdrawal recipient (felt limbs),
//! withdrawal amount (eight 16-bit LE limbs), controller, controller class, handle (felt limbs),
//! policy_id (nine words), deadline, not_before (four 16-bit LE limbs each), outcome index,
//! outcome type, x (eight 16-bit limbs), data (felt limbs), one zero.
//! The account binds the decoded statement with `binding` (felt252 Poseidon, `TMP1_BIND_V1`),
//! which the pool recomputes from its policy-spend data.
use core::poseidon::poseidon_hash_span;
use stwo_circuit_air::{CircuitProof, compute_circuit_hash, verify_circuit};
use stwo_verifier_core::Hash;
use stwo_verifier_core::fields::qm31::QM31Trait;

pub mod pinned;

const N_OUTPUTS: u32 = 41;
const N_WORDS: u32 = 9;
/// Addresses are below 2^251, as the reference statement's `addr` check.
const ADDRESS_BOUND: u256 = 0x800000000000000000000000000000000000000000000000000000000000000;
const LIMB_SHIFT: u256 = 0x10000000;

#[derive(Drop, Serde, PartialEq, Debug)]
pub struct Statement {
    pub chain: felt252,
    pub pool: felt252,
    pub token: felt252,
    pub root: Span<u32>,
    pub nullifier: Span<u32>,
    pub commitments: [Span<u32>; 2],
    pub deliveries: [felt252; 2],
    pub withdrawal_recipient: felt252,
    pub withdrawal_amount: u128,
    pub controller: felt252,
    pub controller_class: felt252,
    pub handle: felt252,
    pub policy_id: Span<u32>,
    pub deadline: u64,
    pub not_before: u64,
    pub index: u32,
    pub kind: u32,
    pub x: u128,
    pub data: felt252,
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

/// `n` 16-bit little-endian limbs as a u128.
fn from_limbs16(limbs: Span<u32>) -> u128 {
    let mut acc: u128 = 0;
    let mut i = limbs.len();
    while i > 0 {
        i -= 1;
        let limb: u128 = (*limbs.at(i)).into();
        assert!(limb < 0x10000, "16-bit limb range");
        acc = acc * 0x10000 + limb;
    }
    acc
}

fn nonzero_digest(d: Span<u32>) -> bool {
    let mut any = false;
    for w in d {
        if *w != 0 {
            any = true;
        }
    }
    any
}

fn address(v: felt252) -> bool {
    let u: u256 = v.into();
    u < ADDRESS_BOUND
}

/// Verifies exactly one encoded client proof and returns the policy statement it proves.
pub fn verify_policy(mut proof_data: Span<felt252>) -> Statement {
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
    let [tag_0, tag_1] = pinned::statement_tag();
    assert!(*x.at(0) == tag_0 && *x.at(1) == tag_1, "statement tag");
    let statement = Statement {
        chain: felt_from_limbs(x.slice(2, N_WORDS)),
        pool: felt_from_limbs(x.slice(11, N_WORDS)),
        token: felt_from_limbs(x.slice(20, N_WORDS)),
        root: x.slice(29, N_WORDS),
        nullifier: x.slice(38, N_WORDS),
        commitments: [x.slice(47, N_WORDS), x.slice(56, N_WORDS)],
        deliveries: [felt_from_limbs(x.slice(65, N_WORDS)), felt_from_limbs(x.slice(74, N_WORDS))],
        withdrawal_recipient: felt_from_limbs(x.slice(83, N_WORDS)),
        withdrawal_amount: from_limbs16(x.slice(92, 8)),
        controller: felt_from_limbs(x.slice(100, N_WORDS)),
        controller_class: felt_from_limbs(x.slice(109, N_WORDS)),
        handle: felt_from_limbs(x.slice(118, N_WORDS)),
        policy_id: x.slice(127, N_WORDS),
        deadline: from_limbs16(x.slice(136, 4)).try_into().unwrap(),
        not_before: from_limbs16(x.slice(140, 4)).try_into().unwrap(),
        index: *x.at(144),
        kind: *x.at(145),
        x: from_limbs16(x.slice(146, 8)),
        data: felt_from_limbs(x.slice(154, N_WORDS)),
    };
    assert!(*x.at(163) == 0, "statement padding");
    // Liveness and defense in depth over what the circuit enforces (spec §6 step 1).
    assert!(statement.chain != 0 && statement.pool != 0 && statement.token != 0, "zero context");
    assert!(address(statement.pool) && address(statement.token), "address range");
    assert!(nonzero_digest(statement.nullifier), "zero nullifier");
    let [c0, c1] = statement.commitments;
    let [d0, d1] = statement.deliveries;
    assert!((d0 != 0) == nonzero_digest(c0) && (d1 != 0) == nonzero_digest(c1), "delivery");
    let recipient: u256 = statement.withdrawal_recipient.into();
    assert!((recipient != 0) == (statement.withdrawal_amount != 0), "withdrawal");
    assert!(recipient < ADDRESS_BOUND && address(statement.controller), "address range");
    assert!(statement.index < 4, "outcome index");
    assert!(statement.kind == 1 || statement.kind == 2, "outcome type");
    assert!((statement.kind == 1) == (statement.x == 0), "split amount");
    assert!(statement.index != 0 || statement.kind == 1, "refund type");
    verify_circuit(:proof, :circuit_hash);
    statement
}

/// `Poseidon('TMP1_BIND_V1', chain, pool, token, root₉, nullifier₉, commitment₀₉, commitment₁₉,
/// delivery₀, delivery₁, w_recipient, w_amount, controller, controller_class, handle,
/// policy_id₉, deadline, not_before, index, type, x, data)`: what the pool recomputes.
pub fn binding(s: @Statement) -> felt252 {
    let mut b: Array<felt252> = array!['TMP1_BIND_V1', *s.chain, *s.pool, *s.token];
    let [cm0, cm1] = *s.commitments;
    for part in array![*s.root, *s.nullifier, cm0, cm1].span() {
        for w in *part {
            b.append((*w).into());
        }
    }
    let [d0, d1] = *s.deliveries;
    b.append(d0);
    b.append(d1);
    b.append(*s.withdrawal_recipient);
    b.append((*s.withdrawal_amount).into());
    b.append(*s.controller);
    b.append(*s.controller_class);
    b.append(*s.handle);
    for w in *s.policy_id {
        b.append((*w).into());
    }
    b.append((*s.deadline).into());
    b.append((*s.not_before).into());
    b.append((*s.index).into());
    b.append((*s.kind).into());
    b.append((*s.x).into());
    b.append(*s.data);
    poseidon_hash_span(b.span())
}

/// The full check a pool performs on the decoded statement, for standalone execution.
#[executable]
fn main(expected: Statement, proof_data: Span<felt252>) -> Array<felt252> {
    let s = verify_policy(proof_data);
    assert!(s == expected, "statement");
    array![s.chain, s.pool, s.token, binding(@s)]
}

#[cfg(test)]
mod tests {
    use super::{felt_from_limbs, from_limbs16};

    #[test]
    fn limbs_recombine_little_endian() {
        let limbs = array![0x534e5f5, 0x45504f4, 0x4c4941, 0, 0, 0, 0, 0, 0];
        assert!(felt_from_limbs(limbs.span()) == 0x4c4941_45504f4_534e5f5);
        assert!(from_limbs16(array![0x1234, 0x5678, 0, 0].span()) == 0x56781234);
    }

    #[test]
    #[should_panic(expected: 'non-canonical felt')]
    fn felt_must_be_canonical() {
        let m = 0xfffffff;
        let limbs = array![m, m, m, m, m, m, m, m, m];
        felt_from_limbs(limbs.span());
    }
}
