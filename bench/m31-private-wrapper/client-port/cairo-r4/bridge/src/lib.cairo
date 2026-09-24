//! Client bridge for the R0 V4 payment (`docs/hidden-asset-spec.md` §4.5) on the arithmetic-only
//! stwo-circuits route (fork `templar/arithmetic-profile`). Verifies one blinded client payment
//! proof and decodes its public statement; pins the client circuit's hash (`pinned.cairo`).
//!
//! The 32 outputs carry 128 M31 limbs, four per QM31 in coordinate order: tag (`TMPZ` and the
//! relation/format word), chain, pool, token_out (28-bit LE felt limbs), root, nullifier₀,
//! nullifier₁, commitment₀, delivery₀ (felt limbs), commitment₁, delivery₁ (felt limbs),
//! withdrawal recipient (felt limbs), withdrawal amount (eight 16-bit LE limbs), execution
//! intent (felt limbs), identity handle (nine words), one zero.
//! Digests are nine M31 words. The spend's asset is private; `token_out` is the asset exactly
//! when value leaves the pool (a withdrawal or an intent) and zero otherwise (the exit rule,
//! enforced here). Both output slots always carry a commitment and a delivery digest. A missing
//! withdrawal has a zero recipient and amount. A nonzero intent authorizes one open-note
//! execution (the pool recomputes it); its budget is the withdrawal, possibly zero. A nonzero
//! identity handle needs an intent.
//! The account binds the decoded statement with `binding` (felt252 Poseidon), which the pool
//! recomputes from its spend data, as the reference ordinary pool does.
use core::poseidon::poseidon_hash_span;
use stwo_circuit_air::{CircuitProof, compute_circuit_hash, verify_circuit};
use stwo_verifier_core::Hash;
use stwo_verifier_core::fields::qm31::QM31Trait;

pub mod pinned;

const N_OUTPUTS: u32 = 32;
const N_WORDS: u32 = 9;
/// Addresses (pool, recipient) and asset identifiers are below 2^251.
const ADDRESS_BOUND: u256 = 0x800000000000000000000000000000000000000000000000000000000000000;
const LIMB_SHIFT: u256 = 0x10000000;

#[derive(Drop, Serde, PartialEq, Debug)]
pub struct Statement {
    pub chain: felt252,
    pub pool: felt252,
    /// The asset on exit, zero for an in-pool transfer.
    pub token_out: felt252,
    pub root: Span<u32>,
    pub nullifiers: [Span<u32>; 2],
    pub commitments: [Span<u32>; 2],
    pub deliveries: [felt252; 2],
    pub withdrawal_recipient: felt252,
    pub withdrawal_amount: u128,
    pub intent: felt252,
    pub identity: Span<u32>,
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

/// Eight 16-bit little-endian limbs as a u128.
fn amount_from_limbs(limbs: Span<u32>) -> u128 {
    assert!(limbs.len() == 8, "amount limb count");
    let mut acc: u128 = 0;
    let mut i = limbs.len();
    while i > 0 {
        i -= 1;
        let limb: u128 = (*limbs.at(i)).into();
        assert!(limb < 0x10000, "amount limb range");
        acc = acc * 0x10000 + limb;
    }
    acc
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
    // The tag names the relation and tree format; the pinned circuit hash already fixes both.
    let [tag_0, tag_1] = pinned::statement_tag();
    assert!(*x.at(0) == tag_0 && *x.at(1) == tag_1, "statement tag");
    let nf0 = x.slice(38, N_WORDS);
    let nf1 = x.slice(47, N_WORDS);
    assert!(nf0 != nf1, "duplicate nullifier");
    let statement = Statement {
        chain: felt_from_limbs(x.slice(2, N_WORDS)),
        pool: felt_from_limbs(x.slice(11, N_WORDS)),
        token_out: felt_from_limbs(x.slice(20, N_WORDS)),
        root: x.slice(29, N_WORDS),
        nullifiers: [nf0, nf1],
        commitments: [x.slice(56, N_WORDS), x.slice(74, N_WORDS)],
        deliveries: [felt_from_limbs(x.slice(65, N_WORDS)), felt_from_limbs(x.slice(83, N_WORDS))],
        withdrawal_recipient: felt_from_limbs(x.slice(92, N_WORDS)),
        withdrawal_amount: amount_from_limbs(x.slice(101, 8)),
        intent: felt_from_limbs(x.slice(109, N_WORDS)),
        identity: x.slice(118, N_WORDS),
    };
    assert!(*x.at(127) == 0, "statement padding");
    // V4 liveness checks (spec §4.5): nonzero context, addresses in range, nonzero nullifiers,
    // commitments and delivery digests, and the exit rule.
    assert!(statement.chain != 0 && statement.pool != 0, "zero context");
    let pool_u: u256 = statement.pool.into();
    let token_u: u256 = statement.token_out.into();
    assert!(pool_u < ADDRESS_BOUND && token_u < ADDRESS_BOUND, "address range");
    let [n0, n1] = statement.nullifiers;
    assert!(nonzero_digest(n0) && nonzero_digest(n1), "zero digest");
    // Both output slots always exist.
    let [c0, c1] = statement.commitments;
    let [d0, d1] = statement.deliveries;
    assert!(nonzero_digest(c0) && nonzero_digest(c1), "zero commitment");
    assert!(d0 != 0 && d1 != 0, "delivery");
    // A withdrawal has both a recipient (an address) and an amount, or neither.
    let recipient: u256 = statement.withdrawal_recipient.into();
    assert!((recipient != 0) == (statement.withdrawal_amount != 0), "withdrawal");
    assert!(recipient < ADDRESS_BOUND, "address range");
    // The exit rule: the asset is published exactly when value leaves the pool. The circuit
    // forces it on any withdrawal or intent; this rejects a voluntary reveal on a transfer.
    let exits = statement.withdrawal_amount != 0 || statement.intent != 0;
    assert!((statement.token_out != 0) == exits, "exit rule");
    // An identity handle only accompanies an intent.
    assert!(!nonzero_digest(statement.identity) || statement.intent != 0, "identity intent");
    verify_circuit(:proof, :circuit_hash);
    statement
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

/// `Poseidon('TMR0_BIND_V4', chain, pool, token_out, root₉, nf₀₉, nf₁₉, cm₀₉, delivery₀, cm₁₉,
/// delivery₁, recipient, amount, intent, identity₉)`: what the pool recomputes from its spend
/// data.
pub fn binding(s: @Statement) -> felt252 {
    let mut b: Array<felt252> = array!['TMR0_BIND_V4', *s.chain, *s.pool, *s.token_out];
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
    b.append(*s.withdrawal_recipient);
    b.append((*s.withdrawal_amount).into());
    b.append(*s.intent);
    for w in *s.identity {
        b.append((*w).into());
    }
    poseidon_hash_span(b.span())
}

/// The full check a pool performs on the decoded statement, for standalone execution.
#[executable]
fn main(
    chain: felt252,
    pool: felt252,
    token_out: felt252,
    root: Span<u32>,
    nullifiers: Span<u32>,
    commitments: Span<u32>,
    deliveries: Span<felt252>,
    withdrawal_recipient: felt252,
    withdrawal_amount: u128,
    intent: felt252,
    identity: Span<u32>,
    proof_data: Span<felt252>,
) -> Array<felt252> {
    let s = verify_payment(proof_data);
    assert!(s.chain == chain && s.pool == pool && s.token_out == token_out, "context");
    assert!(s.root == root, "root");
    let [nf0, nf1] = s.nullifiers;
    assert!(nf0 == nullifiers.slice(0, N_WORDS) && nf1 == nullifiers.slice(N_WORDS, N_WORDS), "nullifiers");
    assert!(nullifiers.len() == 2 * N_WORDS && commitments.len() == 2 * N_WORDS, "lengths");
    let [cm0, cm1] = s.commitments;
    assert!(cm0 == commitments.slice(0, N_WORDS) && cm1 == commitments.slice(N_WORDS, N_WORDS), "commitments");
    let [d0, d1] = s.deliveries;
    assert!(deliveries.len() == 2 && d0 == *deliveries.at(0) && d1 == *deliveries.at(1), "deliveries");
    assert!(
        s.withdrawal_recipient == withdrawal_recipient && s.withdrawal_amount == withdrawal_amount,
        "withdrawal",
    );
    assert!(s.intent == intent && s.identity == identity, "intent or identity");
    array![chain, pool, token_out, binding(@s)]
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
