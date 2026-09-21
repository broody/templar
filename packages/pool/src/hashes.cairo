//! TemplarPool v2 derivation family — normative implementation of
//! `docs/pool-v2-spec.md` §3.1 (revised 2026-09-20 by ADR-0011/0012).
//!
//! All hashes are Starknet Poseidon over felt252 with domain-separation tags as
//! the first preimage element. The inner-statement circuit (M2) must reproduce
//! these derivations byte-for-byte over the BN254 field via non-native
//! arithmetic — this module and its reference vectors are the contract/circuit
//! agreement target.
//!
//! Conventions:
//! - `ContractAddress` values enter preimages via their felt252 representation.
//! - `u128` values enter preimages via `Into<felt252>`.
//! - `NO_CONTROLLER` (`0`) and zero `policy_commitment` denote ordinary notes.
//! - Functions are pure: non-zero assumptions are enforced at the action layer,
//!   not here (matches upstream `hashes.cairo`).

use core::poseidon::poseidon_hash_span;
use starknet::ContractAddress;

/// Domain-separation tags. Literal values are pinned in
/// `docs/pool-v2-spec.md` §3.1; changing any of them changes every derivation
/// and requires a spec revision. The note family is V3 (ADR-0011/0012: two-part
/// leaf, recipient-authored notes — `channel_key` removed); the binding family
/// stays V2.
pub mod tags {
    pub const NOTE_SECRET_TAG: felt252 = 'NOTE_SECRET_TAG:V3';
    pub const NOTE_INNER_TAG: felt252 = 'NOTE_INNER_TAG:V3';
    pub const NOTE_ID_TAG: felt252 = 'NOTE_ID_TAG:V3';
    pub const COMMITMENT_TAG: felt252 = 'COMMITMENT_TAG:V3';
    pub const NULLIFIER_TAG: felt252 = 'NULLIFIER_TAG:V3';
    pub const TRANSITION_COMMIT_TAG: felt252 = 'TRANSITION_COMMIT_TAG:V2';
    pub const TX_BIND_TAG: felt252 = 'TX_BIND_TAG:V2';
}

use tags::*;

/// Hashes a span of felt252 values.
pub fn hash(data: Span<felt252>) -> felt252 {
    poseidon_hash_span(data)
}

/// `note_secret = H(NOTE_SECRET_TAG, salt, owner_private_key)`
///
/// The single secret of a note, derived recipient-side (ADR-0012): the
/// nullifier and (via `inner`) the commitment descend from it. Only the owner
/// can compute it — a sender who paid an invoice knows `inner` and `note_id`
/// but can never derive `note_secret`, so they can never spend a note they
/// funded (ADR-0009 receiver-only property).
pub fn compute_note_secret(salt: u128, owner_private_key: felt252) -> felt252 {
    hash([NOTE_SECRET_TAG, salt.into(), owner_private_key].span())
}

/// `inner = H(NOTE_INNER_TAG, note_secret)`
///
/// The hiding inner commitment (ADR-0011) — the only secret-bearing input of
/// the leaf. Safe to hand to a sender (invoice) or to the contract (deposit):
/// it commits to `note_secret` without revealing it.
pub fn compute_inner(note_secret: felt252) -> felt252 {
    hash([NOTE_INNER_TAG, note_secret].span())
}

/// `note_id = H(NOTE_ID_TAG, note_secret)`
///
/// Recipient-authored discovery/matching key (ADR-0012), emitted at creation.
/// Opaque to observers. Never revealed at spend.
pub fn compute_note_id(note_secret: felt252) -> felt252 {
    hash([NOTE_ID_TAG, note_secret].span())
}

/// `commitment = H(COMMITMENT_TAG, token, amount, controller,
///                 policy_commitment, inner)`
///
/// The tree leaf (two-part, ADR-0011). Every field except `inner` is public at
/// creation, so the contract computes it on-chain for `deposit` and the SDK
/// computes it for spend outputs. `controller = 0` and `policy_commitment = 0`
/// denote an ordinary note; non-zero values make the authorization requirement
/// immutable on-chain (ADR-0009).
pub fn compute_note_commitment(
    token: ContractAddress,
    amount: u128,
    controller: ContractAddress,
    policy_commitment: felt252,
    inner: felt252,
) -> felt252 {
    hash(
        [
            COMMITMENT_TAG, token.into(), amount.into(), controller.into(), policy_commitment,
            inner,
        ]
            .span(),
    )
}

/// `nullifier = H(NULLIFIER_TAG, note_secret)`
///
/// Receiver-only spend capability. Unique per note (fresh `salt` ⇒ fresh
/// `note_secret`). Emitted at spend; unlinkable to the creation event.
pub fn compute_nullifier(note_secret: felt252) -> felt252 {
    hash([NULLIFIER_TAG, note_secret].span())
}
