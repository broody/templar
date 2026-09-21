//! Spend bundle types, verifier seams, and statement binding — spec §5–§7.
//!
//! Trust posture (ADR-0001): `apply_spend` never sees openings or the inner
//! proof's semantics. Its state writes are authorized by (a) an inner-proof
//! verification over `SpendPublicInputs` and (b) a `statement_binding` that
//! ties the verified public inputs to the exact `server_actions` (§7.3.6).
//!
//! Seams by milestone (single-phase per ADR-0010 — no outer block, no
//! proof-facts migration):
//! - M1: `IVerifier` / `ISigVerifier` are mocks (configurable verdict).
//! - M2: `IVerifier` becomes a real on-chain verifier (Garaga-class Groth16)
//!   for the inner statement.
//! - M3 (mainnet readiness): `ISigVerifier` becomes an on-chain cairo-ec check
//!   (§6.3). The `apply_spend` signature does not change.

use core::poseidon::poseidon_hash_span;
use starknet::ContractAddress;

pub const MAX_INPUT_NOTES: usize = 4;
pub const MAX_OUTPUT_NOTES: usize = 4;
pub const MAX_WITHDRAWALS: usize = 2;
/// Sentinel: ordinary note / no controller authorization (§2).
pub const NO_CONTROLLER: felt252 = 0;
pub const PROTOCOL_VERSION: felt252 = 'TEMPLAR_V2';

// ---------------------------------------------------------------------------
// Public inputs (§7.2)
// ---------------------------------------------------------------------------

#[derive(Copy, Drop, Serde, PartialEq)]
pub struct TokenAmount {
    pub token: ContractAddress,
    pub amount: u256,
}

/// Cairo-side representation of the frozen §7.2 layout (ADR-0014). The
/// on-chain binding (§7.3.6) hashes the PADDED fixed-size arrays with explicit
/// counts, matching the circuit limb-for-limb; zero values are forbidden in
/// real slots (see the zip) so padding zeros can never be confused with data.
/// The Groth16 public-input vector is the scalar subset (see `IVerifier`).
#[derive(Drop, Serde)]
pub struct SpendPublicInputs {
    pub protocol_version: felt252,
    pub chain_id: felt252,
    pub pool_address: ContractAddress,
    pub tree_root: felt252,
    pub input_nullifiers: Span<felt252>,
    pub output_commitments: Span<felt252>,
    pub withdrawals: Span<TokenAmount>,
    pub controller: ContractAddress,
    pub deadline: u64,
    pub transition_commitment: felt252,
    pub statement_binding: felt252,
}

// ---------------------------------------------------------------------------
// Server actions (§5.1) — compiled by the proven client phase, applied here
// ---------------------------------------------------------------------------

/// Invariants enforced in `pool.cairo`:
/// - `NullifierWrite[i]` must equal `input_nullifiers[i]` in order (1:1 zip —
///   load-bearing: without it, an unproven extra write could DoS any note).
/// - `LeafInsert[i].commitment` must equal `output_commitments[i]` in order;
///   `note_id` is unproven discovery metadata (§8).
/// - `Withdrawal[i]` (token, amount) must equal the public-input entries;
///   `to_addr` is applied on-chain only (§7.2).
/// - `ControllerApply` is optional but at most once, and must match
///   `controller`/`transition_commitment` (§6).
/// Deposits are not a bundle action (ADR-0011): they enter through the
/// proofless `deposit` entry point, where the caller is always the depositor.
#[derive(Copy, Drop, Serde, PartialEq)]
pub enum ServerAction {
    NullifierWrite: felt252,
    LeafInsert: (felt252, felt252), // (commitment, note_id)
    Withdrawal: (ContractAddress, u256, ContractAddress), // (token, amount, to_addr)
    ControllerApply: (ContractAddress, felt252, u64, felt252, felt252), // (controller, transition_commitment, deadline, sig_r, sig_s)
}

// ---------------------------------------------------------------------------
// Statement binding (§7.3.6) — frozen flattening, M2 must agree byte-for-byte
// ---------------------------------------------------------------------------

/// `actions_hash = Poseidon(Serde(ServerAction)…)`. Enum variants serialize
/// with their variant index first (Cairo Serde) — deterministic.
pub fn compute_actions_hash(actions: @Span<ServerAction>) -> felt252 {
    let mut data = array![];
    let mut i: usize = 0;
    while i < actions.len() {
        Serde::serialize(actions.at(i), ref data);
        i += 1;
    }
    poseidon_hash_span(data.span())
}

/// `statement_binding = H(TX_BIND_TAG, §7.2 fields, H(server_actions))` —
/// ADR-0014 padded encoding, mirrored by the circuit limb-for-limb:
///
/// ```text
/// TX_BIND_TAG, protocol_version, chain_id, pool_address, tree_root,
/// n_in, input_nullifiers[0..4](zero-padded),
/// n_out, output_commitments[0..4](zero-padded),
/// n_wd, (withdrawal.token, withdrawal.low, withdrawal.high)[0..2](zero-padded),
/// controller, deadline, transition_commitment, actions_hash
/// ```
pub fn compute_statement_binding(pi: @SpendPublicInputs, actions_hash: felt252) -> felt252 {
    let mut data = array![
        pool::hashes::tags::TX_BIND_TAG,
        *pi.protocol_version,
        *pi.chain_id,
    ];
    data.append((*pi.pool_address).into());
    data.append(*pi.tree_root);
    data.append(pi.input_nullifiers.len().into());
    let mut i: usize = 0;
    while i < MAX_INPUT_NOTES {
        if i < pi.input_nullifiers.len() {
            data.append(*pi.input_nullifiers.at(i));
        } else {
            data.append(0);
        }
        i += 1;
    }
    data.append(pi.output_commitments.len().into());
    i = 0;
    while i < MAX_OUTPUT_NOTES {
        if i < pi.output_commitments.len() {
            data.append(*pi.output_commitments.at(i));
        } else {
            data.append(0);
        }
        i += 1;
    }
    data.append(pi.withdrawals.len().into());
    i = 0;
    while i < MAX_WITHDRAWALS {
        if i < pi.withdrawals.len() {
            let w = *pi.withdrawals.at(i);
            data.append(w.token.into());
            data.append(w.amount.low.into());
            data.append(w.amount.high.into());
        } else {
            data.append(0);
            data.append(0);
            data.append(0);
        }
        i += 1;
    }
    data.append((*pi.controller).into());
    data.append((*pi.deadline).into());
    data.append(*pi.transition_commitment);
    data.append(actions_hash);
    poseidon_hash_span(data.span())
}

// ---------------------------------------------------------------------------
// Seams + minimal ERC20 face
// ---------------------------------------------------------------------------

/// Inner-proof verification seam. `public_inputs` is the fixed 8-scalar
/// Groth16 public-input vector (ADR-0014): `[protocol_version, chain_id,
/// pool_address, tree_root, controller, deadline, transition_commitment,
/// statement_binding]`. The array fields of `SpendPublicInputs` enter the
/// proof via `statement_binding`, which the pool recomputes from calldata.
/// M1: mock. M2: real on-chain verifier (§5, ADR-0010).
#[starknet::interface]
pub trait IVerifier<TState> {
    fn verify(
        self: @TState, proof: Span<felt252>, public_inputs: Span<felt252>,
    ) -> bool;
}

/// Controller signature seam (§6.3). The signature is over
/// `transition_commitment`; the pool checks deadline and field matching, the
/// verifier only the cryptographic validity. M1: mock. M3: on-chain cairo-ec.
#[starknet::interface]
pub trait ISigVerifier<TState> {
    fn verify_transition(
        self: @TState,
        controller: ContractAddress,
        transition_commitment: felt252,
        sig_r: felt252,
        sig_s: felt252,
    ) -> bool;
}

/// Minimal token face for deposit (transferFrom) and withdrawal (transfer).
#[starknet::interface]
pub trait IERC20<TState> {
    fn approve(ref self: TState, spender: ContractAddress, amount: u256) -> bool;
    fn transfer(ref self: TState, recipient: ContractAddress, amount: u256) -> bool;
    fn transfer_from(
        ref self: TState, sender: ContractAddress, recipient: ContractAddress, amount: u256,
    ) -> bool;
}
