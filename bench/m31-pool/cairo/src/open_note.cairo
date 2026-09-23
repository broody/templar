//! Open notes on the compact path (ADR-0023, renamed from return notes): transaction-local
//! destinations filled by one external call, ABI-compatible with upstream adapters.
//!
//! An R0 V3 spend authorizes one execution through its `intent`: the Poseidon felt below, over
//! the adapter, the call, the budget (the spend's withdrawal) and the ordered destinations. The
//! pool recomputes it, pays the budget, calls the adapter, matches the returned
//! `OpenNoteDeposit`s to the destinations, pulls the proceeds and appends each funded note's
//! commitment, computed on chain from the actual amount (as `deposit` does). Two kinds:
//! - `INVOKE`: `privacy_invoke(calldata)`, as upstream's Ekubo and Vesu anonymizers;
//! - `COMPUTE`: `privacy_invoke_with_computation([identity_commitment] ++ calldata)`, as
//!   upstream's shadow-account anonymizer. The commitment is `Poseidon(partial, nonce)` (upstream's
//!   `commitment_from_partial`), with `partial` derived from the proven identity handle, so only
//!   the handle's owner can address their shadow accounts.
use core::hash::HashStateTrait;
use core::poseidon::{PoseidonTrait, poseidon_hash_span};
use starknet::ContractAddress;
use crate::spend::{Spend, delivery_digest};

pub const INVOKE: u8 = 0;
pub const COMPUTE: u8 = 1;
pub const MAX_DESTINATIONS: u32 = 2;
pub const MAX_CALLDATA: u32 = 64;
/// Private outputs and funded open notes together, per transaction.
pub const MAX_NOTES: u32 = 4;

/// One destination: a note of `token` for the owner committed by `inner` (nine M31 words, as a
/// deposit's `inner`), funded with at least `minimum`; `ciphertext` is its delivery payload.
#[derive(Copy, Drop, Serde)]
pub struct OpenDestination {
    pub note_id: felt252,
    pub token: ContractAddress,
    pub minimum: u128,
    pub inner: Span<felt252>,
    pub ciphertext: Span<felt252>,
}

#[derive(Drop, Serde)]
pub struct ExecutionIntent {
    pub kind: u8,
    pub adapter: ContractAddress,
    /// The shadow-account nonce (`COMPUTE`); zero for `INVOKE`.
    pub nonce: felt252,
    /// Last block number at which the execution may settle.
    pub expiry: u64,
    pub calldata: Span<felt252>,
    pub destinations: Span<OpenDestination>,
}

/// Identical wire layout to upstream `privacy::objects::OpenNoteDeposit`.
#[derive(Copy, Drop, Serde)]
pub struct OpenNoteDeposit {
    pub note_id: felt252,
    pub token: ContractAddress,
    pub amount: u128,
}

pub fn selector_of(kind: u8) -> felt252 {
    if kind == INVOKE {
        selector!("privacy_invoke")
    } else {
        assert(kind == COMPUTE, 'EXECUTION_KIND');
        selector!("privacy_invoke_with_computation")
    }
}

/// `Poseidon('OPEN_EXEC_V1', chain, pool, token, kind, adapter, nonce, budget recipient, budget,
/// expiry, selector, |calldata|, calldata…, |destinations|, (note_id, token, minimum, inner₉,
/// delivery digest)…)`.
pub fn hash_intent(spend: @Spend, intent: @ExecutionIntent) -> felt252 {
    assert(intent.calldata.len() <= MAX_CALLDATA, 'CALLDATA_LIMIT');
    let n = intent.destinations.len();
    assert(n > 0 && n <= MAX_DESTINATIONS, 'OPEN_NOTE_COUNT');
    let w = *spend.withdrawal;
    let mut data = array![
        'OPEN_EXEC_V1', *spend.chain, (*spend.pool).into(), (*spend.token).into(), (*intent.kind).into(),
        (*intent.adapter).into(), *intent.nonce, w.recipient.into(), w.amount.into(), (*intent.expiry).into(),
        selector_of(*intent.kind), intent.calldata.len().into(),
    ];
    data.append_span(*intent.calldata);
    data.append(n.into());
    for i in 0..n {
        let d = *intent.destinations.at(i);
        assert(d.inner.len() == 9, 'OPEN_NOTE_INNER');
        for j in 0..i {
            assert((*intent.destinations.at(j)).note_id != d.note_id, 'DUPLICATE_NOTE_ID');
        }
        data.append(d.note_id);
        data.append(d.token.into());
        data.append(d.minimum.into());
        data.append_span(d.inner);
        data.append(delivery_digest(d.ciphertext));
    }
    poseidon_hash_span(data.span())
}

/// The upstream-style partial commitment of a proven identity handle (nine M31 words).
pub fn partial_commitment(identity: Span<felt252>) -> felt252 {
    let mut data = array!['TEMPLAR_IDENTITY_V1'];
    data.append_span(identity);
    poseidon_hash_span(data.span())
}

/// Upstream's `commitment_from_partial`: `Poseidon(partial, nonce)`.
pub fn identity_commitment(partial: felt252, nonce: felt252) -> felt252 {
    PoseidonTrait::new().update(partial).update(nonce).finalize()
}
