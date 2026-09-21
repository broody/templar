//! Transaction-local funding destinations; ABI-compatible with upstream adapters.
use core::poseidon::poseidon_hash_span;
use starknet::ContractAddress;
use pool::spend::{Spend, PROTOCOL_VERSION, delivery_digest};

#[derive(Drop, Serde)]
pub struct ReturnNote {
    pub note_id: felt252,
    pub token: ContractAddress,
    pub minimum: u128,
    pub inner: felt252,
    pub ciphertext: Span<felt252>,
}

#[derive(Drop, Serde)]
pub struct ExecutionIntent {
    pub adapter: ContractAddress,
    pub amount: u128,
    pub expiry: u64,
    pub calldata: Span<felt252>,
    pub notes: Span<ReturnNote>,
}

/// Identical wire layout to upstream privacy::objects::OpenNoteDeposit.
#[derive(Drop, Serde)]
pub struct OpenNoteDeposit {
    pub note_id: felt252,
    pub token: ContractAddress,
    pub amount: u128,
}

pub fn hash_intent(spend: @Spend, intent: @ExecutionIntent) -> felt252 {
    assert(intent.calldata.len() <= 64, 'CALLDATA_LIMIT');
    assert(intent.notes.len() > 0 && intent.notes.len() <= 4, 'RETURN_NOTE_COUNT');
    let mut data = array!['RTN_EXEC_V1', PROTOCOL_VERSION, *spend.chain,
        (*spend.pool).into(), (*spend.token).into(), (*intent.adapter).into(),
        (*intent.amount).into(), (*intent.expiry).into(), selector!("privacy_invoke"),
        intent.calldata.len().into()];
    for word in *intent.calldata { data.append(*word); };
    data.append(intent.notes.len().into());
    for note in *intent.notes {
        data.append(*note.note_id); data.append((*note.token).into());
        data.append((*note.minimum).into()); data.append(*note.inner);
        data.append(delivery_digest(*note.ciphertext));
    };
    poseidon_hash_span(data.span())
}

pub fn return_digest(ciphertext: Span<felt252>, amount: u128) -> felt252 {
    assert(amount != 0, 'RETURN_ZERO');
    poseidon_hash_span(array!['RTN_RETURN_V1', amount.into(), delivery_digest(ciphertext)].span())
}

#[starknet::interface]
pub trait IBalance<TState> {
    fn balance_of(self: @TState, account: ContractAddress) -> u256;
}
