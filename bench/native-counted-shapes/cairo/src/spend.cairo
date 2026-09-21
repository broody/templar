//! Isolated controlled push transport; distinct protocol and fresh pool.
use core::poseidon::poseidon_hash_span;
use starknet::ContractAddress;

pub const PROTOCOL_VERSION: felt252 = 'TEMPLAR_SHAPES_DYN1';

#[derive(Drop, Serde)]
pub struct Output {
    pub commitment: felt252,
    pub ciphertext: Span<felt252>,
}

#[derive(Copy, Drop, Serde)]
pub struct Withdrawal {
    pub recipient: ContractAddress,
    pub amount: u128,
}

#[derive(Drop, Serde)]
pub struct Spend {
    pub version: felt252,
    pub chain: felt252,
    pub pool: ContractAddress,
    pub root: felt252,
    pub token: ContractAddress,
    pub binding: felt252,
    pub controller: ContractAddress,
    pub deadline: u64,
    pub nonce: felt252,
    pub transition: felt252,
    pub sig_r: felt252,
    pub sig_s: felt252,
    pub nullifiers: Span<felt252>,
    pub outputs: Span<Output>,
    pub withdrawals: Span<Withdrawal>,
}

/// Canonical 304 bytes = nine 31-byte big-endian words + one 25-byte word.
/// This exact encoding matches protocol.ciphertext_hash; no modular reduction.
pub fn delivery_digest(ciphertext: Span<felt252>) -> felt252 {
    assert(ciphertext.len() == 10, 'PAYLOAD_LENGTH');
    let mut data = array!['CTRL_DELIVERY_V1', 304];
    for i in 0..10_usize {
        let word = *ciphertext.at(i);
        let integer: u256 = word.into();
        let limit: u256 = if i == 9 { 0x100000000000000000000000000000000000000000000000000 }
                          else { 0x100000000000000000000000000000000000000000000000000000000000000 };
        assert(integer < limit, 'PAYLOAD_WORD');
        data.append(word);
    };
    poseidon_hash_span(data.span())
}

pub fn compute_binding(s: @Spend) -> felt252 {
    assert(s.nullifiers.len() > 0 && s.nullifiers.len() <= 64, 'INPUT_COUNT');
    assert(s.outputs.len() <= 64 && s.withdrawals.len() <= 32, 'OUTPUT_COUNT');
    assert(s.outputs.len() + s.withdrawals.len() > 0, 'EMPTY_OUTPUT');
    let mut data = array!['CTRL_BIND_V1', *s.version, *s.chain, (*s.pool).into(), *s.root,
        (*s.token).into(), (*s.controller).into(), (*s.deadline).into(), *s.nonce, *s.transition, s.nullifiers.len().into()];
    for nf in *s.nullifiers { data.append(*nf); }; data.append(s.outputs.len().into());
    for output in *s.outputs { data.append(*output.commitment); data.append(delivery_digest(*output.ciphertext)); };
    data.append(s.withdrawals.len().into());
    for withdrawal in *s.withdrawals { data.append((*withdrawal.recipient).into()); data.append((*withdrawal.amount).into()); };
    poseidon_hash_span(data.span())
}

#[starknet::interface]
pub trait IVerifier<TState> {
    fn verify(self: @TState, proof: Span<felt252>, public_inputs: Span<felt252>) -> bool;
}

#[starknet::interface]
pub trait IERC20<TState> {
    fn approve(ref self: TState, spender: ContractAddress, amount: u256) -> bool;
    fn transfer(ref self: TState, recipient: ContractAddress, amount: u256) -> bool;
    fn transfer_from(ref self: TState, sender: ContractAddress, recipient: ContractAddress, amount: u256) -> bool;
}

/// Exact off-chain controller authorization, recomputed from the private witness.
/// Leg arrays have ni*(nf,amount,policy), no*(cm,amount,policy,delivery), nw*(recipient,amount).
pub fn compute_transition(chain: felt252, pool: felt252, root: felt252, token: felt252,
    controller: felt252, deadline: felt252, nonce: felt252,
    ni: felt252, no: felt252, nw: felt252, inputs: Span<felt252>, outputs: Span<felt252>,
    withdrawals: Span<felt252>) -> felt252 {
    assert(inputs.len().into() == ni*3 && outputs.len().into() == no*4 && withdrawals.len().into() == nw*2, 'TRANSITION_SHAPE');
    let mut data = array!['CTRL_TRANSITION_V1', PROTOCOL_VERSION, chain, pool, root, token,
                         controller, deadline, nonce, ni];
    for x in inputs { data.append(*x); };
    data.append(no);
    for x in outputs { data.append(*x); };
    data.append(nw);
    for x in withdrawals { data.append(*x); };
    poseidon_hash_span(data.span())
}

#[starknet::interface]
pub trait IController<TState> {
    fn verify_transition(self: @TState, transition: felt252, sig_r: felt252, sig_s: felt252) -> bool;
}
