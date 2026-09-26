//! The R0 V6 statement account's entry points, for the snforge tests and the pool end to end.

/// The statement account's entry points (V6: the proof alone, no salt and no signature).
#[starknet::interface]
pub trait IStatementAccount<T> {
    fn __validate__(self: @T, proof_data: Span<felt252>) -> felt252;
    fn __execute__(ref self: T, proof_data: Span<felt252>);
}
