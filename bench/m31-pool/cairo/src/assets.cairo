//! Asset identifiers and token-standard interfaces for M31 pool V2
//! (`docs/hidden-asset-spec.md` §3, §5). A note's token field holds an asset identifier: an ERC20
//! contract address, or `Poseidon('TEMPLAR_ASSET_V1', standard, contract, id.low, id.high)` for
//! an ERC721 or ERC1155 token id. Identifiers are below 2^251.
use core::poseidon::poseidon_hash_span;
use starknet::ContractAddress;

pub const ERC20: u16 = 20;
pub const ERC721: u16 = 721;
pub const ERC1155: u16 = 1155;

/// 2^251: addresses and asset identifiers are below it.
pub const ADDRESS_BOUND: u256 = 0x800000000000000000000000000000000000000000000000000000000000000;

/// Interface ids of OpenZeppelin Cairo ≥ 0.20 (`openzeppelin_interfaces` 2.2.0).
pub const ISRC5_ID: felt252 = 0x3f918d17e5ee77373b56385708f855659a07f75997f365cf87748628532a055;
pub const ISRC6_ID: felt252 = 0x2ceccef7f994940b3962a6c67e0ba4fcd37df7d131417c604f91e03caecc1cd;
pub const IERC721_ID: felt252 = 0x33eb2f84c309543403fd69f0d0f363781ef06ef6faeb0131ff16ea3175bd943;
pub const IERC721_RECEIVER_ID: felt252 = 0x3a0dff5f70d80458ad14ae37bb182a728e3c8cdda0402a5daa86620bdf910bc;
pub const IERC1155_ID: felt252 = 0x6114a8f75559e1b39fcba08ce02961a1aa082d9256a158dd3e64964e4b1b52;
pub const IERC1155_RECEIVER_ID: felt252 = 0x15e8665b5af20040c3af1670509df02eb916375cdf7d8cbaf7bd553a257515e;

/// A registered ERC721 or ERC1155 asset. `standard` is zero for an unregistered identifier.
#[derive(Copy, Drop, Serde, starknet::Store, PartialEq, Debug)]
pub struct AssetInfo {
    pub standard: u16,
    pub contract: ContractAddress,
    pub id: u256,
}

pub fn asset_id(standard: u16, contract: ContractAddress, id: u256) -> felt252 {
    poseidon_hash_span(array!['TEMPLAR_ASSET_V1', standard.into(), contract.into(), id.low.into(), id.high.into()].span())
}

pub fn below_bound(v: felt252) -> bool {
    let x: u256 = v.into();
    x < ADDRESS_BOUND
}

#[starknet::interface]
pub trait ISRC5<TState> {
    fn supports_interface(self: @TState, interface_id: felt252) -> bool;
}

#[starknet::interface]
pub trait IERC721<TState> {
    fn owner_of(self: @TState, token_id: u256) -> ContractAddress;
    fn transfer_from(ref self: TState, from: ContractAddress, to: ContractAddress, token_id: u256);
}

#[starknet::interface]
pub trait IERC1155<TState> {
    fn balance_of(self: @TState, account: ContractAddress, token_id: u256) -> u256;
    fn safe_transfer_from(
        ref self: TState, from: ContractAddress, to: ContractAddress, token_id: u256, value: u256, data: Span<felt252>,
    );
}

/// The pool's receiver hooks, called by token contracts during a safe transfer to the pool.
#[starknet::interface]
pub trait IAssetReceiver<TState> {
    fn on_erc721_received(
        ref self: TState, operator: ContractAddress, from: ContractAddress, token_id: u256, data: Span<felt252>,
    ) -> felt252;
    fn on_erc1155_received(
        ref self: TState, operator: ContractAddress, from: ContractAddress, token_id: u256, value: u256,
        data: Span<felt252>,
    ) -> felt252;
    fn on_erc1155_batch_received(
        ref self: TState, operator: ContractAddress, from: ContractAddress, token_ids: Span<u256>,
        values: Span<u256>, data: Span<felt252>,
    ) -> felt252;
    fn supports_interface(self: @TState, interface_id: felt252) -> bool;
}
