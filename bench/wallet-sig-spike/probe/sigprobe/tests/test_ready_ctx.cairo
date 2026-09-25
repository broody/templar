//! Diagnostic: why the real Ready (Argent 0.5.0) account's is_valid_signature fails inside a
//! transaction whose account is SigProbe (node simulation), while a direct call and the virtual OS
//! accept. Uses the user's real Ready signature over the spike spend message (sign-live results).
use snforge_std::{
    ContractClassTrait, DeclareResultTrait, declare, start_cheat_account_contract_address_global,
    start_cheat_caller_address, start_cheat_nonce_global, start_cheat_resource_bounds_global,
    start_cheat_transaction_version_global, stop_cheat_account_contract_address_global,
};
use starknet::ContractAddress;

#[starknet::interface]
trait IValid<T> {
    fn is_valid_signature(self: @T, hash: felt252, signature: Array<felt252>) -> felt252;
}

const READY: felt252 = 0x054f2b25070d70d49f1c1f7c10ef2639889fdac15894d3fba1a03caf5603eca3;
const PROBE: felt252 = 0x056c0198ad608cd65c9ac150b3563f68825cf073c84d359fc4ec7ff835eeec31;
const BRAAVOS: felt252 = 0x0665f820f6fda2b1a864ae5814e568f26fbc259c43c428643b64172c2bef58db;
const HASH: felt252 = 0x4d29dd987153f7c0163a924857f024e3f4afe971cc4ce2296fa0d61d1358667;
const R: felt252 = 0x4d6b980b49e9901e103453375a09955394c49ab7aa9316c031dd5c87ebbd091;
const S: felt252 = 0xa2d040f8f06fe78bdf5e0ec3981e8556a2a7c39281c85c134a30329477f31;

fn addr(x: felt252) -> ContractAddress {
    x.try_into().unwrap()
}

#[feature("safe_dispatcher")]
fn ivs(label: ByteArray) {
    let d = IValidSafeDispatcher { contract_address: addr(READY) };
    match d.is_valid_signature(HASH, array![R, S]) {
        Result::Ok(v) => println!("{label}: ok {v}"),
        Result::Err(e) => println!("{label}: panic {e:?}"),
    }
}

#[test]
#[fork("SEPOLIA")]
fn ready_ivs_contexts() {
    ivs("no tx context");
    start_cheat_transaction_version_global(3);
    ivs("tx v3, account 0");
    start_cheat_account_contract_address_global(addr(BRAAVOS));
    ivs("tx v3, account Braavos");
    start_cheat_account_contract_address_global(addr(PROBE));
    ivs("tx v3, account SigProbe");
    start_cheat_account_contract_address_global(addr(READY));
    ivs("tx v3, account Ready itself");
    stop_cheat_account_contract_address_global();
}

#[starknet::interface]
trait IProbe<T> {
    fn __execute__(ref self: T, target: ContractAddress, hash: felt252, signature: Span<felt252>);
}

/// The node-simulation shape: SigProbe is the transaction's account (zero prices, 1e9 L2 gas,
/// version 3, nonce 0) and __execute__ runs with caller 0 against the real Ready account.
#[test]
#[fork("SEPOLIA")]
#[feature("safe_dispatcher")]
fn probe_as_tx_account_against_ready() {
    let (probe, _) = declare("SigProbe").unwrap().contract_class().deploy(@array![]).unwrap();
    start_cheat_transaction_version_global(3);
    start_cheat_nonce_global(0);
    start_cheat_account_contract_address_global(probe);
    start_cheat_resource_bounds_global(
        array![
            starknet::ResourcesBounds { resource: 'L1_GAS', max_amount: 0, max_price_per_unit: 0 },
            starknet::ResourcesBounds { resource: 'L2_GAS', max_amount: 1000000000, max_price_per_unit: 0 },
            starknet::ResourcesBounds { resource: 'L1_DATA', max_amount: 0, max_price_per_unit: 0 },
        ]
            .span(),
    );
    start_cheat_caller_address(probe, addr(0));
    let d = IProbeSafeDispatcher { contract_address: probe };
    match d.__execute__(addr(READY), HASH, array![R, S].span()) {
        Result::Ok(_) => println!("probe as tx account -> Ready: ok"),
        Result::Err(e) => println!("probe as tx account -> Ready: panic {e:?}"),
    }
    ivs("direct, same cheated context");
}
