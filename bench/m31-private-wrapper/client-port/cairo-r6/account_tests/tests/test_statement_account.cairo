//! The R0 V6 statement account on real client proofs (`docs/pool-v3-spec.md` §5.3).
//!
//! Fixtures (`fixtures/`, written by `kat/gen_fixtures.cjs` from real proofs): an ordinary V6
//! partial withdrawal with its expected binding, chain and pool; a V6 proof whose statement the
//! bridge must reject (`valid_until = 0`); and a V5 proof. Each test deploys the statement account
//! and runs `__execute__` as the OS does (caller 0, the proof's chain).
use snforge_std::fs::{FileTrait, read_txt};
use snforge_std::{
    ContractClassTrait, DeclareResultTrait, MessageToL1, MessageToL1SpyAssertionsTrait, MessageToL1SpyTrait, declare,
    spy_messages_to_l1, start_cheat_caller_address, start_cheat_chain_id_global, start_cheat_resource_bounds_global,
    start_cheat_tip_global,
};
use starknet::syscalls::call_contract_syscall;
use starknet::{ContractAddress, ResourcesBounds};
use templar_account_tests::{IStatementAccountDispatcher, IStatementAccountDispatcherTrait};

#[derive(Drop)]
struct Fixture {
    proof: Span<felt252>,
    binding: felt252,
    chain: felt252,
    pool: felt252,
}

/// `constants`: binding, chain, pool.
fn load(name: ByteArray) -> Fixture {
    let proof = read_txt(@FileTrait::new(format!("fixtures/{name}-proof.txt")));
    let c = read_txt(@FileTrait::new(format!("fixtures/{name}-constants.txt"))).span();
    Fixture { proof: proof.span(), binding: *c.at(0), chain: *c.at(1), pool: *c.at(2) }
}

fn addr(x: felt252) -> ContractAddress {
    x.try_into().unwrap()
}

fn statement_class() -> starknet::ClassHash {
    *declare("PaymentVerifierAccount").unwrap().contract_class().class_hash
}

fn deploy_statement() -> IStatementAccountDispatcher {
    let (a, _) = declare("PaymentVerifierAccount").unwrap().contract_class().deploy(@array![]).unwrap();
    IStatementAccountDispatcher { contract_address: a }
}

/// `__execute__` as the OS runs it: caller 0, the proof's chain id.
fn execute(s: IStatementAccountDispatcher, f: @Fixture) {
    start_cheat_chain_id_global(*f.chain);
    start_cheat_caller_address(s.contract_address, addr(0));
    s.__execute__(*f.proof);
}

fn message_count(ref spy: snforge_std::cheatcodes::message_to_l1::MessageToL1Spy) -> u32 {
    let messages: Array<(ContractAddress, MessageToL1)> = spy.get_messages().messages;
    ArrayTrait::len(@messages)
}

/// One V6 message, `[class, 'TMPZR0_PAYMENT_V6', chain, pool, binding]` to address 0, whose
/// binding is starknet.js's `TMR0_BIND_V5` over the proof's public statement.
#[test]
fn ordinary_proof_emits_one_v6_message() {
    let f = load("ordinary");
    let s = deploy_statement();
    let mut spy = spy_messages_to_l1();
    execute(s, @f);
    let payload = array![statement_class().into(), 'TMPZR0_PAYMENT_V6', f.chain, f.pool, f.binding];
    spy.assert_sent(@array![(s.contract_address, MessageToL1 { to_address: 0.try_into().unwrap(), payload })]);
    assert!(message_count(ref spy) == 1);
}

#[test]
#[should_panic(expected: "OS_ONLY")]
fn nonzero_caller() {
    let f = load("ordinary");
    let s = deploy_statement();
    start_cheat_chain_id_global(f.chain);
    start_cheat_caller_address(s.contract_address, addr(0x1234));
    s.__execute__(f.proof);
}

#[test]
#[should_panic(expected: "chain")]
fn other_chain() {
    let f = load("ordinary");
    let s = deploy_statement();
    start_cheat_chain_id_global('SN_MAIN');
    start_cheat_caller_address(s.contract_address, addr(0));
    s.__execute__(f.proof);
}

/// A V5 proof: another client circuit.
#[test]
#[should_panic(expected: "not the client circuit")]
fn v5_proof_is_rejected() {
    let f = load("v5");
    execute(deploy_statement(), @f);
}

/// A real V6 proof of a statement the bridge rejects (`valid_until = 0`).
#[test]
#[should_panic(expected: "valid_until")]
fn forged_statement_is_rejected() {
    let f = load("forge-valid-until-zero");
    execute(deploy_statement(), @f);
}

#[test]
#[should_panic(expected: 'INVALID_PROOF_ENCODING')]
fn empty_proof_is_rejected() {
    let f = load("ordinary");
    let s = deploy_statement();
    start_cheat_chain_id_global(f.chain);
    start_cheat_caller_address(s.contract_address, addr(0));
    s.__execute__(array![].span());
}

/// V5's calldata shape `(proof_data, salt = 0, signature = [])` is not V6's `(proof_data)`: the
/// extra felts fail argument decoding.
#[test]
fn v5_shaped_calldata_is_rejected() {
    let f = load("ordinary");
    let s = deploy_statement();
    start_cheat_chain_id_global(f.chain);
    start_cheat_caller_address(s.contract_address, addr(0));
    let mut calldata: Array<felt252> = array![];
    f.proof.serialize(ref calldata);
    calldata.append(0);
    calldata.append(0);
    let r = call_contract_syscall(s.contract_address, selector!("__execute__"), calldata.span());
    assert!(r.is_err(), "V5-shaped calldata accepted");
}

// ---------------------------------------------------------------- __validate__

fn free_bounds() -> Span<ResourcesBounds> {
    array![
        ResourcesBounds { resource: 'L1_GAS', max_amount: 0, max_price_per_unit: 0 },
        ResourcesBounds { resource: 'L2_GAS', max_amount: 1000000000, max_price_per_unit: 0 },
        ResourcesBounds { resource: 'L1_DATA', max_amount: 0, max_price_per_unit: 0 },
    ]
        .span()
}

#[test]
fn validate_accepts_a_free_transaction() {
    let s = deploy_statement();
    start_cheat_resource_bounds_global(free_bounds());
    start_cheat_tip_global(0);
    assert!(s.__validate__(array![].span()) == 'VALID');
}

#[test]
#[should_panic(expected: "PROVE_ONLY")]
fn validate_rejects_a_tip() {
    let s = deploy_statement();
    start_cheat_resource_bounds_global(free_bounds());
    start_cheat_tip_global(1);
    s.__validate__(array![].span());
}

#[test]
#[should_panic(expected: "PROVE_ONLY")]
fn validate_rejects_a_price() {
    let s = deploy_statement();
    start_cheat_resource_bounds_global(
        array![
            ResourcesBounds { resource: 'L1_GAS', max_amount: 0, max_price_per_unit: 0 },
            ResourcesBounds { resource: 'L2_GAS', max_amount: 1000000000, max_price_per_unit: 1 },
            ResourcesBounds { resource: 'L1_DATA', max_amount: 0, max_price_per_unit: 0 },
        ]
            .span(),
    );
    start_cheat_tip_global(0);
    s.__validate__(array![].span());
}
