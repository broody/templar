//! The R0 V5 statement account on real client proofs (`docs/account-bound-note-spec.md` §5.4).
//!
//! Fixtures (`fixtures/`, written by `kat/gen_fixtures.cjs` from real proofs): a bound partial
//! withdrawal naming account `A`, and an ordinary one. For the bound spend, `constants` also holds
//! the salt, a signature and the spend message hash computed by starknet.js (so `MODE_CHECK`
//! pins the hash the account computes), and the expected binding.
//!
//! Each test deploys the statement account and, at `A`, a mock bound account, then runs
//! `__execute__` as the OS does (caller 0, the proof's chain).
use snforge_std::fs::{FileTrait, read_txt};
use snforge_std::{
    ContractClassTrait, DeclareResultTrait, MessageToL1, MessageToL1SpyAssertionsTrait, MessageToL1SpyTrait, declare,
    spy_messages_to_l1,
    start_cheat_caller_address, start_cheat_chain_id_global, start_cheat_resource_bounds_global, start_cheat_tip_global,
};
use starknet::{ContractAddress, ResourcesBounds};
use templar_account_tests::{
    IStatementAccountDispatcher, IStatementAccountDispatcherTrait, MODE_ANY, MODE_CHECK, MODE_EMIT, MODE_PANIC,
    MODE_REENTER, MODE_ZERO,
};

#[derive(Drop)]
struct Fixture {
    proof: Span<felt252>,
    account: felt252,
    salt: felt252,
    hash: felt252,
    signature_hash: felt252,
    binding: felt252,
    chain: felt252,
    pool: felt252,
    signature: Span<felt252>,
}

/// `constants`: account, salt, hash, signature_hash, binding, chain, pool, then the signature.
fn load(name: ByteArray) -> Fixture {
    let proof = read_txt(@FileTrait::new(format!("fixtures/{name}-proof.txt")));
    let c = read_txt(@FileTrait::new(format!("fixtures/{name}-constants.txt"))).span();
    Fixture {
        proof: proof.span(),
        account: *c.at(0),
        salt: *c.at(1),
        hash: *c.at(2),
        signature_hash: *c.at(3),
        binding: *c.at(4),
        chain: *c.at(5),
        pool: *c.at(6),
        signature: c.slice(7, c.len() - 7),
    }
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

fn deploy_mock(f: @Fixture, mode: felt252, statement: ContractAddress) {
    let calldata = array![mode, *f.hash, *f.signature_hash, statement.into()];
    declare("MockAccount").unwrap().contract_class().deploy_at(@calldata, addr(*f.account)).unwrap();
}

/// `__execute__` as the OS runs it: caller 0, the proof's chain id.
fn execute(s: IStatementAccountDispatcher, f: @Fixture, salt: felt252, signature: Span<felt252>) {
    start_cheat_chain_id_global(*f.chain);
    start_cheat_caller_address(s.contract_address, addr(0));
    s.__execute__(*f.proof, salt, signature);
}

fn bound_with(mode: felt252) -> (IStatementAccountDispatcher, Fixture) {
    let f = load("bound");
    let s = deploy_statement();
    deploy_mock(@f, mode, s.contract_address);
    (s, f)
}

fn message_count(ref spy: snforge_std::cheatcodes::message_to_l1::MessageToL1Spy) -> u32 {
    let messages: Array<(ContractAddress, MessageToL1)> = spy.get_messages().messages;
    ArrayTrait::len(@messages)
}

fn expected_message(s: IStatementAccountDispatcher, f: @Fixture) -> (ContractAddress, MessageToL1) {
    let payload = array![statement_class().into(), 'TMPZR0_PAYMENT_V5', *f.chain, *f.pool, *f.binding];
    (s.contract_address, MessageToL1 { to_address: 0.try_into().unwrap(), payload })
}

// ---------------------------------------------------------------- bound mode

/// The account's `VALID` over the exact starknet.js spend hash authorizes the spend: one message,
/// with the binding the pool recomputes.
#[test]
fn bound_valid_signature_emits_one_message() {
    let (s, f) = bound_with(MODE_CHECK);
    let mut spy = spy_messages_to_l1();
    execute(s, @f, f.salt, f.signature);
    spy.assert_sent(@array![expected_message(s, @f)]);
    assert!(message_count(ref spy) == 1);
}

/// Another salt changes the hash: the account does not sign it.
#[test]
#[should_panic(expected: "SIG_NOT_VALID")]
fn bound_other_salt_is_not_signed() {
    let (s, f) = bound_with(MODE_CHECK);
    execute(s, @f, f.salt + 1, f.signature);
}

#[test]
#[should_panic(expected: "SIG_NOT_VALID")]
fn bound_tampered_signature() {
    let (s, f) = bound_with(MODE_CHECK);
    let mut sig: Array<felt252> = f.signature.into();
    sig.append(0);
    execute(s, @f, f.salt, sig.span());
}

/// A bound spend needs a nonzero salt (AB-P17).
#[test]
#[should_panic(expected: "SALT")]
fn bound_zero_salt() {
    let (s, f) = bound_with(MODE_ANY);
    execute(s, @f, 0, f.signature);
}

#[test]
#[should_panic(expected: "SIG_NOT_VALID")]
fn bound_account_returns_zero() {
    let (s, f) = bound_with(MODE_ZERO);
    execute(s, @f, f.salt, f.signature);
}

/// Argent and Braavos panic on a bad signature; a failed call fails the spend.
#[test]
#[should_panic(expected: "SIG_CALL_FAILED")]
fn bound_account_panics() {
    let (s, f) = bound_with(MODE_PANIC);
    execute(s, @f, f.salt, f.signature);
}

/// Only the exact return `['VALID']` passes.
#[test]
#[should_panic(expected: "SIG_NOT_VALID")]
fn bound_account_returns_two_felts() {
    let f = load("bound");
    let s = deploy_statement();
    declare("MockTwoFelts").unwrap().contract_class().deploy_at(@array![], addr(f.account)).unwrap();
    execute(s, @f, f.salt, f.signature);
}

/// A deployed contract without `is_valid_signature` (AB-IP1): the call returns an error.
#[test]
#[should_panic(expected: "SIG_CALL_FAILED")]
fn bound_account_without_the_entry_point() {
    let f = load("bound");
    let s = deploy_statement();
    declare("MockNoEntryPoint").unwrap().contract_class().deploy_at(@array![], addr(f.account)).unwrap();
    execute(s, @f, f.salt, f.signature);
}

/// No contract at the bound address: rejected before the call. The check is diagnostic (AB-IP1):
/// without it the whole execution aborts, which also leaves no proof.
#[test]
#[should_panic(expected: "ACCOUNT_NOT_DEPLOYED")]
fn bound_account_undeployed() {
    let f = load("bound");
    let s = deploy_statement();
    execute(s, @f, f.salt, f.signature);
}

/// A callee that re-enters the statement account fails the spend. Its inner call carries an empty
/// proof, so the bridge also rejects it; the caller-0 guard itself is `nonzero_caller` (AB-IP3).
#[test]
#[should_panic(expected: "SIG_CALL_FAILED")]
fn bound_account_that_reenters_fails() {
    let (s, f) = bound_with(MODE_REENTER);
    execute(s, @f, f.salt, f.signature);
}

/// A callee that emits a message makes two: the adapter's `MESSAGE_COUNT = 1` rejects the proof
/// (the account itself cannot stop it; spec §5.4).
#[test]
fn bound_account_that_emits_leaves_two_messages() {
    let (s, f) = bound_with(MODE_EMIT);
    let mut spy = spy_messages_to_l1();
    execute(s, @f, f.salt, f.signature);
    assert!(message_count(ref spy) == 2);
}

/// A statement naming the statement account itself is rejected before any call (AB-M11).
#[test]
#[should_panic(expected: "SELF_ACCOUNT")]
fn bound_account_is_the_statement_account() {
    let f = load("bound");
    let (a, _) = declare("PaymentVerifierAccount").unwrap().contract_class().deploy_at(@array![], addr(f.account)).unwrap();
    execute(IStatementAccountDispatcher { contract_address: a }, @f, f.salt, f.signature);
}

#[test]
#[should_panic(expected: "OS_ONLY")]
fn nonzero_caller() {
    let (s, f) = bound_with(MODE_ANY);
    start_cheat_chain_id_global(f.chain);
    start_cheat_caller_address(s.contract_address, addr(0x1234));
    s.__execute__(f.proof, f.salt, f.signature);
}

#[test]
#[should_panic(expected: "chain")]
fn other_chain() {
    let (s, f) = bound_with(MODE_ANY);
    start_cheat_chain_id_global('SN_MAIN');
    start_cheat_caller_address(s.contract_address, addr(0));
    s.__execute__(f.proof, f.salt, f.signature);
}

// ---------------------------------------------------------------- ordinary mode

#[test]
fn ordinary_needs_no_authorization() {
    let f = load("ordinary");
    let s = deploy_statement();
    let mut spy = spy_messages_to_l1();
    execute(s, @f, 0, array![].span());
    spy.assert_sent(@array![expected_message(s, @f)]);
    assert!(message_count(ref spy) == 1);
}

#[test]
#[should_panic(expected: "ORDINARY_AUTH")]
fn ordinary_rejects_a_salt() {
    let f = load("ordinary");
    execute(deploy_statement(), @f, 1, array![].span());
}

#[test]
#[should_panic(expected: "ORDINARY_AUTH")]
fn ordinary_rejects_a_signature() {
    let f = load("ordinary");
    execute(deploy_statement(), @f, 0, array![1, 2].span());
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
    assert!(s.__validate__(array![].span(), 7, array![1].span()) == 'VALID');
}

#[test]
#[should_panic(expected: "PROVE_ONLY")]
fn validate_rejects_a_tip() {
    let s = deploy_statement();
    start_cheat_resource_bounds_global(free_bounds());
    start_cheat_tip_global(1);
    s.__validate__(array![].span(), 0, array![].span());
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
    s.__validate__(array![].span(), 0, array![].span());
}
