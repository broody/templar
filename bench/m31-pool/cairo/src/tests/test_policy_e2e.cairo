//! Real policy-note settlements (`policy_e2e.py`): an executor's P1 proof of an escrow release
//! and a seed-recovered P1 refund after the deadline, each through bridge, virtual OS and PROOF2,
//! settled here through the P1 PROOF2 adapter and `apply_policy_spend` at the committed
//! addresses. The pool's tree must end at the root the beneficiary's wallet computed.
use core::testing::get_available_gas;
use snforge_std::{
    ContractClassTrait, DeclareResultTrait, declare, start_cheat_block_number, start_cheat_caller_address,
    start_cheat_chain_id, start_cheat_proof_facts, stop_cheat_caller_address, test_address,
};
use starknet::syscalls::get_class_hash_at_syscall;
use starknet::{ContractAddress, SyscallResultTrait};
use m31_pool::policy::PolicySpend;
use m31_pool::policy_escrow::{IPolicyEscrowDispatcher, IPolicyEscrowDispatcherTrait};
use m31_pool::pool::{IM31PoolDispatcher, IM31PoolDispatcherTrait};
use m31_pool::spend::{IERC20Dispatcher, IERC20DispatcherTrait};
use m31_pool::tree::{IM31TreeDispatcher, IM31TreeDispatcherTrait};
use super::policy_vectors::*;

fn addr(x: felt252) -> ContractAddress {
    x.try_into().unwrap()
}
fn deploy_at(name: ByteArray, data: Array<felt252>, at: felt252) {
    declare(name).unwrap_syscall().contract_class().deploy_at(@data, addr(at)).unwrap_syscall();
}
fn decode(felts: Array<felt252>) -> PolicySpend {
    let mut f = felts.span();
    Serde::deserialize(ref f).unwrap()
}

/// Pool, token, escrow and P1 adapter at the committed addresses; the depositor's two policy
/// notes deposited; chain and block set for the proofs.
fn setup() -> IM31PoolDispatcher {
    let me: felt252 = test_address().into();
    deploy_at("E2EToken", array![me, 1000000, 0], TOKEN);
    deploy_at("Proof2Adapter", array![POOL, STATEMENT, STATEMENT_CLASS, OS_PROGRAM, 4096, 'TMPZP1_POLICY_V1'], P1_ADAPTER);
    // The R0 verifier is unused here.
    deploy_at("M31Pool", array![me, 0x1, 1, 0], POOL);
    deploy_at("PolicyEscrow", array![POOL], ESCROW);
    let class: felt252 = get_class_hash_at_syscall(addr(ESCROW)).unwrap_syscall().into();
    assert!(class == ESCROW_CLASS, "the policies commit to this escrow class");
    let pool = IM31PoolDispatcher { contract_address: addr(POOL) };
    pool.set_policy_verifier(addr(P1_ADAPTER));
    let token = IERC20Dispatcher { contract_address: addr(TOKEN) };
    token.approve(addr(POOL), 1000000);
    pool.deposit(addr(TOKEN), DEPOSIT0_AMOUNT, deposit0_inner().span(), deposit0_ciphertext().span());
    pool.deposit(addr(TOKEN), DEPOSIT1_AMOUNT, deposit1_inner().span(), deposit1_ciphertext().span());
    for x in array![addr(POOL), addr(P1_ADAPTER), addr(ESCROW)] {
        start_cheat_chain_id(x, 'SN_SEPOLIA');
        start_cheat_block_number(x, BASE_BLOCK + 20);
    }
    pool
}
fn arbiter_approves(outcome: u8) {
    start_cheat_caller_address(addr(ESCROW), addr(ARBITER));
    IPolicyEscrowDispatcher { contract_address: addr(ESCROW) }.approve(POLICY_ID_A, outcome);
    stop_cheat_caller_address(addr(ESCROW));
}

#[test]
fn policy_real_release_and_seed_refund() {
    let pool = setup();
    arbiter_approves(1);
    start_cheat_proof_facts(addr(P1_ADAPTER), facts_a().span());
    let g = get_available_gas();
    pool.apply_policy_spend(decode(spend_a()), array![].span(), ciphertexts_a().span(), array![].span());
    println!("GAS apply_policy_spend release two_notes={}", g - get_available_gas());
    assert!(IPolicyEscrowDispatcher { contract_address: addr(ESCROW) }.consumed(addr(ARBITER), POLICY_ID_A));
    // Note B's deadline has passed: its refund settles without the controller.
    start_cheat_proof_facts(addr(P1_ADAPTER), facts_b().span());
    let g = get_available_gas();
    pool.apply_policy_spend(decode(spend_b()), array![].span(), ciphertexts_b().span(), array![].span());
    println!("GAS apply_policy_spend refund one_note={}", g - get_available_gas());
    let tree = IM31TreeDispatcher { contract_address: addr(POOL) };
    assert_eq!(tree.get_leaf_count(), 5);
    assert!(tree.get_root() == root_after().span(), "the pool's tree is the wallets' tree");
    assert_eq!(IERC20Dispatcher { contract_address: addr(TOKEN) }.balance_of(addr(POOL)), (DEPOSIT0_AMOUNT + DEPOSIT1_AMOUNT).into());
}

#[test]
#[should_panic(expected: 'ESCROW_NOT_APPROVED')]
fn policy_real_release_needs_the_arbiter() {
    let pool = setup();
    start_cheat_proof_facts(addr(P1_ADAPTER), facts_a().span());
    pool.apply_policy_spend(decode(spend_a()), array![].span(), ciphertexts_a().span(), array![].span());
}

#[test]
#[should_panic(expected: 'ESCROW_NOT_APPROVED')]
fn policy_real_cancelled_release_rejected() {
    let pool = setup();
    arbiter_approves(0);
    start_cheat_proof_facts(addr(P1_ADAPTER), facts_a().span());
    pool.apply_policy_spend(decode(spend_a()), array![].span(), ciphertexts_a().span(), array![].span());
}

#[test]
#[should_panic(expected: 'NULLIFIER_USED')]
fn policy_real_replay_rejected() {
    let pool = setup();
    start_cheat_proof_facts(addr(P1_ADAPTER), facts_b().span());
    pool.apply_policy_spend(decode(spend_b()), array![].span(), ciphertexts_b().span(), array![].span());
    pool.apply_policy_spend(decode(spend_b()), array![].span(), ciphertexts_b().span(), array![].span());
}

/// Another proof's facts do not authorize this statement.
#[test]
#[should_panic(expected: 'PROOF_BINDING')]
fn policy_real_other_facts_rejected() {
    let pool = setup();
    arbiter_approves(1);
    start_cheat_proof_facts(addr(P1_ADAPTER), facts_b().span());
    pool.apply_policy_spend(decode(spend_a()), array![].span(), ciphertexts_a().span(), array![].span());
}

/// The relayer cannot redirect a published output: the binding covers it.
#[test]
#[should_panic(expected: 'BAD_BINDING')]
fn policy_real_redirected_output_rejected() {
    let pool = setup();
    arbiter_approves(1);
    start_cheat_proof_facts(addr(P1_ADAPTER), facts_a().span());
    let mut s = decode(spend_a());
    let mut cms = array![];
    cms.append_span(s.commitments.slice(9, 9));
    cms.append_span(s.commitments.slice(0, 9));
    s.commitments = cms.span();
    pool.apply_policy_spend(s, array![].span(), ciphertexts_a().span(), array![].span());
}

/// The refund cannot settle through the controller window with a later deadline: the deadline is
/// proven (here: a statement claiming a far deadline fails the binding).
#[test]
#[should_panic(expected: 'BAD_BINDING')]
fn policy_real_deadline_is_bound() {
    let pool = setup();
    start_cheat_proof_facts(addr(P1_ADAPTER), facts_b().span());
    let mut s = decode(spend_b());
    s.deadline = 10000000;
    pool.apply_policy_spend(s, array![].span(), ciphertexts_b().span(), array![].span());
}
