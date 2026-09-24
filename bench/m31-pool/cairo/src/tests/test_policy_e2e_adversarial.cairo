//! Separation and relayer tests on the real P1 vectors, from the implementation review.
use snforge_std::{
    ContractClassTrait, DeclareResultTrait, declare, start_cheat_block_number, start_cheat_caller_address,
    start_cheat_chain_id, start_cheat_proof_facts, stop_cheat_caller_address, test_address,
};
use starknet::{ContractAddress, SyscallResultTrait};
use m31_pool::policy::PolicySpend;
use m31_pool::policy_escrow::{IPolicyEscrowDispatcher, IPolicyEscrowDispatcherTrait};
use m31_pool::pool::{IM31PoolDispatcher, IM31PoolDispatcherTrait};
use m31_pool::spend::{IERC20Dispatcher, IERC20DispatcherTrait, IVerifierDispatcher, IVerifierDispatcherTrait};
use super::policy_vectors::*;

fn a(x: felt252) -> ContractAddress {
    x.try_into().unwrap()
}

/// Real P1 facts do not pass an R0-tagged adapter, even one pinned to the P1 statement account
/// and class (the tag alone separates them).
#[test]
#[should_panic(expected: 'PROOF_BINDING')]
fn r_real_p1_facts_rejected_by_r0_tagged_adapter() {
    let pool: ContractAddress = a(POOL);
    let (addr, _) = declare("Proof2Adapter").unwrap_syscall().contract_class()
        .deploy(@array![POOL, STATEMENT, STATEMENT_CLASS, OS_PROGRAM, 4096, 'TMPZR0_PAYMENT_V3']).unwrap_syscall();
    start_cheat_caller_address(addr, pool);
    start_cheat_chain_id(addr, 'SN_SEPOLIA');
    start_cheat_block_number(addr, BASE_BLOCK + 20);
    start_cheat_proof_facts(addr, facts_a().span());
    let mut f = spend_a().span();
    let s: PolicySpend = Serde::deserialize(ref f).unwrap();
    IVerifierDispatcher { contract_address: addr }.verify(array![].span(), array!['SN_SEPOLIA', POOL, s.binding].span());
}

/// Sanity for the test above: the P1-tagged adapter accepts the same call.
#[test]
fn r_real_p1_facts_accepted_by_p1_adapter() {
    let pool: ContractAddress = a(POOL);
    let (addr, _) = declare("Proof2Adapter").unwrap_syscall().contract_class()
        .deploy(@array![POOL, STATEMENT, STATEMENT_CLASS, OS_PROGRAM, 4096, 'TMPZP1_POLICY_V1']).unwrap_syscall();
    start_cheat_caller_address(addr, pool);
    start_cheat_chain_id(addr, 'SN_SEPOLIA');
    start_cheat_block_number(addr, BASE_BLOCK + 20);
    start_cheat_proof_facts(addr, facts_a().span());
    let mut f = spend_a().span();
    let s: PolicySpend = Serde::deserialize(ref f).unwrap();
    assert!(IVerifierDispatcher { contract_address: addr }.verify(array![].span(), array!['SN_SEPOLIA', POOL, s.binding].span()));
}

/// Real statement: the relayer cannot swap the two ciphertexts (delivery digests are bound).
#[test]
#[should_panic(expected: 'DELIVERY')]
fn r_real_swapped_ciphertexts_rejected() {
    let me: felt252 = test_address().into();
    let dep = |name: ByteArray, data: Array<felt252>, at: felt252| {
        declare(name).unwrap_syscall().contract_class().deploy_at(@data, a(at)).unwrap_syscall();
    };
    dep("E2EToken", array![me, 1000000, 0], TOKEN);
    dep("Proof2Adapter", array![POOL, STATEMENT, STATEMENT_CLASS, OS_PROGRAM, 4096, 'TMPZP1_POLICY_V1'], P1_ADAPTER);
    dep("M31Pool", array![me, 0x1, 1, 0], POOL);
    dep("PolicyEscrow", array![POOL], ESCROW);
    let pool = IM31PoolDispatcher { contract_address: a(POOL) };
    pool.set_policy_verifier(a(P1_ADAPTER));
    IERC20Dispatcher { contract_address: a(TOKEN) }.approve(a(POOL), 1000000);
    pool.deposit(a(TOKEN), DEPOSIT0_AMOUNT, deposit0_inner().span(), deposit0_ciphertext().span());
    pool.deposit(a(TOKEN), DEPOSIT1_AMOUNT, deposit1_inner().span(), deposit1_ciphertext().span());
    for x in array![a(POOL), a(P1_ADAPTER), a(ESCROW)] {
        start_cheat_chain_id(x, 'SN_SEPOLIA');
        start_cheat_block_number(x, BASE_BLOCK + 20);
    }
    start_cheat_caller_address(a(ESCROW), a(ARBITER));
    IPolicyEscrowDispatcher { contract_address: a(ESCROW) }.approve(POLICY_ID_A, 1);
    stop_cheat_caller_address(a(ESCROW));
    start_cheat_proof_facts(a(P1_ADAPTER), facts_a().span());
    let c = ciphertexts_a();
    let mut f = spend_a().span();
    let s: PolicySpend = Serde::deserialize(ref f).unwrap();
    pool.apply_policy_spend(s, array![].span(), array![*c.at(1), *c.at(0)].span(), array![].span());
}
