//! A real R0 V3 open-note spend (`open_note_e2e.py`): client proof binding a real execution
//! intent, bridge, virtual OS and PROOF2, settled here through the PROOF2 adapter and
//! `apply_spend_with_invoke` at the addresses the proof commits to.
use core::poseidon::poseidon_hash_span;
use snforge_std::{
    ContractClassTrait, DeclareResultTrait, declare, start_cheat_block_number, start_cheat_chain_id,
    start_cheat_proof_facts, test_address,
};
use starknet::{ContractAddress, SyscallResultTrait};
use m31_pool::open_note::{ExecutionIntent, identity_commitment};
use m31_pool::pool::{IM31PoolDispatcher, IM31PoolDispatcherTrait};
use m31_pool::spend::{IERC20Dispatcher, IERC20DispatcherTrait, Spend};
use m31_pool::tree::{IM31TreeDispatcher, IM31TreeDispatcherTrait};
use super::e2e_vectors::*;

fn addr(x: felt252) -> ContractAddress {
    x.try_into().unwrap()
}
fn deploy_at(name: ByteArray, data: Array<felt252>, at: felt252) {
    declare(name).unwrap_syscall().contract_class().deploy_at(@data, addr(at)).unwrap_syscall();
}

/// The pool's identity commitment is upstream's `commitment_from_partial`, equal to
/// `poseidon_hash_span([partial, nonce])`, and matches the Python wallet.
#[test]
fn identity_commitment_matches_wallet() {
    let (partial, nonce, expected) = identity_check();
    assert_eq!(identity_commitment(partial, nonce), expected);
    assert_eq!(identity_commitment(partial, nonce), poseidon_hash_span(array![partial, nonce].span()));
}

#[test]
fn open_note_real_proof_end_to_end() {
    let me: felt252 = test_address().into();
    deploy_at("E2EToken", array![me, 1000000, 0], TOKEN_A);
    deploy_at("E2EToken", array![me, 1000000, 0], TOKEN_B);
    deploy_at("MockSwapAdapter", array![], ADAPTER);
    deploy_at("Proof2Adapter", array![POOL, STATEMENT, STATEMENT_CLASS, OS_PROGRAM, 4096, 'TMPZR0_PAYMENT_V3'], PROOF2_ADAPTER);
    deploy_at("M31Pool", array![me, PROOF2_ADAPTER, 1, 0], POOL);
    let (a, b) = (IERC20Dispatcher { contract_address: addr(TOKEN_A) }, IERC20Dispatcher { contract_address: addr(TOKEN_B) });
    let pool = IM31PoolDispatcher { contract_address: addr(POOL) };
    // The wallet's deposits, so the tree reaches the root the proof opens.
    a.approve(addr(POOL), 1000000);
    pool.deposit(addr(TOKEN_A), DEPOSIT0_AMOUNT, deposit0_inner().span(), deposit0_ciphertext().span());
    pool.deposit(addr(TOKEN_A), DEPOSIT1_AMOUNT, deposit1_inner().span(), deposit1_ciphertext().span());
    // The adapter holds the swap proceeds.
    b.transfer(addr(ADAPTER), PROCEEDS.into());
    for x in array![addr(POOL), addr(PROOF2_ADAPTER)] {
        start_cheat_chain_id(x, 'SN_SEPOLIA');
        start_cheat_block_number(x, BASE_BLOCK + 20);
    }
    start_cheat_proof_facts(addr(PROOF2_ADAPTER), facts().span());
    let mut sf = spend_felts().span();
    let spend: Spend = Serde::deserialize(ref sf).unwrap();
    let mut itf = intent_felts().span();
    let intent: ExecutionIntent = Serde::deserialize(ref itf).unwrap();
    let nullifiers = spend.nullifiers;
    pool.apply_spend_with_invoke(spend, intent, array![].span());
    assert_eq!(b.balance_of(addr(POOL)), PROCEEDS.into());
    assert_eq!(a.balance_of(addr(ADAPTER)), BUDGET.into());
    assert_eq!(IM31TreeDispatcher { contract_address: addr(POOL) }.get_leaf_count(), 4);
    assert!(pool.get_nullifier_spent(nullifiers.slice(0, 9)) && pool.get_nullifier_spent(nullifiers.slice(9, 9)));
}
