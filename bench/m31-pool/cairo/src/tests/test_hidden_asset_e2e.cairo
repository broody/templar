//! Real hidden-asset settlements (`hidden_asset_e2e.py`): pool V2, an ERC20, an ERC721 and an
//! ERC1155 at the committed addresses; the three deposits replayed (ERC20 pull, ERC721 and ERC1155
//! pushes, the latter an escrow policy note); then two hidden-asset transfers (R0 V4), the
//! ERC1155 escrow release (P1) paying by safe transfer, and the NFT's withdrawal (R0 V4, asset
//! published), each through bridge, virtual OS and a large proof, settled here with the real
//! proof facts. The pool's tree must end at the wallets' root.
use core::testing::get_available_gas;
use snforge_std::{
    ContractClassTrait, DeclareResultTrait, declare, start_cheat_block_number, start_cheat_caller_address,
    start_cheat_chain_id, start_cheat_proof_facts, stop_cheat_caller_address, test_address,
};
use starknet::syscalls::get_class_hash_at_syscall;
use starknet::{ContractAddress, SyscallResultTrait};
use m31_pool::assets::{IERC1155Dispatcher, IERC1155DispatcherTrait, IERC721Dispatcher, IERC721DispatcherTrait};
use m31_pool::policy::PolicySpend;
use m31_pool::policy_escrow::{IPolicyEscrowDispatcher, IPolicyEscrowDispatcherTrait};
use m31_pool::pool_v2::{IM31PoolV2Dispatcher, IM31PoolV2DispatcherTrait};
use m31_pool::spend::{IERC20Dispatcher, IERC20DispatcherTrait};
use m31_pool::spend4::Spend;
use m31_pool::test_nft::{IMintDispatcher, IMintDispatcherTrait};
use m31_pool::tree::{IM31TreeDispatcher, IM31TreeDispatcherTrait};
use super::hidden_asset_vectors::*;

fn addr(x: felt252) -> ContractAddress {
    x.try_into().unwrap()
}
fn deploy_at(name: ByteArray, data: Array<felt252>, at: felt252) {
    declare(name).unwrap_syscall().contract_class().deploy_at(@data, addr(at)).unwrap_syscall();
}
fn spend(felts: Array<felt252>) -> Spend {
    let mut f = felts.span();
    Serde::deserialize(ref f).unwrap()
}
fn policy_spend(felts: Array<felt252>) -> PolicySpend {
    let mut f = felts.span();
    Serde::deserialize(ref f).unwrap()
}

#[starknet::interface]
trait IERC721SafeTransfer<T> {
    fn safe_transfer_from(ref self: T, from: ContractAddress, to: ContractAddress, token_id: u256, data: Span<felt252>);
}

/// Everything at the committed addresses, the three deposits replayed in the wallets' order.
fn setup() -> IM31PoolV2Dispatcher {
    let me: felt252 = test_address().into();
    deploy_at("E2EToken", array![me, 1000000, 0], ERC20_TOKEN);
    deploy_at("TestERC721", array![], NFT);
    deploy_at("TestERC1155", array![], MULTI);
    deploy_at("AccountLikeRecipient", array![], ACCOUNT);
    deploy_at("Proof2Adapter", array![POOL, R4_STATEMENT, R4_STATEMENT_CLASS, OS_PROGRAM, 4096, 'TMPZR0_PAYMENT_V4'], R4_ADAPTER);
    deploy_at("Proof2Adapter", array![POOL, P1_STATEMENT, P1_STATEMENT_CLASS, OS_PROGRAM, 4096, 'TMPZP1_POLICY_V1'], P1_ADAPTER);
    deploy_at("M31PoolV2", array![me, R4_ADAPTER, 1, 0], POOL);
    deploy_at("PolicyEscrow", array![POOL], ESCROW);
    let class: felt252 = get_class_hash_at_syscall(addr(ESCROW)).unwrap_syscall().into();
    assert!(class == ESCROW_CLASS, "the policy commits to this escrow class");
    let pool = IM31PoolV2Dispatcher { contract_address: addr(POOL) };
    pool.set_policy_verifier(addr(P1_ADAPTER));
    for x in array![addr(POOL), addr(R4_ADAPTER), addr(P1_ADAPTER), addr(ESCROW)] {
        start_cheat_chain_id(x, 'SN_SEPOLIA');
        start_cheat_block_number(x, BASE_BLOCK + 20);
    }
    IERC20Dispatcher { contract_address: addr(ERC20_TOKEN) }.approve(addr(POOL), 1000000);
    pool.deposit(addr(ERC20_TOKEN), ERC20_AMOUNT, deposit0_inner().span(), deposit0_ciphertext().span());
    IMintDispatcher { contract_address: addr(NFT) }.mint(test_address(), NFT_ID, 1);
    IERC721SafeTransferDispatcher { contract_address: addr(NFT) }.safe_transfer_from(test_address(), addr(POOL), NFT_ID, nft_hook_data().span());
    IMintDispatcher { contract_address: addr(MULTI) }.mint(test_address(), MULTI_ID, MULTI_AMOUNT.into());
    IERC1155Dispatcher { contract_address: addr(MULTI) }
        .safe_transfer_from(test_address(), addr(POOL), MULTI_ID, MULTI_AMOUNT.into(), multi_hook_data().span());
    assert_eq!(pool.get_asset(NFT_ASSET).standard, 721);
    assert_eq!(pool.get_asset(MULTI_ASSET).standard, 1155);
    pool
}
fn arbiter_approves() {
    start_cheat_caller_address(addr(ESCROW), addr(ARBITER));
    IPolicyEscrowDispatcher { contract_address: addr(ESCROW) }.approve(POLICY_ID, 1);
    stop_cheat_caller_address(addr(ESCROW));
}

#[test]
fn hidden_asset_real_transfers_escrow_and_withdrawal() {
    let pool = setup();
    // S1, S2: in-pool transfers; neither publishes its asset.
    start_cheat_proof_facts(addr(R4_ADAPTER), facts_s1().span());
    let s1 = spend(spend_s1());
    assert!(s1.asset == 0);
    let g = get_available_gas();
    pool.apply_spend(s1, array![].span());
    println!("GAS apply_spend v4 erc20_transfer one_input={}", g - get_available_gas());
    start_cheat_proof_facts(addr(R4_ADAPTER), facts_s2().span());
    let s2 = spend(spend_s2());
    assert!(s2.asset == 0);
    let g = get_available_gas();
    pool.apply_spend(s2, array![].span());
    println!("GAS apply_spend v4 nft_transfer one_input_dummy_output={}", g - get_available_gas());
    // S3: the ERC1155 escrow release pays 300 units by safe transfer.
    arbiter_approves();
    start_cheat_proof_facts(addr(P1_ADAPTER), facts_s3().span());
    let g = get_available_gas();
    pool.apply_policy_spend(policy_spend(spend_s3()), array![].span(), array![array![].span(), array![].span()].span(), array![].span());
    println!("GAS apply_policy_spend erc1155_release withdrawal={}", g - get_available_gas());
    assert_eq!(IERC1155Dispatcher { contract_address: addr(MULTI) }.balance_of(addr(ACCOUNT), MULTI_ID), MULTI_AMOUNT.into());
    assert_eq!(pool.get_held(MULTI_ASSET), 0);
    // S4: Bob withdraws the NFT; the asset is published.
    start_cheat_proof_facts(addr(R4_ADAPTER), facts_s4().span());
    let s4 = spend(spend_s4());
    assert!(s4.asset == NFT_ASSET);
    let g = get_available_gas();
    pool.apply_spend(s4, array![].span());
    println!("GAS apply_spend v4 nft_withdrawal two_dummy_outputs={}", g - get_available_gas());
    assert_eq!(IERC721Dispatcher { contract_address: addr(NFT) }.owner_of(NFT_ID), addr(NFT_RECIPIENT));
    assert_eq!(pool.get_held(NFT_ASSET), 0);
    assert_eq!(pool.get_held(ERC20_TOKEN), ERC20_AMOUNT.into());
    let tree = IM31TreeDispatcher { contract_address: addr(POOL) };
    assert_eq!(tree.get_leaf_count(), LEAVES_AFTER);
    assert!(tree.get_root() == root_after().span(), "the pool's tree is the wallets' tree");
}

#[test]
#[should_panic(expected: 'NULLIFIER_USED')]
fn hidden_asset_real_replay_rejected() {
    let pool = setup();
    start_cheat_proof_facts(addr(R4_ADAPTER), facts_s1().span());
    pool.apply_spend(spend(spend_s1()), array![].span());
    pool.apply_spend(spend(spend_s1()), array![].span());
}

/// Another spend's facts do not authorize this statement.
#[test]
#[should_panic(expected: 'PROOF_BINDING')]
fn hidden_asset_real_other_facts_rejected() {
    let pool = setup();
    start_cheat_proof_facts(addr(R4_ADAPTER), facts_s2().span());
    pool.apply_spend(spend(spend_s1()), array![].span());
}

/// Publishing the asset on a transfer changes the binding the proof carries.
#[test]
#[should_panic(expected: 'EXIT_RULE')]
fn hidden_asset_real_revealed_transfer_rejected() {
    let pool = setup();
    start_cheat_proof_facts(addr(R4_ADAPTER), facts_s1().span());
    let mut s1 = spend(spend_s1());
    s1.asset = ERC20_TOKEN;
    pool.apply_spend(s1, array![].span());
}

/// The NFT withdrawal cannot be redirected: the recipient is bound.
#[test]
#[should_panic(expected: 'BAD_BINDING')]
fn hidden_asset_real_redirected_withdrawal_rejected() {
    let pool = setup();
    start_cheat_proof_facts(addr(R4_ADAPTER), facts_s1().span());
    pool.apply_spend(spend(spend_s1()), array![].span());
    start_cheat_proof_facts(addr(R4_ADAPTER), facts_s2().span());
    pool.apply_spend(spend(spend_s2()), array![].span());
    start_cheat_proof_facts(addr(R4_ADAPTER), facts_s4().span());
    let mut s4 = spend(spend_s4());
    s4.withdrawal.recipient = addr(0xbad);
    pool.apply_spend(s4, array![].span());
}

/// The escrow release needs the arbiter.
#[test]
#[should_panic(expected: 'ESCROW_NOT_APPROVED')]
fn hidden_asset_real_release_needs_the_arbiter() {
    let pool = setup();
    start_cheat_proof_facts(addr(P1_ADAPTER), facts_s3().span());
    pool.apply_policy_spend(policy_spend(spend_s3()), array![].span(), array![array![].span(), array![].span()].span(), array![].span());
}
