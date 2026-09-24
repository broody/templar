//! M31 pool V2 (`docs/hidden-asset-spec.md` §5): R0 V4 spends, the exit rule and uniform shape,
//! ERC20 pull deposits, ERC721/ERC1155 push deposits through the receiver hooks, the asset
//! registry and per-contract standards, `held` accounting and `pay_out` by standard. The R0 V4
//! verdict is mocked here; real proofs run in the end-to-end tests.
use core::poseidon::poseidon_hash_span;
use snforge_std::{
    ContractClassTrait, DeclareResultTrait, declare, start_cheat_block_number_global, start_cheat_caller_address,
    stop_cheat_caller_address, test_address,
};
use starknet::syscalls::get_class_hash_at_syscall;
use starknet::{ContractAddress, SyscallResultTrait, get_tx_info};
use m31_pool::assets::{
    ERC1155, ERC20, ERC721, IAssetReceiverDispatcher, IAssetReceiverDispatcherTrait, IERC1155Dispatcher,
    IERC1155DispatcherTrait, IERC1155_RECEIVER_ID, IERC721Dispatcher, IERC721DispatcherTrait, IERC721_RECEIVER_ID,
    ISRC5_ID, ISRC6_ID, asset_id,
};
use m31_pool::hash::{key, read_digest};
use m31_pool::open_note::{ExecutionIntent, INVOKE, OpenDestination, hash_intent_of};
use m31_pool::policy::{FIXED, PolicySpend, policy_binding};
use m31_pool::policy_escrow::{IPolicyEscrowDispatcher, IPolicyEscrowDispatcherTrait};
use m31_pool::pool_v2::{IM31PoolV2Dispatcher, IM31PoolV2DispatcherTrait};
use m31_pool::spend::{IERC20Dispatcher, IERC20DispatcherTrait, Output, Withdrawal, delivery_digest};
use m31_pool::spend4::{Spend, compute_binding};
use m31_pool::test_nft::{IMintDispatcher, IMintDispatcherTrait};
use m31_pool::tree::{IM31TreeDispatcher, IM31TreeDispatcherTrait};

const RECIPIENT: felt252 = 0xb0b;
const ARBITER: felt252 = 0xa4b1;

fn deploy(name: ByteArray, data: Array<felt252>) -> ContractAddress {
    let (address, _) = declare(name).unwrap_syscall().contract_class().deploy(@data).unwrap_syscall();
    address
}
fn payload(seed: felt252) -> Span<felt252> {
    array![seed, 2, 3, 4, 5, 6, 7, 8, 9, 10].span()
}
fn digest(seed: felt252) -> Span<felt252> {
    array![seed, seed + 1, seed + 2, seed + 3, seed + 4, seed + 5, seed + 6, seed + 7, seed + 8].span()
}
fn zeros() -> Span<felt252> {
    array![0, 0, 0, 0, 0, 0, 0, 0, 0].span()
}
fn addr(v: felt252) -> ContractAddress {
    v.try_into().unwrap()
}
/// Hook data: `inner₉ ‖ ciphertext₁₀`.
fn hook_data(seed: felt252) -> Span<felt252> {
    let mut d = array![];
    d.append_span(digest(seed));
    d.append_span(payload(seed));
    d.span()
}

#[derive(Drop)]
struct Env {
    pool: IM31PoolV2Dispatcher,
    tree: IM31TreeDispatcher,
    erc20: IERC20Dispatcher,
    nft: ContractAddress,
    multi: ContractAddress,
}

/// A V2 pool (single-permutation nodes), an ERC20 with 1000 deposited, and an ERC721 (ids 1–3)
/// and an ERC1155 (id 7: 1000 units) held by the test contract.
fn env() -> Env {
    let verifier = deploy("MockVerifier", array![1]);
    let pool = deploy("M31PoolV2", array![test_address().into(), verifier.into(), 1, 0]);
    let p = IM31PoolV2Dispatcher { contract_address: pool };
    p.set_policy_verifier(verifier);
    let erc20 = IERC20Dispatcher { contract_address: deploy("E2EToken", array![test_address().into(), 1000000, 0]) };
    erc20.approve(pool, 1000000);
    p.deposit(erc20.contract_address, 1000, digest(7), payload(1));
    let nft = deploy("TestERC721", array![]);
    let multi = deploy("TestERC1155", array![]);
    for id in 1..4_u8 {
        IMintDispatcher { contract_address: nft }.mint(test_address(), id.into(), 1);
    }
    IMintDispatcher { contract_address: multi }.mint(test_address(), 7, 1000);
    start_cheat_block_number_global(100);
    Env { pool: p, tree: IM31TreeDispatcher { contract_address: pool }, erc20, nft, multi }
}

fn deposit_nft(e: @Env, id: u256, seed: felt252) -> felt252 {
    IERC721SafeTransferDispatcher { contract_address: *e.nft }.safe_transfer_from(test_address(), *e.pool.contract_address, id, hook_data(seed));
    asset_id(ERC721, *e.nft, id)
}
fn deposit_multi(e: @Env, value: u256, seed: felt252) -> felt252 {
    IERC1155Dispatcher { contract_address: *e.multi }
        .safe_transfer_from(test_address(), *e.pool.contract_address, 7, value, hook_data(seed));
    asset_id(ERC1155, *e.multi, 7)
}

#[starknet::interface]
trait IERC721SafeTransfer<T> {
    fn safe_transfer_from(ref self: T, from: ContractAddress, to: ContractAddress, token_id: u256, data: Span<felt252>);
}
#[starknet::interface]
trait IERC1155Batch<T> {
    fn safe_batch_transfer_from(
        ref self: T, from: ContractAddress, to: ContractAddress, token_ids: Span<u256>, values: Span<u256>,
        data: Span<felt252>,
    );
}

/// A V4 spend: two nullifiers and two outputs always; `asset` is published only with a withdrawal
/// or an intent.
fn spend(e: @Env, nf_seed: felt252, asset: felt252, recipient: felt252, amount: u128) -> Spend {
    let mut nfs = array![];
    nfs.append_span(digest(nf_seed));
    nfs.append_span(digest(nf_seed + 100));
    let out = |j: felt252| Output { commitment: digest(nf_seed + 500 + 100 * j), ciphertext: payload(j + 2) };
    let mut sp = Spend {
        chain: get_tx_info().unbox().chain_id, pool: *e.pool.contract_address, asset, root: (*e.tree).get_root(),
        nullifiers: nfs.span(), outputs: array![out(0), out(1)].span(),
        withdrawal: Withdrawal { recipient: addr(recipient), amount }, intent: 0, identity: zeros(), binding: 0,
    };
    sp.binding = compute_binding(@sp);
    sp
}
fn transfer(e: @Env, nf_seed: felt252) -> Spend {
    spend(e, nf_seed, 0, 0, 0)
}
fn withdraw(e: @Env, nf_seed: felt252, asset: felt252, recipient: felt252, amount: u128) -> Spend {
    spend(e, nf_seed, asset, recipient, amount)
}

// ---------------------------------------------------------------- ERC20 and V4 spends

#[test]
fn erc20_deposit_transfer_and_withdraw() {
    let e = env();
    let a: felt252 = e.erc20.contract_address.into();
    assert_eq!(e.pool.get_held(a), 1000);
    assert_eq!(e.pool.get_contract_standard(e.erc20.contract_address), ERC20);
    let before = e.tree.get_leaf_count();
    // An in-pool transfer publishes no asset and always appends two outputs.
    e.pool.apply_spend(transfer(@e, 1000), array![].span());
    assert_eq!(e.tree.get_leaf_count(), before + 2);
    assert!(e.pool.get_nullifier_spent(digest(1000)) && e.pool.get_nullifier_spent(digest(1100)));
    // A withdrawal publishes the asset and pays it.
    e.pool.apply_spend(withdraw(@e, 2000, a, RECIPIENT, 400), array![].span());
    assert_eq!(e.erc20.balance_of(addr(RECIPIENT)), 400);
    assert_eq!(e.pool.get_held(a), 600);
    assert_eq!(e.tree.get_leaf_count(), before + 4);
}

#[test]
#[should_panic(expected: 'EXIT_RULE')]
fn voluntary_reveal_rejected() {
    let e = env();
    e.pool.apply_spend(spend(@e, 1000, e.erc20.contract_address.into(), 0, 0), array![].span());
}

#[test]
#[should_panic(expected: 'EXIT_RULE')]
fn hidden_asset_on_exit_rejected() {
    let e = env();
    e.pool.apply_spend(withdraw(@e, 1000, 0, RECIPIENT, 10), array![].span());
}

#[test]
#[should_panic(expected: 'BAD_WITHDRAWAL')]
fn recipient_without_amount_rejected() {
    let e = env();
    e.pool.apply_spend(spend(@e, 1000, 0, RECIPIENT, 0), array![].span());
}

#[test]
#[should_panic(expected: 'ZERO_COMMITMENT')]
fn both_outputs_required() {
    let e = env();
    let mut sp = transfer(@e, 1000);
    sp.outputs = array![Output { commitment: digest(1), ciphertext: payload(2) }, Output { commitment: zeros(), ciphertext: payload(3) }].span();
    sp.binding = compute_binding(@sp);
}

#[test]
#[should_panic(expected: 'PAYLOAD_LENGTH')]
fn both_ciphertexts_required() {
    let e = env();
    let mut sp = transfer(@e, 1000);
    sp.outputs = array![Output { commitment: digest(1), ciphertext: payload(2) }, Output { commitment: digest(2), ciphertext: array![].span() }].span();
    sp.binding = compute_binding(@sp);
}

#[test]
#[should_panic(expected: 'NULLIFIER_USED')]
fn dummy_nullifiers_are_spent_too() {
    let e = env();
    e.pool.apply_spend(transfer(@e, 1000), array![].span());
    // A second spend reusing only the first spend's second (dummy) nullifier.
    let mut sp = transfer(@e, 5000);
    let mut nfs = array![];
    nfs.append_span(digest(5000));
    nfs.append_span(digest(1100));
    sp.nullifiers = nfs.span();
    sp.binding = compute_binding(@sp);
    e.pool.apply_spend(sp, array![].span());
}

#[test]
#[should_panic(expected: 'BAD_BINDING')]
fn asset_is_bound() {
    let e = env();
    let mut sp = withdraw(@e, 1000, e.erc20.contract_address.into(), RECIPIENT, 10);
    sp.asset = sp.asset + 1;
    e.pool.apply_spend(sp, array![].span());
}

#[test]
#[should_panic(expected: 'BAD_RECIPIENT')]
fn withdrawal_to_the_pool_rejected() {
    let e = env();
    let pool: felt252 = e.pool.contract_address.into();
    e.pool.apply_spend(withdraw(@e, 1000, e.erc20.contract_address.into(), pool, 10), array![].span());
}

#[test]
#[should_panic(expected: 'HELD_UNDERFLOW')]
fn withdrawal_beyond_holdings_rejected() {
    let e = env();
    e.pool.apply_spend(withdraw(@e, 1000, e.erc20.contract_address.into(), RECIPIENT, 1001), array![].span());
}

// ---------------------------------------------------------------- ERC721

#[test]
fn erc721_push_deposit_registers_and_holds() {
    let e = env();
    let before = e.tree.get_leaf_count();
    let a = deposit_nft(@e, 2, 40);
    assert_eq!(e.tree.get_leaf_count(), before + 1);
    assert_eq!(IERC721Dispatcher { contract_address: e.nft }.owner_of(2), e.pool.contract_address);
    assert_eq!(e.pool.get_held(a), 1);
    let info = e.pool.get_asset(a);
    assert!(info.standard == ERC721 && info.contract == e.nft && info.id == 2);
    assert_eq!(e.pool.asset_id(ERC721, e.nft, 2), a);
    assert_eq!(e.pool.get_contract_standard(e.nft), ERC721);
    assert!(e.pool.get_delivery_digest(before) == delivery_digest(payload(40)));
}

#[test]
fn erc721_withdraw_and_redeposit() {
    let e = env();
    let a = deposit_nft(@e, 2, 40);
    e.pool.apply_spend(withdraw(@e, 1000, a, RECIPIENT, 1), array![].span());
    assert_eq!(IERC721Dispatcher { contract_address: e.nft }.owner_of(2), addr(RECIPIENT));
    assert_eq!(e.pool.get_held(a), 0);
    // The new owner pushes it back; the asset is already registered.
    start_cheat_caller_address(e.nft, addr(RECIPIENT));
    IERC721SafeTransferDispatcher { contract_address: e.nft }.safe_transfer_from(addr(RECIPIENT), e.pool.contract_address, 2, hook_data(41));
    stop_cheat_caller_address(e.nft);
    assert_eq!(e.pool.get_held(a), 1);
}

#[test]
#[should_panic(expected: 'HELD_UNDERFLOW')]
fn erc721_amount_two_rejected() {
    let e = env();
    let a = deposit_nft(@e, 2, 40);
    e.pool.apply_spend(withdraw(@e, 1000, a, RECIPIENT, 2), array![].span());
}

#[test]
#[should_panic(expected: 'HOOK_DATA')]
fn erc721_malformed_data_rejected() {
    let e = env();
    IERC721SafeTransferDispatcher { contract_address: e.nft }.safe_transfer_from(test_address(), e.pool.contract_address, 2, digest(1));
}

#[test]
#[should_panic(expected: 'BAD_DEPOSIT')]
fn erc721_zero_inner_rejected() {
    let e = env();
    let mut d = array![];
    d.append_span(zeros());
    d.append_span(payload(1));
    IERC721SafeTransferDispatcher { contract_address: e.nft }.safe_transfer_from(test_address(), e.pool.contract_address, 2, d.span());
}

/// An NFT sent with a plain transfer is held without a note and cannot be deposited later.
#[test]
#[should_panic(expected: 'ERC721: unauthorized caller')]
fn erc721_unsolicited_plain_transfer_is_lost() {
    let e = env();
    IERC721Dispatcher { contract_address: e.nft }.transfer_from(test_address(), e.pool.contract_address, 3);
    assert_eq!(e.pool.get_held(asset_id(ERC721, e.nft, 3)), 0);
    // The pool now owns it; nobody can push it with a note.
    IERC721SafeTransferDispatcher { contract_address: e.nft }.safe_transfer_from(test_address(), e.pool.contract_address, 3, hook_data(1));
}

// ---------------------------------------------------------------- ERC1155

#[test]
fn erc1155_push_deposit_and_payout() {
    let e = env();
    let a = deposit_multi(@e, 300, 50);
    assert_eq!(e.pool.get_held(a), 300);
    assert_eq!(IERC1155Dispatcher { contract_address: e.multi }.balance_of(e.pool.contract_address, 7), 300);
    let account = deploy("AccountLikeRecipient", array![]);
    e.pool.apply_spend(withdraw(@e, 1000, a, account.into(), 120), array![].span());
    assert_eq!(IERC1155Dispatcher { contract_address: e.multi }.balance_of(account, 7), 120);
    assert_eq!(e.pool.get_held(a), 180);
}

#[test]
#[should_panic(expected: 'ENTRYPOINT_NOT_FOUND')]
fn erc1155_payout_to_recipient_without_src5_reverts() {
    let e = env();
    let a = deposit_multi(@e, 300, 50);
    let plain = deploy("PlainRecipient", array![]);
    e.pool.apply_spend(withdraw(@e, 1000, a, plain.into(), 1), array![].span());
}

#[test]
#[should_panic(expected: 'REENTRANCY')]
fn erc1155_recipient_hook_cannot_reenter() {
    let e = env();
    let a = deposit_multi(@e, 300, 50);
    let evil = deploy("ReentrantRecipient", array![e.pool.contract_address.into(), e.erc20.contract_address.into()]);
    e.pool.apply_spend(withdraw(@e, 1000, a, evil.into(), 1), array![].span());
}

#[test]
#[should_panic(expected: 'AMOUNT_RANGE')]
fn erc1155_value_above_u128_rejected() {
    let e = env();
    let big: u256 = 0x100000000000000000000000000000000;
    IMintDispatcher { contract_address: e.multi }.mint(test_address(), 7, big);
    IERC1155Dispatcher { contract_address: e.multi }.safe_transfer_from(test_address(), e.pool.contract_address, 7, big, hook_data(1));
}

#[test]
#[should_panic(expected: "BATCH_DEPOSIT")]
fn erc1155_batch_rejected() {
    let e = env();
    IMintDispatcher { contract_address: e.multi }.mint(test_address(), 8, 10);
    IERC1155BatchDispatcher { contract_address: e.multi }
        .safe_batch_transfer_from(test_address(), e.pool.contract_address, array![7, 8].span(), array![1, 1].span(), hook_data(1));
}

/// A hook-less mint to the pool does not block later deposits of that id (the `≥` check); the
/// surplus is never credited.
#[test]
fn erc1155_hookless_mint_does_not_block_deposits() {
    let e = env();
    IMintDispatcher { contract_address: e.multi }.mint(e.pool.contract_address, 7, 5);
    let a = deposit_multi(@e, 10, 50);
    assert_eq!(e.pool.get_held(a), 10);
    assert_eq!(IERC1155Dispatcher { contract_address: e.multi }.balance_of(e.pool.contract_address, 7), 15);
}

/// Calling the hook directly without transferring fails the balance check.
#[test]
#[should_panic(expected: 'NOT_RECEIVED')]
fn erc1155_hook_without_transfer_rejected() {
    let e = env();
    deposit_multi(@e, 10, 50);
    start_cheat_caller_address(e.pool.contract_address, e.multi);
    IAssetReceiverDispatcher { contract_address: e.pool.contract_address }
        .on_erc1155_received(test_address(), test_address(), 7, 1, hook_data(51));
}

// ---------------------------------------------------------------- standards and registry

#[test]
fn pool_answers_src5() {
    let e = env();
    let r = IAssetReceiverDispatcher { contract_address: e.pool.contract_address };
    assert!(r.supports_interface(ISRC5_ID) && r.supports_interface(IERC1155_RECEIVER_ID) && r.supports_interface(IERC721_RECEIVER_ID));
    assert!(!r.supports_interface(ISRC6_ID));
}

/// A contract recorded as ERC721 cannot be deposited as an ERC20.
#[test]
#[should_panic(expected: 'STANDARD_MISMATCH')]
fn nft_contract_as_erc20_rejected() {
    let e = env();
    deposit_nft(@e, 1, 40);
    e.pool.deposit(e.nft, 1, digest(9), payload(9));
}

/// A contract recorded as ERC20 cannot register NFT assets through a hook.
#[test]
#[should_panic(expected: 'STANDARD_MISMATCH')]
fn erc20_contract_as_nft_rejected() {
    let e = env();
    start_cheat_caller_address(e.pool.contract_address, e.erc20.contract_address);
    IAssetReceiverDispatcher { contract_address: e.pool.contract_address }
        .on_erc721_received(test_address(), test_address(), 1, hook_data(1));
}

/// One contract cannot back notes as both ERC721 and ERC1155.
#[test]
#[should_panic(expected: 'STANDARD_MISMATCH')]
fn one_contract_two_nft_standards_rejected() {
    let e = env();
    deposit_nft(@e, 1, 40);
    start_cheat_caller_address(e.pool.contract_address, e.nft);
    IAssetReceiverDispatcher { contract_address: e.pool.contract_address }
        .on_erc1155_received(test_address(), test_address(), 1, 1, hook_data(1));
}

/// An NFT asset identifier is never accepted as an ERC20 address.
#[test]
#[should_panic(expected: 'ASSET_REGISTERED')]
fn registered_identifier_as_erc20_rejected() {
    let e = env();
    let a = deposit_nft(@e, 1, 40);
    e.pool.deposit(addr(a), 1, digest(9), payload(9));
}

/// A contract that does not claim the token interface through SRC5 cannot register assets.
#[test]
#[should_panic(expected: 'ENTRYPOINT_NOT_FOUND')]
fn hook_from_non_token_rejected() {
    let e = env();
    let plain = deploy("PlainRecipient", array![]);
    start_cheat_caller_address(e.pool.contract_address, plain);
    IAssetReceiverDispatcher { contract_address: e.pool.contract_address }
        .on_erc721_received(test_address(), test_address(), 1, hook_data(1));
}

// ---------------------------------------------------------------- open notes and policy notes

/// Executions move ERC20 only: an NFT asset cannot be a budget.
#[test]
#[should_panic(expected: 'EXECUTION_ASSET')]
fn execution_with_nft_asset_rejected() {
    let e = env();
    let a = deposit_nft(@e, 1, 40);
    let adapter = deploy("MockSwapAdapter", array![]);
    let intent = ExecutionIntent {
        kind: INVOKE, adapter, nonce: 0, expiry: 1000000, calldata: array![].span(),
        destinations: array![OpenDestination { note_id: 77, token: e.erc20.contract_address, minimum: 1, inner: digest(900), ciphertext: payload(9) }].span(),
    };
    let mut sp = withdraw(@e, 1000, a, adapter.into(), 1);
    sp.intent = hash_intent_of(sp.chain, sp.pool.into(), sp.asset, sp.withdrawal, @intent);
    sp.binding = compute_binding(@sp);
    e.pool.apply_spend_with_invoke(sp, intent, array![].span());
}

/// An ERC721 escrow: a policy note holding the NFT settles its release outcome as a withdrawal to
/// the beneficiary, through `pay_out`.
#[test]
fn nft_policy_note_release_pays_the_nft() {
    let e = env();
    let a = deposit_nft(@e, 2, 40);
    let escrow = deploy("PolicyEscrow", array![e.pool.contract_address.into()]);
    let class: felt252 = get_class_hash_at_syscall(escrow).unwrap_syscall().into();
    let pid = digest(61);
    start_cheat_caller_address(escrow, addr(ARBITER));
    IPolicyEscrowDispatcher { contract_address: escrow }.approve(key(read_digest(pid)), 1);
    stop_cheat_caller_address(escrow);
    let mut cms = array![];
    cms.append_span(zeros());
    cms.append_span(zeros());
    let mut sp = PolicySpend {
        chain: get_tx_info().unbox().chain_id, pool: e.pool.contract_address, token: addr(a),
        root: e.tree.get_root(), nullifier: digest(3000), commitments: cms.span(),
        delivery0: 0, delivery1: 0, withdrawal: Withdrawal { recipient: addr(RECIPIENT), amount: 1 }, controller: escrow,
        controller_class: class, handle: ARBITER, policy_id: pid, deadline: 1000, not_before: 0, index: 1, kind: FIXED,
        x: 0, data: poseidon_hash_span(array![].span()), binding: 0,
    };
    sp.binding = policy_binding(@sp);
    e.pool.apply_policy_spend(sp, array![].span(), array![array![].span(), array![].span()].span(), array![].span());
    assert_eq!(IERC721Dispatcher { contract_address: e.nft }.owner_of(2), addr(RECIPIENT));
    assert_eq!(e.pool.get_held(a), 0);
}
