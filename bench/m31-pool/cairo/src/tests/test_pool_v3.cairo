//! M31 pool V3 (`docs/account-bound-note-spec.md` §8, acceptance §15 P3b) with mocked verdicts:
//! bootstrap, the verifier timelock and two-step ownership, the root rule, the expiry rules, the
//! V5 binding, no fee or gating path, V2's tree tests on the V3 tree, F17, F18, F30, and the pool
//! branches F28 found uncovered. The real statement account runs against the pool in
//! `client-port/cairo-r5/pool_e2e`.
use core::poseidon::poseidon_hash_span;
use snforge_std::{
    ContractClassTrait, DeclareResultTrait, EventSpyAssertionsTrait, declare, spy_events,
    start_cheat_block_number_global, start_cheat_block_timestamp_global, start_cheat_caller_address,
    start_cheat_proof_facts, stop_cheat_caller_address, store, test_address,
};
use starknet::storage::StoragePointerReadAccess;
use starknet::syscalls::get_class_hash_at_syscall;
use starknet::{ClassHash, ContractAddress, SyscallResultTrait, get_block_number, get_tx_info};
use m31_pool::assets::{IAssetReceiverSafeDispatcher, IAssetReceiverSafeDispatcherTrait};
use m31_pool::hash::{COMPRESS, key, node, read_digest};
use m31_pool::open_note::{COMPUTE, ExecutionIntent, INVOKE, OpenDestination, hash_intent_of};
use m31_pool::policy::{FIXED, PolicySpend, policy_binding};
use m31_pool::policy_escrow::{IPolicyEscrowDispatcher, IPolicyEscrowDispatcherTrait};
use m31_pool::pool_v3::M31PoolV3::{
    Cancelled, Event, OwnershipTransferStarted, OwnershipTransferred, Proposed, ShadowClassSet, VerifierChanged,
};
use m31_pool::pool_v3::{
    IM31PoolV3Dispatcher, IM31PoolV3DispatcherTrait, IM31PoolV3SafeDispatcher, IM31PoolV3SafeDispatcherTrait, P1,
    Parameters, R0,
};
use m31_pool::routing_adapter::Route;
use m31_pool::spend::{IERC20Dispatcher, IERC20DispatcherTrait, Output, Withdrawal};
use m31_pool::spend5::{Spend, compute_binding};
use m31_pool::test_adapters::{IFeeOnTopDispatcher, IFeeOnTopDispatcherTrait, Proceeds};
use m31_pool::test_nft::{IMintDispatcher, IMintDispatcherTrait};
use m31_pool::tree_v3::m31_tree_v3_component::M31TreeInternalTrait;
use m31_pool::tree_v3::{IM31TreeV3Dispatcher, IM31TreeV3DispatcherTrait, node_c, zero_c};
use m31_pool::zeros::zero;
use super::binding_v5_vectors::vectors;
use super::vectors::{EMPTY_ROOT_COMPRESS, leaves, roots_compress};

const E: u64 = 1500;
const Q: u64 = 100;
const W: u64 = 4096;
const T: u64 = 86400;
const START: u64 = 1000;
const NOW: u64 = 1000000;
const RECIPIENT: felt252 = 0xb0b;
const ARBITER: felt252 = 0xa4b1;
const STRANGER: felt252 = 0x5742;

fn deploy(name: ByteArray, data: Array<felt252>) -> ContractAddress {
    let (address, _) = declare(name).unwrap_syscall().contract_class().deploy(@data).unwrap_syscall();
    address
}
fn pool_args(owner: ContractAddress, store_nodes: bool, e: u64, q: u64, w: u64, t: u64) -> Array<felt252> {
    array![owner.into(), store_nodes.into(), e.into(), q.into(), w.into(), t.into()]
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
fn at_block(b: u64) {
    start_cheat_block_number_global(b);
}
/// The SDK's `valid_until = ceil((latest + E) / Q) · Q` (spec §8.2).
fn sdk_valid_until(latest: u64) -> u64 {
    (latest + E + Q - 1) / Q * Q
}
/// The first felt of a revert's panic data.
fn reason<T, +Drop<T>>(r: Result<T, Array<felt252>>) -> felt252 {
    match r {
        Ok(_) => panic!("expected a revert"),
        Err(data) => *data.at(0),
    }
}

#[derive(Drop, Copy)]
struct Env {
    pool: IM31PoolV3Dispatcher,
    safe: IM31PoolV3SafeDispatcher,
    tree: IM31TreeV3Dispatcher,
    erc20: IERC20Dispatcher,
}

/// A pool deployed, not yet initialized, at block `START` and time `NOW`.
fn fresh(store_nodes: bool) -> Env {
    at_block(START);
    start_cheat_block_timestamp_global(NOW);
    let pool = deploy("M31PoolV3", pool_args(test_address(), store_nodes, E, Q, W, T));
    let erc20 = IERC20Dispatcher { contract_address: deploy("E2EToken", array![test_address().into(), 1000000, 0]) };
    erc20.approve(pool, 1000000);
    Env {
        pool: IM31PoolV3Dispatcher { contract_address: pool }, safe: IM31PoolV3SafeDispatcher { contract_address: pool },
        tree: IM31TreeV3Dispatcher { contract_address: pool }, erc20,
    }
}
/// Initialized with accepting mock verifiers, and 1000 of the ERC20 deposited.
fn env_with(store_nodes: bool) -> Env {
    let e = fresh(store_nodes);
    e.pool.initialize(deploy("MockVerifier", array![1]), deploy("MockVerifier", array![1]), array![].span());
    e.pool.deposit(e.erc20.contract_address, 1000, digest(7), payload(1));
    e
}
/// Allowlists a shadow class through the timelock.
fn allow_shadow(e: Env, class_hash: ClassHash) {
    e.pool.propose(class_hash.into(), 1);
    start_cheat_block_timestamp_global(NOW + T);
    e.pool.apply(class_hash.into());
    start_cheat_block_timestamp_global(NOW);
}
fn env() -> Env {
    env_with(true)
}

/// A V5 spend on the current root, expiring as the SDK sets it for this block.
fn spend(e: Env, nf_seed: felt252, asset: felt252, recipient: felt252, amount: u128) -> Spend {
    let mut nfs = array![];
    nfs.append_span(digest(nf_seed));
    nfs.append_span(digest(nf_seed + 100));
    let out = |j: felt252| Output { commitment: digest(nf_seed + 500 + 100 * j), ciphertext: payload(j + 2) };
    let mut sp = Spend {
        chain: get_tx_info().unbox().chain_id, pool: e.pool.contract_address, asset, root: e.tree.get_root(),
        nullifiers: nfs.span(), outputs: array![out(0), out(1)].span(),
        withdrawal: Withdrawal { recipient: addr(recipient), amount }, intent: 0, identity: zeros(),
        valid_until: sdk_valid_until(get_block_number()), binding: 0,
    };
    sp.binding = compute_binding(@sp);
    sp
}
fn transfer(e: Env, nf_seed: felt252) -> Spend {
    spend(e, nf_seed, 0, 0, 0)
}
fn withdraw(e: Env, nf_seed: felt252, amount: u128) -> Spend {
    spend(e, nf_seed, e.erc20.contract_address.into(), RECIPIENT, amount)
}
fn rebind(mut sp: Spend) -> Spend {
    sp.binding = compute_binding(@sp);
    sp
}
fn with_valid_until(mut sp: Spend, valid_until: u64) -> Spend {
    sp.valid_until = valid_until;
    rebind(sp)
}

fn swap_calldata(in_token: ContractAddress, in_amount: u128, proceeds: Array<Proceeds>) -> Span<felt252> {
    let mut data = array![];
    in_token.serialize(ref data);
    in_amount.serialize(ref data);
    proceeds.span().serialize(ref data);
    data.span()
}
/// An INVOKE execution: a budget of the ERC20 to `adapter`, proceeds of `out_token` into one open note.
fn swap(e: Env, nf_seed: felt252, adapter: ContractAddress, budget: u128, out_token: ContractAddress, out_amount: u128) -> (Spend, ExecutionIntent) {
    let intent = ExecutionIntent {
        kind: INVOKE, adapter, nonce: 0, expiry: 1000000,
        calldata: swap_calldata(e.erc20.contract_address, budget, array![Proceeds { note_id: 77, token: out_token, amount: out_amount }]),
        destinations: array![OpenDestination { note_id: 77, token: out_token, minimum: 1, inner: digest(900), ciphertext: payload(9) }].span(),
    };
    bind_intent(spend(e, nf_seed, e.erc20.contract_address.into(), adapter.into(), budget), intent)
}
fn bind_intent(mut sp: Spend, intent: ExecutionIntent) -> (Spend, ExecutionIntent) {
    sp.intent = hash_intent_of(sp.chain, sp.pool.into(), sp.asset, sp.withdrawal, @intent);
    (rebind(sp), intent)
}
#[starknet::interface]
trait IFaucet<T> {
    fn faucet(ref self: T, to: ContractAddress, amount: u256);
}
fn out_token_funding(adapter: ContractAddress, amount: u256) -> ContractAddress {
    let b = deploy("E2EToken", array![test_address().into(), 1000000, 0]);
    IFaucetDispatcher { contract_address: b }.faucet(adapter, amount);
    b
}

// ---------------------------------------------------------------- bootstrap (§8.4)

#[test]
fn constructor_checks_its_parameters() {
    let class = declare("M31PoolV3").unwrap_syscall().contract_class();
    let me = test_address();
    let fails = |args: Array<felt252>| {
        match class.deploy(@args) {
            Ok(_) => panic!("expected a failed deployment"),
            Err(data) => *data.at(0),
        }
    };
    assert_eq!(fails(pool_args(addr(0), true, E, Q, W, T)), 'ZERO_OWNER');
    assert_eq!(fails(pool_args(me, true, E, 0, W, T)), 'EXPIRY_RULES');
    assert_eq!(fails(pool_args(me, true, 0x100000000, Q, 0x200000000, T)), 'EXPIRY_RULES');
    assert_eq!(fails(pool_args(me, true, E, Q, E + Q - 1, T)), 'ROOT_WINDOW');
    assert_eq!(fails(pool_args(me, true, 0, 1, 0x100000000, T)), 'ROOT_WINDOW');
    assert_eq!(fails(pool_args(me, true, E, Q, W, 0)), 'TIMELOCK');
    // `W = E + Q` is the smallest window; the constructor names the owner in an event.
    let mut spy = spy_events();
    let (pool, _) = class.deploy(@pool_args(me, false, E, Q, E + Q, T)).unwrap_syscall();
    spy.assert_emitted(@array![(pool, Event::OwnershipTransferred(OwnershipTransferred { previous_owner: addr(0), new_owner: me }))]);
    let p = IM31PoolV3Dispatcher { contract_address: pool };
    assert_eq!(p.get_parameters(), Parameters { expiry_window: E, quantum: Q, root_window: E + Q, timelock: T });
    assert_eq!(p.get_owner(), me);
    assert_eq!(p.get_verifier(R0), addr(0));
    assert_eq!(p.get_verifier(P1), addr(0));
}

#[test]
#[feature("safe_dispatcher")]
fn nothing_enters_before_initialize() {
    let e = fresh(true);
    assert_eq!(reason(e.safe.deposit(e.erc20.contract_address, 10, digest(7), payload(1))), 'NOT_INITIALIZED');
    assert_eq!(reason(e.safe.apply_spend(transfer(e, 1000), array![].span())), 'NOT_INITIALIZED');
    let (sp, intent) = swap(e, 2000, addr(0x5a), 10, e.erc20.contract_address, 1);
    assert_eq!(reason(e.safe.apply_spend_with_invoke(sp, intent, array![].span())), 'NOT_INITIALIZED');
    let (policy, _) = policy_spend(e, 3000, addr(0x1));
    assert_eq!(
        reason(e.safe.apply_policy_spend(policy, array![].span(), array![array![].span(), array![].span()].span(), array![].span())),
        'NOT_INITIALIZED',
    );
    let hooks = IAssetReceiverSafeDispatcher { contract_address: e.pool.contract_address };
    let mut data = array![];
    data.append_span(digest(1));
    data.append_span(payload(1));
    assert_eq!(reason(hooks.on_erc721_received(test_address(), test_address(), 1, data.span())), 'NOT_INITIALIZED');
    assert_eq!(reason(hooks.on_erc1155_received(test_address(), test_address(), 1, 1, data.span())), 'NOT_INITIALIZED');
    assert_eq!(reason(e.safe.propose(R0, 0x1)), 'NOT_INITIALIZED');
}

#[test]
#[feature("safe_dispatcher")]
fn initialize_once_by_the_owner() {
    let e = fresh(true);
    let r0 = deploy("MockVerifier", array![1]);
    let p1 = deploy("MockVerifier", array![1]);
    let shadow: ClassHash = 0x5ad0.try_into().unwrap();
    let none = array![].span();
    start_cheat_caller_address(e.pool.contract_address, addr(STRANGER));
    assert_eq!(reason(e.safe.initialize(r0, p1, none)), 'NOT_OWNER');
    stop_cheat_caller_address(e.pool.contract_address);
    assert_eq!(reason(e.safe.initialize(addr(0), p1, none)), 'ZERO_VERIFIER');
    assert_eq!(reason(e.safe.initialize(r0, addr(0), none)), 'ZERO_VERIFIER');
    assert_eq!(reason(e.safe.initialize(r0, p1, array![0.try_into().unwrap()].span())), 'ZERO_CLASS');
    // Both verifiers and the first allowlist, with their events.
    let mut spy = spy_events();
    e.pool.initialize(r0, p1, array![shadow].span());
    let pool = e.pool.contract_address;
    spy.assert_emitted(@array![
        (pool, Event::VerifierChanged(VerifierChanged { kind: R0, verifier: r0 })),
        (pool, Event::VerifierChanged(VerifierChanged { kind: P1, verifier: p1 })),
        (pool, Event::ShadowClassSet(ShadowClassSet { class_hash: shadow, allowed: true })),
    ]);
    assert_eq!(e.pool.get_verifier(R0), r0);
    assert_eq!(e.pool.get_verifier(P1), p1);
    assert!(e.pool.is_shadow_class(shadow));
    assert_eq!(reason(e.safe.initialize(r0, p1, none)), 'INITIALIZED');
    // Deposits open.
    e.pool.deposit(e.erc20.contract_address, 10, digest(7), payload(1));
    assert_eq!(e.tree.get_leaf_count(), 1);
}

/// Defence in depth: `initialize` refuses a non-empty tree (unreachable without a storage write,
/// since deposits wait for it).
#[test]
#[should_panic(expected: 'TREE_NOT_EMPTY')]
fn initialize_requires_an_empty_tree() {
    let e = fresh(true);
    store(e.pool.contract_address, selector!("tree_count"), array![1].span());
    e.pool.initialize(deploy("MockVerifier", array![1]), deploy("MockVerifier", array![1]), array![].span());
}

// ---------------------------------------------------------------- timelock (§8.4)

#[test]
#[feature("safe_dispatcher")]
fn timelock_for_each_verifier() {
    let e = env();
    let pool = e.pool.contract_address;
    for kind in array![R0, P1] {
        let original = e.pool.get_verifier(kind);
        let a: felt252 = deploy("MockVerifier", array![1]).into();
        let b: felt252 = deploy("MockVerifier", array![1]).into();
        start_cheat_block_timestamp_global(NOW);
        let mut spy = spy_events();
        // Propose: pending with its eta; the current verifier is unchanged.
        e.pool.propose(kind, a);
        spy.assert_emitted(@array![(pool, Event::Proposed(Proposed { key: kind, value: a, eta: NOW + T }))]);
        assert_eq!(e.pool.get_proposal(kind), (a, NOW + T));
        assert_eq!(e.pool.get_verifier(kind), original);
        // Not before eta.
        start_cheat_block_timestamp_global(NOW + T - 1);
        assert_eq!(reason(e.safe.apply(kind)), 'TIMELOCK');
        // Cancel: nothing pending, nothing to apply.
        e.pool.cancel(kind);
        spy.assert_emitted(@array![(pool, Event::Cancelled(Cancelled { key: kind, value: a }))]);
        assert_eq!(e.pool.get_proposal(kind), (0, 0));
        start_cheat_block_timestamp_global(NOW + T);
        assert_eq!(reason(e.safe.apply(kind)), 'NO_PROPOSAL');
        assert_eq!(reason(e.safe.cancel(kind)), 'NO_PROPOSAL');
        // Re-propose: a fresh eta from now. A newer proposal replaces a pending one, with a fresh
        // eta and a `Cancelled` event for the one it replaces (AB-PV3).
        e.pool.propose(kind, a);
        assert_eq!(e.pool.get_proposal(kind), (a, NOW + 2 * T));
        start_cheat_block_timestamp_global(NOW + T + 10);
        let mut replaced = spy_events();
        e.pool.propose(kind, b);
        replaced.assert_emitted(@array![
            (pool, Event::Cancelled(Cancelled { key: kind, value: a })),
            (pool, Event::Proposed(Proposed { key: kind, value: b, eta: NOW + 2 * T + 10 })),
        ]);
        start_cheat_block_timestamp_global(NOW + 2 * T);
        assert_eq!(reason(e.safe.apply(kind)), 'TIMELOCK');
        // Applied at eta.
        start_cheat_block_timestamp_global(NOW + 2 * T + 10);
        e.pool.apply(kind);
        spy.assert_emitted(@array![(pool, Event::VerifierChanged(VerifierChanged { kind, verifier: b.try_into().unwrap() }))]);
        assert_eq!(e.pool.get_verifier(kind).into(), b);
        assert_eq!(e.pool.get_proposal(kind), (0, 0));
    }
    // Owner only; verifiers must be addresses; unknown kinds have no verifier.
    start_cheat_caller_address(pool, addr(STRANGER));
    assert_eq!(reason(e.safe.propose(R0, 0x1)), 'NOT_OWNER');
    assert_eq!(reason(e.safe.apply(R0)), 'NOT_OWNER');
    assert_eq!(reason(e.safe.cancel(R0)), 'NOT_OWNER');
    stop_cheat_caller_address(pool);
    assert_eq!(reason(e.safe.propose(P1, 0)), 'ZERO_VERIFIER');
    assert_eq!(reason(e.safe.propose(P1, 0x800000000000000000000000000000000000000000000000000000000000000)), 'VERIFIER_ADDRESS');
    assert_eq!(reason(e.safe.get_verifier('R1')), 'VERIFIER_KIND');
}

/// A due proposal applies from `eta` until `eta + T`, then lapses (AB-PV2).
#[test]
#[feature("safe_dispatcher")]
fn proposals_lapse_after_a_second_period() {
    let e = env();
    let v: felt252 = deploy("MockVerifier", array![1]).into();
    e.pool.propose(R0, v);
    start_cheat_block_timestamp_global(NOW + 2 * T + 1);
    assert_eq!(reason(e.safe.apply(R0)), 'PROPOSAL_LAPSED');
    // Still pending until cancelled or replaced; re-proposing restarts the clock.
    assert_eq!(e.pool.get_proposal(R0), (v, NOW + T));
    e.pool.propose(R0, v);
    start_cheat_block_timestamp_global(NOW + 4 * T + 1);
    e.pool.apply(R0);
    assert_eq!(e.pool.get_verifier(R0).into(), v);
}

/// The shadow-class allowlist takes the same timelock (AB-PV1): allowing closes INVOKE to the
/// class and opens COMPUTE, so neither happens without notice.
#[test]
#[feature("safe_dispatcher")]
fn shadow_classes_take_the_timelock() {
    let e = env();
    let pool = e.pool.contract_address;
    let class_hash: ClassHash = 0x5ad0.try_into().unwrap();
    let k: felt252 = class_hash.into();
    let mut spy = spy_events();
    e.pool.propose(k, 1);
    spy.assert_emitted(@array![(pool, Event::Proposed(Proposed { key: k, value: 1, eta: NOW + T }))]);
    assert!(!e.pool.is_shadow_class(class_hash));
    start_cheat_block_timestamp_global(NOW + T - 1);
    assert_eq!(reason(e.safe.apply(k)), 'TIMELOCK');
    start_cheat_block_timestamp_global(NOW + T);
    e.pool.apply(k);
    spy.assert_emitted(@array![(pool, Event::ShadowClassSet(ShadowClassSet { class_hash, allowed: true }))]);
    assert!(e.pool.is_shadow_class(class_hash));
    // Disallowing takes it too.
    e.pool.propose(k, 0);
    assert_eq!(e.pool.get_proposal(k), (0, NOW + 2 * T));
    assert_eq!(reason(e.safe.apply(k)), 'TIMELOCK');
    assert!(e.pool.is_shadow_class(class_hash));
    start_cheat_block_timestamp_global(NOW + 2 * T);
    e.pool.apply(k);
    assert!(!e.pool.is_shadow_class(class_hash));
    // A value is 0 or 1; zero is no class; owner only.
    assert_eq!(reason(e.safe.propose(k, 2)), 'SHADOW_VALUE');
    assert_eq!(reason(e.safe.propose(0, 1)), 'ZERO_CLASS');
    start_cheat_caller_address(pool, addr(STRANGER));
    assert_eq!(reason(e.safe.propose(k, 1)), 'NOT_OWNER');
}

/// An applied verifier decides from then on, for both relations.
#[test]
#[feature("safe_dispatcher")]
fn applied_verifiers_decide() {
    let e = env();
    let reject: felt252 = deploy("MockVerifier", array![0]).into();
    e.pool.propose(R0, reject);
    e.pool.propose(P1, reject);
    // Until eta, the old verifiers still accept.
    e.pool.apply_spend(transfer(e, 1000), array![].span());
    start_cheat_block_timestamp_global(NOW + T);
    e.pool.apply(R0);
    e.pool.apply(P1);
    assert_eq!(reason(e.safe.apply_spend(transfer(e, 2000), array![].span())), 'PROOF_REJECTED');
    let (policy, data) = policy_spend(e, 3000, escrow_for(e));
    assert_eq!(
        reason(e.safe.apply_policy_spend(policy, data, array![array![].span(), array![].span()].span(), array![].span())),
        'PROOF_REJECTED',
    );
}

// ---------------------------------------------------------------- ownership (§8.4)

#[test]
#[feature("safe_dispatcher")]
fn ownership_moves_in_two_steps() {
    let e = env();
    let pool = e.pool.contract_address;
    let me = test_address();
    let next = addr(0x0e1);
    // Only the owner starts a transfer (AB-PV4).
    start_cheat_caller_address(pool, addr(STRANGER));
    assert_eq!(reason(e.safe.transfer_ownership(addr(STRANGER))), 'NOT_OWNER');
    stop_cheat_caller_address(pool);
    let mut spy = spy_events();
    e.pool.transfer_ownership(next);
    spy.assert_emitted(@array![(pool, Event::OwnershipTransferStarted(OwnershipTransferStarted { previous_owner: me, new_owner: next }))]);
    assert_eq!(e.pool.get_owner(), me);
    assert_eq!(e.pool.get_pending_owner(), next);
    // The pending owner has no rights yet; only it can accept.
    start_cheat_caller_address(pool, next);
    assert_eq!(reason(e.safe.propose(R0, 0x1)), 'NOT_OWNER');
    start_cheat_caller_address(pool, addr(STRANGER));
    assert_eq!(reason(e.safe.accept_ownership()), 'NOT_PENDING_OWNER');
    start_cheat_caller_address(pool, next);
    e.pool.accept_ownership();
    spy.assert_emitted(@array![(pool, Event::OwnershipTransferred(OwnershipTransferred { previous_owner: me, new_owner: next }))]);
    assert_eq!(e.pool.get_owner(), next);
    assert_eq!(e.pool.get_pending_owner(), addr(0));
    e.pool.propose(R0, 0x1);
    // A zero transfer cancels a pending one.
    e.pool.transfer_ownership(me);
    e.pool.transfer_ownership(addr(0));
    stop_cheat_caller_address(pool);
    assert_eq!(reason(e.safe.accept_ownership()), 'NOT_PENDING_OWNER');
    assert_eq!(reason(e.safe.propose(R0, 0x1)), 'NOT_OWNER');
    start_cheat_caller_address(pool, addr(0));
    assert_eq!(reason(e.safe.accept_ownership()), 'NOT_PENDING_OWNER');
}

// ---------------------------------------------------------------- roots (§8.3, F02)

/// A quiet pool never freezes: the current root stays accepted however long nothing lands.
#[test]
fn current_root_accepted_after_a_long_idle() {
    let e = env();
    let root = e.tree.get_root();
    at_block(START + 3 * W + 7);
    let sp = transfer(e, 1000);
    assert!(sp.root == root);
    e.pool.apply_spend(sp, array![].span());
}

/// A replaced root is accepted for exactly `W` blocks after the block that replaced it.
#[test]
#[feature("safe_dispatcher")]
fn replaced_root_window_boundary() {
    let e = env();
    let root = e.tree.get_root();
    assert_eq!(e.tree.get_root_superseded_at(root), 0);
    let replaced = START + 5;
    at_block(replaced);
    e.pool.deposit(e.erc20.contract_address, 10, digest(8), payload(1));
    assert_eq!(e.tree.get_root_superseded_at(root), replaced + 1);
    assert!(e.tree.root_is_known(root));
    at_block(replaced + W);
    assert!(e.tree.root_is_known(root));
    let mut sp = transfer(e, 1000);
    sp.root = root;
    e.pool.apply_spend(rebind(sp), array![].span());
    at_block(replaced + W + 1);
    assert!(!e.tree.root_is_known(root));
    let mut sp = transfer(e, 2000);
    sp.root = root;
    assert_eq!(reason(e.safe.apply_spend(rebind(sp), array![].span())), 'UNKNOWN_ROOT');
    // A root never recorded is unknown.
    let mut sp = transfer(e, 3000);
    sp.root = digest(123);
    assert_eq!(reason(e.safe.apply_spend(rebind(sp), array![].span())), 'UNKNOWN_ROOT');
}

/// Junk appends cannot age a root out: 258 appends in one block (V2's ring held 256) leave the
/// first root accepted (F02's flush).
#[test]
fn junk_appends_do_not_age_a_root() {
    let e = env_with(false);
    let root = e.tree.get_root();
    for i in 0..129_u32 {
        let seed: felt252 = (10000 + 1000 * i).into();
        e.pool.apply_spend(transfer(e, seed), array![].span());
    }
    assert_eq!(e.tree.get_leaf_count(), 1 + 258);
    let mut sp = withdraw(e, 5, 100);
    sp.root = root;
    e.pool.apply_spend(rebind(sp), array![].span());
    assert_eq!(e.erc20.balance_of(addr(RECIPIENT)), 100);
}

/// A policy escrow over the ERC20, approved by the arbiter for outcome 1 (pay 1 unit to RECIPIENT).
fn escrow_for(e: Env) -> ContractAddress {
    let escrow = deploy("PolicyEscrow", array![e.pool.contract_address.into()]);
    start_cheat_caller_address(escrow, addr(ARBITER));
    IPolicyEscrowDispatcher { contract_address: escrow }.approve(key(read_digest(digest(61))), 1);
    stop_cheat_caller_address(escrow);
    escrow
}
fn policy_spend(e: Env, nf_seed: felt252, escrow: ContractAddress) -> (PolicySpend, Span<felt252>) {
    let class: felt252 = get_class_hash_at_syscall(escrow).unwrap_syscall().into();
    let mut cms = array![];
    cms.append_span(zeros());
    cms.append_span(zeros());
    let mut sp = PolicySpend {
        chain: get_tx_info().unbox().chain_id, pool: e.pool.contract_address, token: e.erc20.contract_address,
        root: e.tree.get_root(), nullifier: digest(nf_seed), commitments: cms.span(), delivery0: 0, delivery1: 0,
        withdrawal: Withdrawal { recipient: addr(RECIPIENT), amount: 1 }, controller: escrow, controller_class: class,
        handle: ARBITER, policy_id: digest(61), deadline: 1000000, not_before: 0, index: 1, kind: FIXED, x: 0,
        data: poseidon_hash_span(array![].span()), binding: 0,
    };
    sp.binding = policy_binding(@sp);
    (sp, array![].span())
}

/// `apply_policy_spend` follows the same root rule (§8.3).
#[test]
#[feature("safe_dispatcher")]
fn policy_spends_use_the_root_rule() {
    let e = env();
    let escrow = escrow_for(e);
    let no_ct = array![array![].span(), array![].span()].span();
    let (stale, data) = policy_spend(e, 3000, escrow);
    let (fresh_, _) = policy_spend(e, 4000, escrow);
    let replaced = START + 1;
    at_block(replaced);
    e.pool.deposit(e.erc20.contract_address, 10, digest(8), payload(1));
    at_block(replaced + W + 1);
    assert_eq!(reason(e.safe.apply_policy_spend(stale, data, no_ct, array![].span())), 'UNKNOWN_ROOT');
    at_block(replaced + W);
    e.pool.apply_policy_spend(fresh_, data, no_ct, array![].span());
    assert_eq!(e.erc20.balance_of(addr(RECIPIENT)), 1);
}

/// The P1 path through a routing adapter (`docs/pool-v3-spec.md` §6, §9.2): with a P1 routing
/// adapter in the pool's P1 slot, `apply_policy_spend` settles on facts of the route's statement
/// emitting `[class, 'TMPZP1_POLICY_V1', chain, pool, policy_binding(spend)]`. An R0 V6 message,
/// a wrong binding and a proof older than the route's age are refused, and the good facts still
/// settle afterwards.
#[test]
#[feature("safe_dispatcher")]
fn policy_spends_through_a_p1_routing_adapter() {
    let e = fresh(true);
    let statement = deploy("MockVerifier", array![1]);
    let class: felt252 = get_class_hash_at_syscall(statement).unwrap_syscall().into();
    let route = Route {
        statement, statement_class: class, account_tag: 'TMPZP1_POLICY_V1', os_program: 0x05, proof_version: 'PROOF2',
        proof_variant: 'VIRTUAL_SNOS', output_version: 'VIRTUAL_SNOS0', max_proof_age: 50,
    };
    let mut args = array![e.pool.contract_address.into(), P1];
    array![route].span().serialize(ref args);
    let adapter = deploy("RoutingAdapter", args);
    e.pool.initialize(deploy("MockVerifier", array![0]), adapter, array![].span());
    e.pool.deposit(e.erc20.contract_address, 1000, digest(7), payload(1));
    let escrow = escrow_for(e);
    let no_ct = array![array![].span(), array![].span()].span();
    let (sp, data) = policy_spend(e, 3000, escrow);
    let chain = get_tx_info().unbox().chain_id;
    let facts = |tag: felt252, binding: felt252, base: u64| -> Span<felt252> {
        let message = array![statement.into(), 0, 5, class, tag, chain, e.pool.contract_address.into(), binding];
        array!['PROOF2', 'VIRTUAL_SNOS', 0x05, 'VIRTUAL_SNOS0', base.into(), 0xb10c, 0, 1, poseidon_hash_span(message.span())]
            .span()
    };
    let (base, binding) = (START - 10, sp.binding);
    // The same spend each attempt (`policy_spend` is deterministic).
    let again = || {
        let (s, _) = policy_spend(e, 3000, escrow);
        s
    };
    start_cheat_proof_facts(adapter, facts('TMPZR0_PAYMENT_V6', binding, base));
    assert_eq!(reason(e.safe.apply_policy_spend(again(), data, no_ct, array![].span())), 'NO_ROUTE');
    start_cheat_proof_facts(adapter, facts('TMPZP1_POLICY_V1', binding + 1, base));
    assert_eq!(reason(e.safe.apply_policy_spend(again(), data, no_ct, array![].span())), 'NO_ROUTE');
    start_cheat_proof_facts(adapter, facts('TMPZP1_POLICY_V1', binding, START - 51));
    assert_eq!(reason(e.safe.apply_policy_spend(again(), data, no_ct, array![].span())), 'PROOF_AGE');
    start_cheat_proof_facts(adapter, facts('TMPZP1_POLICY_V1', binding, START - 50));
    e.pool.apply_policy_spend(sp, data, no_ct, array![].span());
    assert_eq!(e.erc20.balance_of(addr(RECIPIENT)), 1);
}

// ---------------------------------------------------------------- expiry (§8.2, F07)

#[test]
#[feature("safe_dispatcher")]
fn expiry_boundaries() {
    let e = env();
    // Landing at `valid_until` itself.
    at_block(1000);
    e.pool.apply_spend(with_valid_until(transfer(e, 1000), 1000), array![].span());
    // One block later.
    at_block(1001);
    assert_eq!(reason(e.safe.apply_spend(with_valid_until(transfer(e, 2000), 1000), array![].span())), 'SPEND_EXPIRED');
    // Off the grid.
    assert_eq!(reason(e.safe.apply_spend(with_valid_until(transfer(e, 2000), 1050), array![].span())), 'VALID_UNTIL_GRID');
    // `block + E + Q` is the farthest: 2600 ≤ 1001 + 1600; the next grid point is not.
    e.pool.apply_spend(with_valid_until(transfer(e, 2000), 2600), array![].span());
    assert_eq!(reason(e.safe.apply_spend(with_valid_until(transfer(e, 3000), 2700), array![].span())), 'VALID_UNTIL_AHEAD');
    at_block(1000);
    e.pool.apply_spend(with_valid_until(transfer(e, 3000), 2600), array![].span());
    assert_eq!(reason(e.safe.apply_spend(with_valid_until(transfer(e, 4000), 2700), array![].span())), 'VALID_UNTIL_AHEAD');
    // Zero never lands, even at block 0 (the bridge also rejects it).
    at_block(0);
    assert_eq!(reason(e.safe.apply_spend(with_valid_until(transfer(e, 4000), 0), array![].span())), 'SPEND_EXPIRED');
}

/// The SDK's `valid_until` lands from the block it was computed at through `valid_until` itself.
#[test]
fn sdk_valid_until_lands_through_its_window() {
    let e = env();
    let mut seed: felt252 = 10000;
    for latest in array![1000_u64, 1001, 1099, 1100, 123456] {
        at_block(latest);
        let vu = sdk_valid_until(latest);
        assert!(vu % Q == 0 && vu >= latest + E && vu <= latest + E + Q);
        e.pool.apply_spend(transfer(e, seed), array![].span());
        let late = transfer(e, seed + 1000);
        at_block(vu);
        e.pool.apply_spend(late, array![].span());
        seed += 10000;
    }
}

#[test]
#[should_panic(expected: 'SPEND_EXPIRED')]
fn invoke_spends_expire_too() {
    let e = env();
    let adapter = deploy("MockSwapAdapter", array![]);
    let b = out_token_funding(adapter, 500);
    let (sp, intent) = swap(e, 1000, adapter, 40, b, 480);
    at_block(sp.valid_until + 1);
    e.pool.apply_spend_with_invoke(sp, intent, array![].span());
}

// ---------------------------------------------------------------- binding (§5.2)

/// The pool's binding equals the Python reference's (`gen_binding_v5_kat.py`), which reproduces
/// the starknet.js KAT and the bridge's binding on every real proof.
#[test]
fn binding_matches_the_reference() {
    for (name, sp) in vectors() {
        assert!(compute_binding(@sp) == sp.binding, "{}", name);
    }
}

/// Every field of the spend changes the binding, `valid_until` included.
#[test]
fn every_field_is_bound() {
    let e = env();
    let adapter: felt252 = 0xada;
    let base = || {
        let mut sp = spend(e, 1000, e.erc20.contract_address.into(), adapter, 40);
        sp.intent = 0x1234;
        sp.identity = digest(40);
        sp
    };
    let b = compute_binding(@base());
    let mut n = 0;
    for field in 0..17_u32 {
        let mut v = base();
        let o0 = v.outputs.at(0);
        let o1 = v.outputs.at(1);
        let (c0, t0, c1, t1) = (*o0.commitment, *o0.ciphertext, *o1.commitment, *o1.ciphertext);
        let set = |c0, t0, c1, t1| array![Output { commitment: c0, ciphertext: t0 }, Output { commitment: c1, ciphertext: t1 }].span();
        match field {
            0 => v.chain += 1,
            1 => v.pool = addr(v.pool.into() + 1),
            2 => v.asset += 1,
            3 => v.root = bump(v.root, 8),
            4 => v.nullifiers = bump(v.nullifiers, 0),
            5 => v.nullifiers = bump(v.nullifiers, 17),
            6 => v.outputs = set(bump(c0, 3), t0, c1, t1),
            7 => v.outputs = set(c0, t0, bump(c1, 8), t1),
            8 => v.outputs = set(c0, bump(t0, 9), c1, t1),
            9 => v.outputs = set(c0, t0, c1, bump(t1, 0)),
            10 => v.outputs = set(c1, t1, c0, t0),
            11 => v.withdrawal = Withdrawal { recipient: addr(adapter + 1), amount: 40 },
            12 => v.withdrawal = Withdrawal { recipient: addr(adapter), amount: 41 },
            13 => v.intent += 1,
            14 => v.identity = bump(v.identity, 4),
            15 => v.valid_until += Q,
            _ => v.valid_until -= Q,
        }
        assert!(compute_binding(@v) != b, "field {} is not bound", field);
        n += 1;
    }
    assert_eq!(n, 17);
}
fn bump(words: Span<felt252>, i: u32) -> Span<felt252> {
    let mut out = array![];
    for k in 0..words.len() {
        out.append(if k == i { *words.at(k) + 1 } else { *words.at(k) });
    }
    out.span()
}

/// The pool recomputes the binding: a spend whose `valid_until` moved (still on the grid and in
/// range) no longer matches the proof's binding.
#[test]
#[should_panic(expected: 'BAD_BINDING')]
fn valid_until_is_bound_at_the_pool() {
    let e = env();
    let mut sp = transfer(e, 1000);
    sp.valid_until = sp.valid_until - Q;
    e.pool.apply_spend(sp, array![].span());
}

// ---------------------------------------------------------------- no fees, no gating (§8.6)

/// A fresh account deposits and an unrelated account submits the spend: nothing checks who.
#[test]
fn any_account_deposits_and_any_account_submits() {
    let e = env();
    let pool = e.pool.contract_address;
    let fresh_account = addr(0xf2e54);
    let submitter = addr(0x7417d);
    IFaucetDispatcher { contract_address: e.erc20.contract_address }.faucet(fresh_account, 500);
    start_cheat_caller_address(e.erc20.contract_address, fresh_account);
    e.erc20.approve(pool, 500);
    stop_cheat_caller_address(e.erc20.contract_address);
    start_cheat_caller_address(pool, fresh_account);
    e.pool.deposit(e.erc20.contract_address, 500, digest(70), payload(3));
    stop_cheat_caller_address(pool);
    assert_eq!(e.erc20.balance_of(fresh_account), 0);
    assert_eq!(e.pool.get_held(e.erc20.contract_address.into()), 1500);
    start_cheat_caller_address(pool, submitter);
    e.pool.apply_spend(withdraw(e, 1000, 1500), array![].span());
    stop_cheat_caller_address(pool);
    // The whole amount reaches the recipient; the submitter receives nothing.
    assert_eq!(e.erc20.balance_of(addr(RECIPIENT)), 1500);
    assert_eq!(e.erc20.balance_of(submitter), 0);
    assert_eq!(e.pool.get_held(e.erc20.contract_address.into()), 0);
}

// ---------------------------------------------------------------- the V3 tree (V2's tests, F30)

/// The V3 tree's roots after each golden insert equal the client's compress tree.
fn check_roots(store_nodes: bool) {
    let mut state = m31_pool::pool_v3::M31PoolV3::contract_state_for_testing();
    state.tree.initializer(store_nodes, W);
    let (lo, hi) = state.tree.tree_root.read();
    assert!(m31_pool::hash::unpack(lo, hi).span() == EMPTY_ROOT_COMPRESS.span());
    let roots = roots_compress();
    let mut i = 0;
    for leaf in leaves() {
        state.tree.insert_leaf(leaf);
        let (lo, hi) = state.tree.tree_root.read();
        assert!(m31_pool::hash::unpack(lo, hi).span() == roots.at(i).span());
        assert!(state.tree.root_is_valid(*roots.at(i)));
        i += 1;
    }
}
/// `insert_two` gives the client's roots: single and paired appends mixed, pairs starting at even
/// and odd indices (index 7 = 0b111 meets at level 4).
fn check_batched_roots(store_nodes: bool) {
    let mut state = m31_pool::pool_v3::M31PoolV3::contract_state_for_testing();
    state.tree.initializer(store_nodes, W);
    let roots = roots_compress();
    let l = leaves();
    let steps: Array<(u32, bool)> = array![(0, false), (1, true), (3, false), (4, true), (6, false), (7, true), (9, true), (11, false)];
    for (i, pair) in steps {
        if pair {
            let idx = state.tree.insert_two(*l.at(i), *l.at(i + 1));
            assert_eq!(idx, i.into());
            let (lo, hi) = state.tree.tree_root.read();
            assert!(m31_pool::hash::unpack(lo, hi).span() == roots.at(i + 1).span());
            // The intermediate root of a pair is never recorded.
            assert!(!state.tree.root_is_valid(*roots.at(i)));
        } else {
            state.tree.insert_leaf(*l.at(i));
            let (lo, hi) = state.tree.tree_root.read();
            assert!(m31_pool::hash::unpack(lo, hi).span() == roots.at(i).span());
        }
    }
    assert_eq!(state.tree.tree_count.read(), 12);
}
#[test]
fn v3_tree_roots_match_client_nodes() { check_roots(true); }
#[test]
fn v3_tree_roots_match_client_frontier() { check_roots(false); }
#[test]
fn v3_batched_roots_match_client_nodes() { check_batched_roots(true); }
#[test]
fn v3_batched_roots_match_client_frontier() { check_batched_roots(false); }

/// The V3 tree's compress-only tables equal the shared ones for the compress format (F30).
#[test]
fn compress_tables_match_the_shared_ones() {
    for level in 0..33_u32 {
        assert!(zero_c(level).span() == zero(COMPRESS, level).span());
    }
    let l = *leaves().at(0);
    let r = *leaves().at(1);
    assert!(node_c(0, l, r).span() == node(COMPRESS, 0, l, r).span());
    assert!(node_c(31, r, l).span() == node(COMPRESS, 31, r, l).span());
}

/// Nodes mode serves empty nodes as the compress tree's empty subtrees.
#[test]
fn empty_nodes_are_compress_zeros() {
    let e = env();
    assert!(e.tree.get_node(5, 1000) == zero(COMPRESS, 5).span());
    assert!(e.tree.get_node(32, 0) == e.tree.get_root());
}

// ---------------------------------------------------------------- F17, F18

#[test]
#[should_panic(expected: 'DEPOSIT_AMOUNT')]
fn fee_on_top_deposit_rejected() {
    let e = env();
    let token = deploy("FeeOnTopToken", array![]);
    let fee = IFeeOnTopDispatcher { contract_address: token };
    fee.faucet(test_address(), 1000);
    fee.set_fees(true, false);
    IERC20Dispatcher { contract_address: token }.approve(e.pool.contract_address, 1000);
    e.pool.deposit(token, 100, digest(9), payload(9));
}

#[test]
#[should_panic(expected: 'DEPOSIT_AMOUNT')]
fn fee_on_transfer_deposit_rejected() {
    let e = env();
    let token = deploy("FeeToken", array![]);
    IFaucetDispatcher { contract_address: token }.faucet(test_address(), 1000);
    IERC20Dispatcher { contract_address: token }.approve(e.pool.contract_address, 1000);
    e.pool.deposit(token, 100, digest(9), payload(9));
}

/// A token that starts taking a fee from the pool on transfer cannot pay out (and so cannot pay
/// one holder from another's funds).
#[test]
#[should_panic(expected: 'PAYOUT_AMOUNT')]
fn fee_on_top_payout_rejected() {
    let e = env();
    let token = deploy("FeeOnTopToken", array![]);
    let fee = IFeeOnTopDispatcher { contract_address: token };
    fee.faucet(test_address(), 1000);
    IERC20Dispatcher { contract_address: token }.approve(e.pool.contract_address, 1000);
    e.pool.deposit(token, 100, digest(9), payload(9));
    fee.faucet(e.pool.contract_address, 1);
    fee.set_fees(false, true);
    e.pool.apply_spend(spend(e, 1000, token.into(), RECIPIENT, 50), array![].span());
}

/// Open-note proceeds pulled from the adapter follow F17 as well.
#[test]
#[should_panic(expected: 'OPEN_NOTE_FUNDING')]
fn fee_on_top_open_note_funding_rejected() {
    let e = env();
    let adapter = deploy("MockSwapAdapter", array![]);
    let token = deploy("FeeOnTopToken", array![]);
    let fee = IFeeOnTopDispatcher { contract_address: token };
    fee.faucet(adapter, 1000);
    fee.set_fees(true, false);
    let (sp, intent) = swap(e, 1000, adapter, 40, token, 480);
    e.pool.apply_spend_with_invoke(sp, intent, array![].span());
}

/// An INVOKE cannot target an allowlisted shadow class, which would act for an identity the
/// spend never proved (F18).
#[test]
#[should_panic(expected: 'INVOKE_TARGET')]
fn invoke_cannot_target_a_shadow_class() {
    let e = env();
    let adapter = deploy("MockSwapAdapter", array![]);
    allow_shadow(e, get_class_hash_at_syscall(adapter).unwrap_syscall());
    let b = out_token_funding(adapter, 500);
    let (sp, intent) = swap(e, 1000, adapter, 40, b, 480);
    e.pool.apply_spend_with_invoke(sp, intent, array![].span());
}

/// The INVOKE path end to end on V3: budget paid, proceeds into an open note, `held` for both.
#[test]
fn invoke_funds_an_open_note() {
    let e = env();
    let adapter = deploy("MockSwapAdapter", array![]);
    let b = out_token_funding(adapter, 500);
    let (sp, intent) = swap(e, 1000, adapter, 40, b, 480);
    let before = e.tree.get_leaf_count();
    e.pool.apply_spend_with_invoke(sp, intent, array![].span());
    assert_eq!(e.tree.get_leaf_count(), before + 3);
    assert_eq!(e.pool.get_held(e.erc20.contract_address.into()), 960);
    assert_eq!(e.pool.get_held(b.into()), 480);
    assert_eq!(IERC20Dispatcher { contract_address: b }.balance_of(e.pool.contract_address), 480);
}

/// A COMPUTE execution on an allowlisted shadow class, with the identity handle.
#[test]
fn compute_funds_an_open_note() {
    let e = env();
    let shadow = deploy("MockShadowAnonymizer", array![]);
    allow_shadow(e, get_class_hash_at_syscall(shadow).unwrap_syscall());
    let (sp, intent) = shadow_spend(e, 1000, shadow, digest(40));
    e.pool.apply_spend_with_invoke(sp, intent, array![].span());
    assert_eq!(e.pool.get_held(e.erc20.contract_address.into()), 970);
}
fn shadow_spend(e: Env, nf_seed: felt252, shadow: ContractAddress, identity: Span<felt252>) -> (Spend, ExecutionIntent) {
    let b = out_token_funding(shadow, 500);
    let mut calldata = array![];
    array![Proceeds { note_id: 88, token: b, amount: 250 }].span().serialize(ref calldata);
    let intent = ExecutionIntent {
        kind: COMPUTE, adapter: shadow, nonce: 0, expiry: 1000000, calldata: calldata.span(),
        destinations: array![OpenDestination { note_id: 88, token: b, minimum: 200, inner: digest(600), ciphertext: payload(12) }].span(),
    };
    let mut sp = spend(e, nf_seed, e.erc20.contract_address.into(), shadow.into(), 30);
    sp.identity = identity;
    bind_intent(sp, intent)
}

// ---------------------------------------------------------------- F28: branches on V3

#[test]
#[feature("safe_dispatcher")]
fn spend_guards() {
    let e = env();
    let no = array![].span();
    let asset: felt252 = e.erc20.contract_address.into();
    let mut sp = transfer(e, 1000);
    sp.chain = 'SN_MAIN';
    assert_eq!(reason(e.safe.apply_spend(rebind(sp), no)), 'WRONG_CHAIN');
    let mut sp = transfer(e, 1000);
    sp.pool = addr(0x9001);
    assert_eq!(reason(e.safe.apply_spend(rebind(sp), no)), 'WRONG_POOL');
    let mut sp = transfer(e, 1000);
    let mut nfs = array![];
    nfs.append_span(zeros());
    nfs.append_span(digest(1100));
    sp.nullifiers = nfs.span();
    assert_eq!(reason(e.safe.apply_spend(rebind(sp), no)), 'ZERO_NULLIFIER');
    // The same nullifier twice in one spend.
    let mut sp = transfer(e, 1000);
    let mut nfs = array![];
    nfs.append_span(digest(1000));
    nfs.append_span(digest(1000));
    sp.nullifiers = nfs.span();
    assert_eq!(reason(e.safe.apply_spend(rebind(sp), no)), 'NULLIFIER_USED');
    // Intents and identities need the invoke entry point.
    let mut sp = withdraw(e, 1000, 10);
    sp.intent = 0x1;
    assert_eq!(reason(e.safe.apply_spend(rebind(sp), no)), 'INTENT_NEEDS_INVOKE');
    let mut sp = transfer(e, 1000);
    sp.identity = digest(40);
    assert_eq!(reason(e.safe.apply_spend(rebind(sp), no)), 'INTENT_NEEDS_INVOKE');
    // An exit's asset must be an address.
    let mut sp = withdraw(e, 1000, 10);
    sp.asset = 0x800000000000000000000000000000000000000000000000000000000000000;
    assert_eq!(reason(e.safe.apply_spend(rebind(sp), no)), 'ASSET_RANGE');
    // The exit rule, and a withdrawal's recipient and amount together.
    assert_eq!(reason(e.safe.apply_spend(spend(e, 1000, asset, 0, 0), no)), 'EXIT_RULE');
    assert_eq!(reason(e.safe.apply_spend(spend(e, 1000, 0, RECIPIENT, 10), no)), 'EXIT_RULE');
    assert_eq!(reason(e.safe.apply_spend(spend(e, 1000, 0, RECIPIENT, 0), no)), 'BAD_WITHDRAWAL');
    let mut sp = withdraw(e, 1000, 10);
    sp.binding += 1;
    assert_eq!(reason(e.safe.apply_spend(sp, no)), 'BAD_BINDING');
    assert_eq!(reason(e.safe.apply_spend(withdraw(e, 1000, 1001), no)), 'HELD_UNDERFLOW');
    // All of it rolled back: the nullifier is still fresh.
    assert!(!e.pool.get_nullifier_spent(digest(1000)));
    e.pool.apply_spend(transfer(e, 1000), no);
    assert_eq!(reason(e.safe.apply_spend(transfer(e, 1000), no)), 'NULLIFIER_USED');
}

#[test]
#[feature("safe_dispatcher")]
fn execution_guards() {
    let e = env();
    let no = array![].span();
    let adapter = deploy("MockSwapAdapter", array![]);
    let b = out_token_funding(adapter, 500);
    // The spend's intent must be the one submitted.
    let (sp, mut intent) = swap(e, 1000, adapter, 40, b, 480);
    intent.expiry += 1;
    assert_eq!(reason(e.safe.apply_spend_with_invoke(sp, intent, no)), 'EXECUTION_INTENT');
    let (mut sp, intent) = swap(e, 1000, adapter, 40, b, 480);
    sp.intent = 0;
    assert_eq!(reason(e.safe.apply_spend_with_invoke(rebind(sp), intent, no)), 'EXECUTION_INTENT');
    // The intent's own expiry.
    let (sp, mut intent) = swap(e, 1000, adapter, 40, b, 480);
    intent.expiry = START - 1;
    let (sp, intent) = bind_intent(sp, intent);
    assert_eq!(reason(e.safe.apply_spend_with_invoke(sp, intent, no)), 'EXECUTION_EXPIRED');
    // Never the pool itself, never zero.
    let (sp, mut intent) = swap(e, 1000, adapter, 40, b, 480);
    intent.adapter = e.pool.contract_address;
    let (sp, intent) = bind_intent(sp, intent);
    assert_eq!(reason(e.safe.apply_spend_with_invoke(sp, intent, no)), 'EXECUTION_ADAPTER');
    let (sp, mut intent) = swap(e, 1000, adapter, 40, b, 480);
    intent.adapter = addr(0);
    let (sp, intent) = bind_intent(sp, intent);
    assert_eq!(reason(e.safe.apply_spend_with_invoke(sp, intent, no)), 'EXECUTION_ADAPTER');
    // INVOKE carries no identity; COMPUTE needs one and an allowlisted class.
    let (mut sp, intent) = swap(e, 1000, adapter, 40, b, 480);
    sp.identity = digest(40);
    let (sp, intent) = bind_intent(sp, intent);
    assert_eq!(reason(e.safe.apply_spend_with_invoke(sp, intent, no)), 'IDENTITY_UNEXPECTED');
    let shadow = deploy("MockShadowAnonymizer", array![]);
    let (sp, intent) = shadow_spend(e, 1000, shadow, zeros());
    assert_eq!(reason(e.safe.apply_spend_with_invoke(sp, intent, no)), 'IDENTITY_REQUIRED');
    let (sp, intent) = shadow_spend(e, 1000, shadow, digest(40));
    assert_eq!(reason(e.safe.apply_spend_with_invoke(sp, intent, no)), 'COMPUTE_TARGET');
    // Executions move ERC20 only.
    let nft = deploy("TestERC721", array![]);
    IMintDispatcher { contract_address: nft }.mint(test_address(), 1, 1);
    IERC721SafeTransferDispatcher { contract_address: nft }
        .safe_transfer_from(test_address(), e.pool.contract_address, 1, hook_data(40));
    let asset = m31_pool::assets::asset_id(721, nft, 1);
    let (mut sp, intent) = swap(e, 1000, adapter, 1, b, 480);
    sp.asset = asset;
    let (sp, intent) = bind_intent(sp, intent);
    assert_eq!(reason(e.safe.apply_spend_with_invoke(sp, intent, no)), 'EXECUTION_ASSET');
}
#[starknet::interface]
trait IERC721SafeTransfer<T> {
    fn safe_transfer_from(ref self: T, from: ContractAddress, to: ContractAddress, token_id: u256, data: Span<felt252>);
}
fn hook_data(seed: felt252) -> Span<felt252> {
    let mut d = array![];
    d.append_span(digest(seed));
    d.append_span(payload(seed));
    d.span()
}

/// High indices append; the last free slot takes one note but not two, and a full tree takes none.
#[test]
#[feature("safe_dispatcher")]
fn tree_full() {
    let e = env_with(false);
    store(e.pool.contract_address, selector!("tree_count"), array![0xffffffff].span());
    assert_eq!(reason(e.safe.apply_spend(transfer(e, 1000), array![].span())), 'TREE_FULL');
    e.pool.deposit(e.erc20.contract_address, 10, digest(8), payload(1));
    assert_eq!(e.tree.get_leaf_count(), 0x100000000);
    assert_eq!(reason(e.safe.deposit(e.erc20.contract_address, 10, digest(9), payload(1))), 'TREE_FULL');
    // Spends that append nothing do not exist in V5: every spend appends two outputs.
    assert_eq!(reason(e.safe.apply_spend(withdraw(e, 2000, 10), array![].span())), 'TREE_FULL');
}
