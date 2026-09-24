//! Adversarial open-note settlement tests. The first group comes from the open-note contract
//! review (reviews/open-note-contract-review.md); the rest cover the review fixes (destination
//! validation, zero public nonce, budget recipient) and the remaining guards.
use snforge_std::{ContractClassTrait, DeclareResultTrait, declare, test_address, start_cheat_block_number_global};
use starknet::{ContractAddress, SyscallResultTrait, get_tx_info};
use m31_pool::open_note::{COMPUTE, ExecutionIntent, INVOKE, OpenDestination, hash_intent};
use m31_pool::pool::{IM31PoolDispatcher, IM31PoolDispatcherTrait};
use m31_pool::spend::{IERC20Dispatcher, IERC20DispatcherTrait, Output, Spend, Withdrawal, compute_binding};
use m31_pool::tree::{IM31TreeDispatcher, IM31TreeDispatcherTrait};
use m31_pool::tree::m31_tree_component::M31TreeInternalTrait;
use starknet::storage::StoragePointerReadAccess;

fn deploy(name: ByteArray, data: Array<felt252>) -> ContractAddress {
    let (address, _) = declare(name).unwrap_syscall().contract_class().deploy(@data).unwrap_syscall();
    address
}
#[starknet::interface]
trait IFaucet<T> { fn faucet(ref self: T, to: ContractAddress, amount: u256); }
fn payload(seed: felt252) -> Span<felt252> { array![seed, 2, 3, 4, 5, 6, 7, 8, 9, 10].span() }
fn digest(seed: felt252) -> Span<felt252> {
    array![seed, seed + 1, seed + 2, seed + 3, seed + 4, seed + 5, seed + 6, seed + 7, seed + 8].span()
}
fn zero_digest() -> Span<felt252> { array![0, 0, 0, 0, 0, 0, 0, 0, 0].span() }
#[derive(Drop)]
struct Env { pool: IM31PoolDispatcher, tree: IM31TreeDispatcher, a: IERC20Dispatcher, b: IERC20Dispatcher }
fn env() -> Env {
    let verifier = deploy("MockVerifier", array![1]);
    let pool = deploy("M31Pool", array![test_address().into(), verifier.into(), 1, 0]);
    let a = IERC20Dispatcher { contract_address: deploy("E2EToken", array![test_address().into(), 1000000, 0]) };
    let b = IERC20Dispatcher { contract_address: deploy("E2EToken", array![test_address().into(), 1000000, 0]) };
    a.approve(pool, 1000000);
    let p = IM31PoolDispatcher { contract_address: pool };
    p.deposit(a.contract_address, 100, digest(7), payload(1));
    Env { pool: p, tree: IM31TreeDispatcher { contract_address: pool }, a, b }
}
fn mint(token: ContractAddress, to: ContractAddress, amount: u256) {
    IFaucetDispatcher { contract_address: token }.faucet(to, amount);
}
fn spend(e: @Env, nf_seed: felt252, n_out: u32, budget: u128, recipient: ContractAddress) -> Spend {
    let mut nfs = array![];
    nfs.append_span(digest(nf_seed));
    nfs.append_span(digest(nf_seed + 100));
    let out = |j: u32| if j < n_out {
        Output { commitment: digest(nf_seed + 500 + (100 * j).into()), ciphertext: payload(j.into() + 2) }
    } else {
        Output { commitment: zero_digest(), ciphertext: array![].span() }
    };
    Spend {
        chain: get_tx_info().unbox().chain_id, pool: (*e.pool).contract_address, token: (*e.a).contract_address,
        root: (*e.tree).get_root(), nullifiers: nfs.span(), outputs: array![out(0), out(1)].span(),
        withdrawal: Withdrawal { recipient, amount: budget }, intent: 0, identity: zero_digest(), binding: 0,
    }
}
fn finish(ref sp: Spend, intent: @ExecutionIntent) {
    sp.intent = hash_intent(@sp, intent);
    sp.binding = compute_binding(@sp);
}
fn evil_intent(e: @Env, adapter: ContractAddress, token: ContractAddress, amount: u128, note_id: felt252, mode: u8, minimum: u128, inner: Span<felt252>) -> ExecutionIntent {
    let mut cd = array![];
    (*e.pool).contract_address.serialize(ref cd);
    token.serialize(ref cd);
    amount.serialize(ref cd);
    note_id.serialize(ref cd);
    mode.serialize(ref cd);
    ExecutionIntent {
        kind: INVOKE, adapter, nonce: 0, expiry: 1000000, calldata: cd.span(),
        destinations: array![OpenDestination { note_id, token, minimum, inner, ciphertext: payload(9) }].span(),
    }
}
fn run(mode: u8, amount: u128, minimum: u128) {
    let e = env();
    let adapter = deploy("EvilAdapter", array![]);
    mint(e.b.contract_address, adapter, 500);
    let mut sp = spend(@e, 1000, 1, 40, adapter);
    let intent = evil_intent(@e, adapter, e.b.contract_address, amount, 77, mode, minimum, digest(900));
    finish(ref sp, @intent);
    e.pool.apply_spend_with_invoke(sp, intent, array![].span());
}
#[test]
#[should_panic(expected: 'REENTRANCY')]
fn r_reentrant_deposit_blocked() { run(1, 100, 1); }
#[test]
#[should_panic(expected: 'INSUFFICIENT_ALLOWANCE')]
fn r_under_approval_rejected() { run(3, 100, 1); }
#[test]
#[should_panic(expected: 'INSUFFICIENT_ALLOWANCE')]
fn r_pull_from_pool_rejected() { run(5, 100, 1); }
#[test]
#[should_panic(expected: 'OPEN_NOTE_AMOUNT')]
fn r_below_minimum_rejected() { run(0, 100, 101); }
#[test]
#[should_panic(expected: 'OPEN_NOTE_AMOUNT')]
fn r_zero_amount_rejected() { run(0, 0, 1); }
#[test]
fn r_control_ok() { run(0, 100, 1); }
#[test]
#[should_panic(expected: 'EXECUTION_EXPIRED')]
fn r_expired() {
    start_cheat_block_number_global(1000001);
    run(0, 100, 1);
}
#[test]
#[should_panic(expected: 'INVOKE_RETURN')]
fn r_extra_return_data_rejected() {
    let e = env();
    let adapter = deploy("ExtraAdapter", array![]);
    mint(e.b.contract_address, adapter, 500);
    let mut sp = spend(@e, 1000, 1, 40, adapter);
    let mut cd = array![];
    e.b.contract_address.serialize(ref cd);
    100_u128.serialize(ref cd);
    77.serialize(ref cd);
    let intent = ExecutionIntent {
        kind: INVOKE, adapter, nonce: 0, expiry: 1000000, calldata: cd.span(),
        destinations: array![OpenDestination { note_id: 77, token: e.b.contract_address, minimum: 1, inner: digest(900), ciphertext: payload(9) }].span(),
    };
    finish(ref sp, @intent);
    e.pool.apply_spend_with_invoke(sp, intent, array![].span());
}
#[test]
#[should_panic(expected: 'OPEN_NOTE_FUNDING')]
fn r_fee_on_transfer_rejected() {
    let e = env();
    let fee = deploy("FeeToken", array![]);
    let adapter = deploy("EvilAdapter", array![]);
    mint(fee, adapter, 500);
    let mut sp = spend(@e, 1000, 1, 40, adapter);
    let intent = evil_intent(@e, adapter, fee, 100, 77, 0, 1, digest(900));
    finish(ref sp, @intent);
    e.pool.apply_spend_with_invoke(sp, intent, array![].span());
}
#[test]
#[should_panic(expected: 'INTENT_NEEDS_INVOKE')]
fn r_apply_spend_rejects_intent() {
    let e = env();
    let adapter = deploy("EvilAdapter", array![]);
    let mut sp = spend(@e, 1000, 1, 40, adapter);
    let intent = evil_intent(@e, adapter, e.b.contract_address, 100, 77, 0, 1, digest(900));
    finish(ref sp, @intent);
    e.pool.apply_spend(sp, array![].span());
}
/// Budget recipient is not constrained to the adapter: a third party receives it.
#[test]
fn r_budget_to_third_party() {
    let e = env();
    let adapter = deploy("EvilAdapter", array![]);
    mint(e.b.contract_address, adapter, 500);
    let third: ContractAddress = 0x1234.try_into().unwrap();
    let mut sp = spend(@e, 1000, 1, 40, third);
    let intent = evil_intent(@e, adapter, e.b.contract_address, 100, 77, 0, 1, digest(900));
    finish(ref sp, @intent);
    e.pool.apply_spend_with_invoke(sp, intent, array![].span());
    assert_eq!(e.a.balance_of(third), 40);
}
/// Three notes (two outputs + one open note) appended from odd index 1: final root equals
/// sequential `insert_leaf` of the same leaves; the pre-state root stays known.
#[test]
fn r_append_from_odd_index_matches_sequential() {
    let e = env();
    let adapter = deploy("EvilAdapter", array![]);
    mint(e.b.contract_address, adapter, 500);
    let root0 = e.tree.get_root();
    let mut sp = spend(@e, 1000, 2, 40, adapter);
    let intent = evil_intent(@e, adapter, e.b.contract_address, 100, 77, 0, 1, digest(900));
    finish(ref sp, @intent);
    let chain = get_tx_info().unbox().chain_id;
    let pool = e.pool.contract_address;
    e.pool.apply_spend_with_invoke(sp, intent, array![].span());
    let mut st = m31_pool::pool::M31Pool::contract_state_for_testing();
    st.tree.initializer(1, false);
    let rd = |s: Span<felt252>| m31_pool::hash::read_digest(s);
    st.tree.insert_leaf(m31_pool::hash::commitment(chain, pool.into(), e.a.contract_address.into(), 100, rd(digest(7))));
    st.tree.insert_leaf(rd(digest(1500)));
    st.tree.insert_leaf(rd(digest(1600)));
    st.tree.insert_leaf(m31_pool::hash::commitment(chain, pool.into(), e.b.contract_address.into(), 100, rd(digest(900))));
    let (lo, hi) = st.tree.tree_root.read();
    assert!(m31_pool::hash::unpack(lo, hi).span() == e.tree.get_root());
    assert_eq!(e.tree.get_leaf_count(), 4);
    assert!(e.tree.root_is_known(root0));
}

fn run_with(e: @Env, adapter: ContractAddress, mut sp: Spend, intent: ExecutionIntent) {
    finish(ref sp, @intent);
    (*e.pool).apply_spend_with_invoke(sp, intent, array![].span());
}
fn destination(note_id: felt252, token: ContractAddress, minimum: u128, inner: Span<felt252>) -> OpenDestination {
    OpenDestination { note_id, token, minimum, inner, ciphertext: payload(9) }
}
/// One honest-adapter intent whose single destination is `d`.
fn with_destination(e: @Env, adapter: ContractAddress, d: OpenDestination) -> ExecutionIntent {
    let mut intent = evil_intent(e, adapter, *e.b.contract_address, 100, d.note_id, 0, 1, digest(900));
    intent.destinations = array![d].span();
    intent
}
fn setup_evil() -> (Env, ContractAddress) {
    let e = env();
    let adapter = deploy("EvilAdapter", array![]);
    mint(e.b.contract_address, adapter, 500);
    (e, adapter)
}

// ---------------------------------------------------------------- destination validation (F1/L2)

#[test]
#[should_panic(expected: 'OPEN_NOTE_INNER')]
fn a_zero_inner_rejected() {
    let (e, adapter) = setup_evil();
    let mut sp = spend(@e, 1000, 1, 40, adapter);
    run_with(@e, adapter, sp, with_destination(@e, adapter, destination(77, e.b.contract_address, 1, zero_digest())));
}
#[test]
#[should_panic(expected: 'DIGEST_WORD')]
fn a_noncanonical_inner_rejected() {
    let (e, adapter) = setup_evil();
    let mut sp = spend(@e, 1000, 1, 40, adapter);
    let bad = array![0x7fffffff, 1, 2, 3, 4, 5, 6, 7, 8].span();
    run_with(@e, adapter, sp, with_destination(@e, adapter, destination(77, e.b.contract_address, 1, bad)));
}
#[test]
#[should_panic(expected: 'OPEN_NOTE_ID')]
fn a_zero_note_id_rejected() {
    let (e, adapter) = setup_evil();
    let mut sp = spend(@e, 1000, 1, 40, adapter);
    run_with(@e, adapter, sp, with_destination(@e, adapter, destination(0, e.b.contract_address, 1, digest(900))));
}
#[test]
#[should_panic(expected: 'OPEN_NOTE_MINIMUM')]
fn a_zero_minimum_rejected() {
    let (e, adapter) = setup_evil();
    let mut sp = spend(@e, 1000, 1, 40, adapter);
    run_with(@e, adapter, sp, with_destination(@e, adapter, destination(77, e.b.contract_address, 0, digest(900))));
}
#[test]
#[should_panic(expected: 'OPEN_NOTE_TOKEN')]
fn a_zero_token_rejected() {
    let (e, adapter) = setup_evil();
    let mut sp = spend(@e, 1000, 1, 40, adapter);
    run_with(@e, adapter, sp, with_destination(@e, adapter, destination(77, 0.try_into().unwrap(), 1, digest(900))));
}
#[test]
#[should_panic(expected: 'DUPLICATE_NOTE_ID')]
fn a_duplicate_note_id_rejected() {
    let (e, adapter) = setup_evil();
    let mut sp = spend(@e, 1000, 1, 40, adapter);
    let mut intent = with_destination(@e, adapter, destination(77, e.b.contract_address, 1, digest(900)));
    intent.destinations = array![destination(77, e.b.contract_address, 1, digest(900)), destination(77, e.b.contract_address, 1, digest(910))].span();
    run_with(@e, adapter, sp, intent);
}

// ---------------------------------------------------------------- nonce, budget, identity

#[test]
#[should_panic(expected: 'EXECUTION_NONCE')]
fn a_nonzero_nonce_rejected() {
    let (e, adapter) = setup_evil();
    let mut sp = spend(@e, 1000, 1, 40, adapter);
    let mut intent = with_destination(@e, adapter, destination(77, e.b.contract_address, 1, digest(900)));
    intent.nonce = 5;
    run_with(@e, adapter, sp, intent);
}
#[test]
#[should_panic(expected: 'BUDGET_RECIPIENT')]
fn a_budget_to_pool_rejected() {
    let (e, adapter) = setup_evil();
    let mut sp = spend(@e, 1000, 1, 40, e.pool.contract_address);
    run_with(@e, adapter, sp, with_destination(@e, adapter, destination(77, e.b.contract_address, 1, digest(900))));
}
#[test]
#[should_panic(expected: 'BAD_WITHDRAWAL')]
fn a_zero_budget_with_recipient_rejected() {
    let (e, adapter) = setup_evil();
    let mut sp = spend(@e, 1000, 1, 0, adapter);
    run_with(@e, adapter, sp, with_destination(@e, adapter, destination(77, e.b.contract_address, 1, digest(900))));
}
#[test]
#[should_panic(expected: 'IDENTITY_REQUIRED')]
fn a_compute_without_identity_rejected() {
    let (e, adapter) = setup_evil();
    let mut sp = spend(@e, 1000, 1, 40, adapter);
    let mut intent = with_destination(@e, adapter, destination(77, e.b.contract_address, 1, digest(900)));
    intent.kind = COMPUTE;
    run_with(@e, adapter, sp, intent);
}
#[test]
#[should_panic(expected: 'IDENTITY_UNEXPECTED')]
fn a_invoke_with_identity_rejected() {
    let (e, adapter) = setup_evil();
    let mut sp = spend(@e, 1000, 1, 40, adapter);
    sp.identity = digest(3000);
    run_with(@e, adapter, sp, with_destination(@e, adapter, destination(77, e.b.contract_address, 1, digest(900))));
}

// ---------------------------------------------------------------- binding, matching, replay

/// The relayer changes the call after the proof bound the intent.
#[test]
#[should_panic(expected: 'EXECUTION_INTENT')]
fn a_changed_calldata_rejected() {
    let (e, adapter) = setup_evil();
    let mut sp = spend(@e, 1000, 1, 40, adapter);
    let intent = with_destination(@e, adapter, destination(77, e.b.contract_address, 1, digest(900)));
    finish(ref sp, @intent);
    let mut changed = with_destination(@e, adapter, destination(77, e.b.contract_address, 1, digest(900)));
    let mut cd = array![];
    cd.append_span(intent.calldata);
    cd.append(0);
    changed.calldata = cd.span();
    e.pool.apply_spend_with_invoke(sp, changed, array![].span());
}
/// The relayer redirects the open note to another owner.
#[test]
#[should_panic(expected: 'EXECUTION_INTENT')]
fn a_redirected_destination_rejected() {
    let (e, adapter) = setup_evil();
    let mut sp = spend(@e, 1000, 1, 40, adapter);
    let intent = with_destination(@e, adapter, destination(77, e.b.contract_address, 1, digest(900)));
    finish(ref sp, @intent);
    let redirected = with_destination(@e, adapter, destination(77, e.b.contract_address, 1, digest(4000)));
    e.pool.apply_spend_with_invoke(sp, redirected, array![].span());
}
#[test]
#[should_panic(expected: 'OPEN_NOTE_COUNT')]
fn a_missing_deposit_rejected() {
    let (e, adapter) = setup_evil();
    let mut sp = spend(@e, 1000, 1, 40, adapter);
    let mut intent = evil_intent(@e, adapter, e.b.contract_address, 100, 77, 6, 1, digest(900));
    run_with(@e, adapter, sp, intent);
}
#[test]
#[should_panic(expected: 'OPEN_NOTE_ID')]
fn a_foreign_deposit_rejected() {
    let (e, adapter) = setup_evil();
    let mut sp = spend(@e, 1000, 1, 40, adapter);
    let intent = evil_intent(@e, adapter, e.b.contract_address, 100, 77, 7, 1, digest(900));
    run_with(@e, adapter, sp, intent);
}
/// Settling the same spend twice: the nullifiers are already spent.
#[test]
#[should_panic(expected: 'NULLIFIER_USED')]
fn a_replay_rejected() {
    let (e, adapter) = setup_evil();
    let first = spend(@e, 1000, 1, 40, adapter);
    run_with(@e, adapter, first, with_destination(@e, adapter, destination(77, e.b.contract_address, 1, digest(900))));
    let again = spend(@e, 1000, 1, 40, adapter);
    run_with(@e, adapter, again, with_destination(@e, adapter, destination(77, e.b.contract_address, 1, digest(900))));
}
