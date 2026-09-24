//! Adversarial tests for `apply_policy_spend` and `PolicyEscrow`, from the implementation review
//! (`reviews/policy-note-impl-contract-review.md`): windows at the boundaries, hostile controllers,
//! class pinning, rollback, escrow keying, output and delivery rules, and R0/P1 separation.
use core::poseidon::poseidon_hash_span;
use snforge_std::{
    ContractClassTrait, DeclareResultTrait, EventSpyTrait, declare, spy_events,
    start_cheat_block_number, start_cheat_block_number_global, start_cheat_caller_address, start_cheat_chain_id,
    start_cheat_proof_facts, stop_cheat_caller_address, test_address,
};
use starknet::syscalls::get_class_hash_at_syscall;
use starknet::{ContractAddress, SyscallResultTrait, get_tx_info};
use m31_pool::hash::{key, read_digest};
use m31_pool::policy::{FIXED, PolicySpend, SPLIT, policy_binding};
use m31_pool::policy_escrow::{IPolicyEscrowDispatcher, IPolicyEscrowDispatcherTrait};
use m31_pool::pool::{IM31PoolDispatcher, IM31PoolDispatcherTrait, IM31PoolSafeDispatcher, IM31PoolSafeDispatcherTrait};
use m31_pool::spend::{
    IERC20Dispatcher, IERC20DispatcherTrait, IVerifierDispatcher, IVerifierDispatcherTrait, Output, Spend, Withdrawal,
    compute_binding, delivery_digest,
};
use m31_pool::tree::{IM31TreeDispatcher, IM31TreeDispatcherTrait};

const ARBITER: felt252 = 0xa4b1;
const DEADLINE: u64 = 1000;

fn deploy(name: ByteArray, data: Array<felt252>) -> ContractAddress {
    let (address, _) = declare(name).unwrap_syscall().contract_class().deploy(@data).unwrap_syscall();
    address
}
fn class_of(a: ContractAddress) -> felt252 {
    get_class_hash_at_syscall(a).unwrap_syscall().into()
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
fn pid(seed: felt252) -> felt252 {
    key(read_digest(digest(seed)))
}
fn a(x: felt252) -> ContractAddress {
    x.try_into().unwrap()
}

#[derive(Drop)]
struct Env {
    pool: IM31PoolDispatcher,
    tree: IM31TreeDispatcher,
    token: IERC20Dispatcher,
    escrow: ContractAddress,
    r0_verifier: ContractAddress,
}

fn env_with(r0_ok: felt252, p1_ok: felt252) -> Env {
    let r0 = deploy("MockVerifier", array![r0_ok]);
    let p1 = deploy("MockVerifier", array![p1_ok]);
    let pool = deploy("M31Pool", array![test_address().into(), r0.into(), 1, 0]);
    let p = IM31PoolDispatcher { contract_address: pool };
    p.set_policy_verifier(p1);
    let token = IERC20Dispatcher { contract_address: deploy("E2EToken", array![test_address().into(), 1000000, 0]) };
    token.approve(pool, 1000000);
    p.deposit(token.contract_address, 1000, digest(7), payload(1));
    let escrow = deploy("PolicyEscrow", array![pool.into()]);
    start_cheat_block_number_global(100);
    Env { pool: p, tree: IM31TreeDispatcher { contract_address: pool }, token, escrow, r0_verifier: r0 }
}
fn env() -> Env {
    env_with(1, 1)
}

fn spend(e: @Env, nf_seed: felt252, pid_seed: felt252, index: u8) -> PolicySpend {
    let mut cms = array![];
    cms.append_span(digest(nf_seed + 500));
    cms.append_span(zeros());
    PolicySpend {
        chain: get_tx_info().unbox().chain_id, pool: *e.pool.contract_address, token: *e.token.contract_address,
        root: (*e.tree).get_root(), nullifier: digest(nf_seed), commitments: cms.span(),
        delivery0: delivery_digest(payload(2)), delivery1: 0,
        withdrawal: Withdrawal { recipient: a(0), amount: 0 }, controller: *e.escrow,
        controller_class: class_of(*e.escrow), handle: ARBITER, policy_id: digest(pid_seed), deadline: DEADLINE,
        not_before: 0, index, kind: FIXED, x: 0, data: poseidon_hash_span(array![].span()), binding: 0,
    }
}
fn cts() -> Span<Span<felt252>> {
    array![payload(2), array![].span()].span()
}
fn apply_cts(e: @Env, mut sp: PolicySpend, c: Span<Span<felt252>>) {
    sp.binding = policy_binding(@sp);
    (*e.pool).apply_policy_spend(sp, array![].span(), c, array![].span());
}
fn apply(e: @Env, sp: PolicySpend) {
    apply_cts(e, sp, cts());
}
fn approve(e: @Env, pid_seed: felt252, outcome: u8) {
    let escrow = IPolicyEscrowDispatcher { contract_address: *e.escrow };
    start_cheat_caller_address(*e.escrow, a(ARBITER));
    escrow.approve(pid(pid_seed), outcome);
    stop_cheat_caller_address(*e.escrow);
}
fn with_controller(e: @Env, mut sp: PolicySpend, c: ContractAddress) -> PolicySpend {
    sp.controller = c;
    sp.controller_class = class_of(c);
    sp
}
/// The pool's `PolicySettled` data (the last one).
fn settled(ref spy: snforge_std::EventSpy, pool: ContractAddress) -> Array<felt252> {
    let events = spy.get_events();
    let mut out = array![];
    for (from, ev) in events.events.span() {
        if *from == pool && *ev.keys.at(0) == selector!("PolicySettled") {
            out = ev.data.clone();
        }
    }
    out
}
fn count_published(ref spy: snforge_std::EventSpy, pool: ContractAddress) -> u32 {
    let events = spy.get_events();
    let mut n = 0;
    for (from, ev) in events.events.span() {
        if *from == pool && *ev.keys.at(0) == selector!("NotePublished") {
            n += 1;
        }
    }
    n
}

// ---------------------------------------------------------------- windows at the boundaries

/// `b == not_before` is allowed.
#[test]
fn r_not_before_boundary_accepted() {
    let e = env();
    approve(@e, 1, 1);
    let mut sp = spend(@e, 3000, 1, 1);
    sp.not_before = 100;
    apply(@e, sp);
}

/// At `b == deadline` the refund still needs the controller (no pool-only refund yet).
#[test]
#[should_panic(expected: 'ESCROW_NOT_APPROVED')]
fn r_refund_at_deadline_needs_controller() {
    let e = env();
    start_cheat_block_number_global(DEADLINE);
    apply(@e, spend(@e, 3000, 1, 0));
}

/// After the deadline the refund needs no controller at all (zero controller and class), and the
/// event says so.
#[test]
fn r_refund_after_deadline_zero_controller_and_event() {
    let e = env();
    start_cheat_block_number_global(DEADLINE + 1);
    let mut sp = spend(@e, 3000, 1, 0);
    sp.controller = a(0);
    sp.controller_class = 0;
    let first = e.tree.get_leaf_count();
    let mut spy = spy_events();
    apply(@e, sp);
    let d = settled(ref spy, e.pool.contract_address);
    assert_eq!(d.len(), 8);
    assert!(*d.at(0) == key(read_digest(digest(3000))));
    assert!(*d.at(1) == 0 && *d.at(2) == ARBITER && *d.at(3) == pid(1));
    assert!(*d.at(4) == 0 && *d.at(5) == 0 && *d.at(6) == first.into() && *d.at(7) == 0);
}

/// Settle/refund race at the boundary: a release settled at the deadline block, then a refund of
/// the same note one block later.
#[test]
#[should_panic(expected: 'NULLIFIER_USED')]
fn r_settle_then_refund_same_note_rejected() {
    let e = env();
    approve(@e, 1, 1);
    start_cheat_block_number_global(DEADLINE);
    apply(@e, spend(@e, 3000, 1, 1));
    start_cheat_block_number_global(DEADLINE + 1);
    apply(@e, spend(@e, 3000, 1, 0));
}

// ---------------------------------------------------------------- the controller call

#[test]
#[should_panic(expected: 'CONTROLLER_RETURN')]
fn r_extra_return_data_rejected() {
    let e = env();
    let c = deploy("LongReturnController", array![]);
    apply(@e, with_controller(@e, spend(@e, 3000, 1, 1), c));
}

/// A controller exposing only PR #2's selector is unreachable.
#[test]
#[should_panic]
fn r_upstream_selector_unreachable() {
    let e = env();
    let c = deploy("UpstreamOnlyController", array![]);
    apply(@e, with_controller(@e, spend(@e, 3000, 1, 1), c));
}

#[test]
#[should_panic(expected: 'REENTRANCY')]
fn r_controller_reenters_policy_spend() {
    let e = env();
    let c = deploy("HostileController", array![1, 0]);
    apply(@e, with_controller(@e, spend(@e, 3000, 1, 1), c));
}

#[test]
#[should_panic(expected: 'REENTRANCY')]
fn r_controller_reenters_apply_spend() {
    let e = env();
    let c = deploy("HostileController", array![2, 0]);
    apply(@e, with_controller(@e, spend(@e, 3000, 1, 1), c));
}

#[test]
#[should_panic(expected: 'NOT_OWNER')]
fn r_controller_cannot_call_owner_setter() {
    let e = env();
    let c = deploy("HostileController", array![3, 0]);
    apply(@e, with_controller(@e, spend(@e, 3000, 1, 1), c));
}

/// A hostile controller cannot relay the authorization to the escrow (the escrow sees the
/// hostile controller as caller).
#[test]
#[should_panic(expected: 'ESCROW_CALLER')]
fn r_controller_cannot_relay_to_escrow() {
    let e = env();
    approve(@e, 1, 1);
    let c = deploy("HostileController", array![4, (e.escrow).into()]);
    apply(@e, with_controller(@e, spend(@e, 3000, 1, 1), c));
}

/// A controller can emit a same-named `PolicySettled` event from its own address: indexers must
/// filter on the pool's address (informational).
#[test]
fn r_controller_fake_event_is_from_controller() {
    let e = env();
    let c = deploy("HostileController", array![5, 0]);
    let mut spy = spy_events();
    apply(@e, with_controller(@e, spend(@e, 3000, 1, 1), c));
    let events = spy.get_events();
    let mut from_c = 0;
    for (from, ev) in events.events.span() {
        if *from == c && *ev.keys.at(0) == selector!("PolicySettled") {
            from_c += 1;
        }
    }
    assert_eq!(from_c, 1);
}

/// Class pinning: a controller that replaces its class after the note pinned it blocks the
/// controller window; the deadline refund still settles.
#[starknet::interface]
trait IUpgrade<T> {
    fn upgrade(ref self: T, class_hash: starknet::ClassHash);
}
#[test]
#[feature("safe_dispatcher")]
fn r_replaced_controller_class_blocks_then_refund() {
    let e = env();
    let c = deploy("UpgradableController", array![]);
    let pinned = class_of(c);
    let other = declare("MockPolicyController").unwrap_syscall().contract_class();
    IUpgradeDispatcher { contract_address: c }.upgrade(*other.class_hash);
    assert!(class_of(c) != pinned);
    let mut sp = spend(@e, 3000, 1, 1);
    sp.controller = c;
    sp.controller_class = pinned;
    sp.binding = policy_binding(@sp);
    let safe = IM31PoolSafeDispatcher { contract_address: e.pool.contract_address };
    let r = safe.apply_policy_spend(sp, array![].span(), cts(), array![].span());
    match r {
        Result::Ok(_) => panic!("settled through a replaced class"),
        Result::Err(d) => assert!(*d.at(0) == 'CONTROLLER_CLASS'),
    }
    start_cheat_block_number_global(DEADLINE + 1);
    let mut sp = spend(@e, 3000, 1, 0);
    sp.controller = c;
    sp.controller_class = pinned;
    apply(@e, sp);
}

/// Atomicity: a failure after the controller call (the withdrawal transfer) rolls back the
/// escrow's consumption; the approval stays usable.
#[test]
#[feature("safe_dispatcher")]
fn r_late_failure_rolls_back_consumption() {
    let e = env();
    approve(@e, 1, 1);
    let mut sp = spend(@e, 3000, 1, 1);
    sp.withdrawal = Withdrawal { recipient: a(0x77), amount: 5000 };
    sp.binding = policy_binding(@sp);
    let safe = IM31PoolSafeDispatcher { contract_address: e.pool.contract_address };
    assert!(safe.apply_policy_spend(sp, array![].span(), cts(), array![].span()).is_err());
    let esc = IPolicyEscrowDispatcher { contract_address: e.escrow };
    assert!(!esc.consumed(a(ARBITER), pid(1)));
    assert!(!e.pool.get_nullifier_spent(digest(3000)));
    apply(@e, spend(@e, 3000, 1, 1));
    assert!(esc.consumed(a(ARBITER), pid(1)));
}

// ---------------------------------------------------------------- escrow

/// An escrow deployed for another pool rejects callbacks from this one.
#[test]
#[should_panic(expected: 'ESCROW_CALLER')]
fn r_escrow_of_another_pool_rejected() {
    let e = env();
    let foreign = deploy("PolicyEscrow", array![0x999]);
    start_cheat_caller_address(foreign, a(ARBITER));
    IPolicyEscrowDispatcher { contract_address: foreign }.approve(pid(1), 1);
    stop_cheat_caller_address(foreign);
    apply(@e, with_controller(@e, spend(@e, 3000, 1, 1), foreign));
}

/// An approval of outcome 1 cannot settle outcome 2 or 3 (never approvable).
#[test]
#[should_panic(expected: 'ESCROW_NOT_APPROVED')]
fn r_escrow_other_slot_rejected() {
    let e = env();
    approve(@e, 1, 1);
    apply(@e, spend(@e, 3000, 1, 2));
}

/// Consumption is per `(arbiter, policy_id)`: another arbiter's approval of the same policy id is
/// independent.
#[test]
fn r_escrow_key_includes_arbiter() {
    let e = env();
    approve(@e, 1, 1);
    let esc = IPolicyEscrowDispatcher { contract_address: e.escrow };
    start_cheat_caller_address(e.escrow, a(0xb0b));
    esc.approve(pid(1), 1);
    stop_cheat_caller_address(e.escrow);
    apply(@e, spend(@e, 3000, 1, 1));
    let mut sp = spend(@e, 4000, 1, 1);
    sp.handle = 0xb0b;
    apply(@e, sp);
}

#[test]
#[should_panic(expected: 'ESCROW_POLICY')]
fn r_escrow_zero_policy_rejected() {
    let e = env();
    start_cheat_caller_address(e.escrow, a(ARBITER));
    IPolicyEscrowDispatcher { contract_address: e.escrow }.approve(0, 1);
}

// ---------------------------------------------------------------- outputs, delivery, withdrawal

/// A split: two notes, `x` and `first_index` in the event, controller-approved.
#[test]
fn r_split_two_notes_event() {
    let e = env();
    let c = deploy("MockPolicyController", array![0]);
    let mut sp = with_controller(@e, spend(@e, 3000, 1, 1), c);
    let mut cms = array![];
    cms.append_span(digest(3500));
    cms.append_span(digest(3600));
    sp.commitments = cms.span();
    sp.delivery1 = delivery_digest(payload(3));
    sp.kind = SPLIT;
    sp.x = 600;
    let first = e.tree.get_leaf_count();
    let mut spy = spy_events();
    apply_cts(@e, sp, array![payload(2), payload(3)].span());
    assert_eq!(e.tree.get_leaf_count(), first + 2);
    let d = settled(ref spy, e.pool.contract_address);
    assert!(*d.at(1) == c.into() && *d.at(4) == 1 && *d.at(5) == 600 && *d.at(6) == first.into() && *d.at(7) == 1);
    assert_eq!(count_published(ref spy, e.pool.contract_address), 2);
    assert!(e.pool.get_delivery_digest(first + 1) == delivery_digest(payload(3)));
}

/// A withdrawal-only fixed outcome: no note; `first_index` is the next free index.
#[test]
fn r_withdrawal_only_outcome() {
    let e = env();
    approve(@e, 1, 1);
    let mut sp = spend(@e, 3000, 1, 1);
    sp.commitments = array![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0].span();
    sp.delivery0 = 0;
    sp.withdrawal = Withdrawal { recipient: a(0x77), amount: 1000 };
    let first = e.tree.get_leaf_count();
    let mut spy = spy_events();
    apply_cts(@e, sp, array![array![].span(), array![].span()].span());
    assert_eq!(e.tree.get_leaf_count(), first);
    assert_eq!(e.token.balance_of(a(0x77)), 1000);
    assert_eq!(count_published(ref spy, e.pool.contract_address), 0);
}

#[test]
#[should_panic(expected: 'EMPTY_OUTPUT')]
fn r_nothing_produced_rejected() {
    let e = env();
    approve(@e, 1, 1);
    let mut sp = spend(@e, 3000, 1, 1);
    sp.commitments = array![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0].span();
    sp.delivery0 = 0;
    apply_cts(@e, sp, array![array![].span(), array![].span()].span());
}

#[test]
#[should_panic(expected: 'BAD_WITHDRAWAL')]
fn r_recipient_without_amount_rejected() {
    let e = env();
    approve(@e, 1, 1);
    let mut sp = spend(@e, 3000, 1, 1);
    sp.withdrawal = Withdrawal { recipient: a(0x77), amount: 0 };
    apply(@e, sp);
}

#[test]
#[should_panic(expected: 'DELIVERY')]
fn r_active_output_zero_delivery_rejected() {
    let e = env();
    approve(@e, 1, 1);
    let mut sp = spend(@e, 3000, 1, 1);
    sp.delivery0 = 0;
    apply(@e, sp);
}

#[test]
#[should_panic(expected: 'INACTIVE_PAYLOAD')]
fn r_inactive_output_nonzero_delivery_rejected() {
    let e = env();
    approve(@e, 1, 1);
    let mut sp = spend(@e, 3000, 1, 1);
    sp.delivery1 = 5;
    apply(@e, sp);
}

#[test]
#[should_panic(expected: 'CIPHERTEXT_COUNT')]
fn r_ciphertext_count_rejected() {
    let e = env();
    approve(@e, 1, 1);
    apply_cts(@e, spend(@e, 3000, 1, 1), array![payload(2)].span());
}

#[test]
#[should_panic(expected: 'PAYLOAD_LENGTH')]
fn r_short_ciphertext_rejected() {
    let e = env();
    approve(@e, 1, 1);
    apply_cts(@e, spend(@e, 3000, 1, 1), array![array![1, 2, 3].span(), array![].span()].span());
}

#[test]
#[should_panic(expected: 'ZERO_NULLIFIER')]
fn r_zero_nullifier_rejected() {
    let e = env();
    approve(@e, 1, 1);
    let mut sp = spend(@e, 3000, 1, 1);
    sp.nullifier = zeros();
    apply(@e, sp);
}

/// Defense in depth (review IC-5): a refund (index 0) with a withdrawal and no note is rejected by
/// the pool too, although P1 already forbids it.
#[test]
#[should_panic(expected: 'REFUND_SHAPE')]
fn r_refund_shape_rechecked_by_pool() {
    let e = env();
    start_cheat_block_number_global(DEADLINE + 1);
    let mut sp = spend(@e, 3000, 1, 0);
    sp.commitments = array![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0].span();
    sp.delivery0 = 0;
    sp.withdrawal = Withdrawal { recipient: a(0x77), amount: 1000 };
    apply_cts(@e, sp, array![array![].span(), array![].span()].span());
}

// ---------------------------------------------------------------- R0 / P1 separation

fn r0_spend(e: @Env, nf_seed: felt252) -> Spend {
    let mut nfs = array![];
    nfs.append_span(digest(nf_seed));
    nfs.append_span(digest(nf_seed + 100));
    let mut sp = Spend {
        chain: get_tx_info().unbox().chain_id, pool: *e.pool.contract_address, token: *e.token.contract_address,
        root: (*e.tree).get_root(), nullifiers: nfs.span(),
        outputs: array![Output { commitment: digest(9000), ciphertext: payload(4) }, Output { commitment: zeros(), ciphertext: array![].span() }].span(),
        withdrawal: Withdrawal { recipient: a(0), amount: 0 }, intent: 0, identity: zeros(), binding: 0,
    };
    sp.binding = compute_binding(@sp);
    sp
}

/// One nullifier map: an R0-spent nullifier cannot be reused by a policy settlement.
#[test]
#[should_panic(expected: 'NULLIFIER_USED')]
fn r_shared_nullifier_r0_then_p1() {
    let e = env();
    e.pool.apply_spend(r0_spend(@e, 3000), array![].span());
    start_cheat_block_number_global(DEADLINE + 1);
    apply(@e, spend(@e, 3000, 1, 0));
}

#[test]
#[should_panic(expected: 'NULLIFIER_USED')]
fn r_shared_nullifier_p1_then_r0() {
    let e = env();
    start_cheat_block_number_global(DEADLINE + 1);
    apply(@e, spend(@e, 3100, 1, 0));
    e.pool.apply_spend(r0_spend(@e, 3000), array![].span());
}

/// The R0 entry point uses the R0 verifier only (P1 accepts, R0 rejects).
#[test]
#[should_panic(expected: 'PROOF_REJECTED')]
fn r_r0_path_uses_r0_verifier() {
    let e = env_with(0, 1);
    e.pool.apply_spend(r0_spend(@e, 3000), array![].span());
}


