//! Policy-note settlement (`apply_policy_spend`, `docs/policy-note-spec.md` §6) with the reference
//! escrow and mock controllers. The P1 verdict is mocked here; the real-proof path is in
//! `test_policy_e2e`. Covers the windows, the controller call and its failures, the escrow's
//! approvals, and the statement checks.
use core::poseidon::poseidon_hash_span;
use snforge_std::{
    ContractClassTrait, DeclareResultTrait, declare, start_cheat_block_number_global, start_cheat_caller_address,
    stop_cheat_caller_address, test_address,
};
use starknet::syscalls::get_class_hash_at_syscall;
use starknet::{ContractAddress, SyscallResultTrait, get_tx_info};
use m31_pool::hash::{key, read_digest};
use m31_pool::policy::{FIXED, ITemplarPolicyControllerDispatcherTrait, PolicySpend, SPLIT, policy_binding};
use m31_pool::policy_escrow::{IPolicyEscrowDispatcher, IPolicyEscrowDispatcherTrait};
use m31_pool::pool::{IM31PoolDispatcher, IM31PoolDispatcherTrait, IM31PoolSafeDispatcher, IM31PoolSafeDispatcherTrait};
use m31_pool::spend::{IERC20Dispatcher, IERC20DispatcherTrait, Withdrawal, delivery_digest};
use m31_pool::test_adapters::{IMockPolicyControllerDispatcher, IMockPolicyControllerDispatcherTrait};
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

#[derive(Drop)]
struct Env {
    pool: IM31PoolDispatcher,
    tree: IM31TreeDispatcher,
    token: IERC20Dispatcher,
    escrow: ContractAddress,
}

/// A pool (single-permutation nodes) with a P1 verifier set, a token with 1000 deposited (so the
/// pool can pay withdrawals and has a known root), and the reference escrow.
fn env() -> Env {
    let verifier = deploy("MockVerifier", array![1]);
    let pool = deploy("M31Pool", array![test_address().into(), verifier.into(), 1, 0]);
    let p = IM31PoolDispatcher { contract_address: pool };
    p.set_policy_verifier(verifier);
    let token = IERC20Dispatcher { contract_address: deploy("E2EToken", array![test_address().into(), 1000000, 0]) };
    token.approve(pool, 1000000);
    p.deposit(token.contract_address, 1000, digest(7), payload(1));
    let escrow = deploy("PolicyEscrow", array![pool.into()]);
    start_cheat_block_number_global(100);
    Env { pool: p, tree: IM31TreeDispatcher { contract_address: pool }, token, escrow }
}

/// A fixed settlement of outcome `index` publishing one note, under policy `pid_seed`, for the
/// escrow with the default arbiter.
fn spend(e: @Env, nf_seed: felt252, pid_seed: felt252, index: u8) -> PolicySpend {
    let mut cms = array![];
    cms.append_span(digest(nf_seed + 500));
    cms.append_span(zeros());
    PolicySpend {
        chain: get_tx_info().unbox().chain_id, pool: *e.pool.contract_address, token: *e.token.contract_address,
        root: (*e.tree).get_root(), nullifier: digest(nf_seed), commitments: cms.span(),
        delivery0: delivery_digest(payload(2)), delivery1: 0,
        withdrawal: Withdrawal { recipient: 0.try_into().unwrap(), amount: 0 }, controller: *e.escrow,
        controller_class: class_of(*e.escrow), handle: ARBITER, policy_id: digest(pid_seed), deadline: DEADLINE,
        not_before: 0, index, kind: FIXED, x: 0, data: poseidon_hash_span(array![].span()), binding: 0,
    }
}
fn cts() -> Span<Span<felt252>> {
    array![payload(2), array![].span()].span()
}
fn apply(e: @Env, mut sp: PolicySpend) {
    sp.binding = policy_binding(@sp);
    (*e.pool).apply_policy_spend(sp, array![].span(), cts(), array![].span());
}
fn approve(e: @Env, pid_seed: felt252, outcome: u8) {
    let escrow = IPolicyEscrowDispatcher { contract_address: *e.escrow };
    start_cheat_caller_address(*e.escrow, ARBITER.try_into().unwrap());
    escrow.approve(pid(pid_seed), outcome);
    stop_cheat_caller_address(*e.escrow);
}

// ---------------------------------------------------------------- happy paths

/// The arbiter releases; the executor settles outcome 1 atomically with the escrow's state change.
#[test]
fn escrow_release_settles() {
    let e = env();
    approve(@e, 1, 1);
    let before = e.tree.get_leaf_count();
    apply(@e, spend(@e, 3000, 1, 1));
    assert_eq!(e.tree.get_leaf_count(), before + 1);
    assert!(e.pool.get_nullifier_spent(digest(3000)));
    assert!(IPolicyEscrowDispatcher { contract_address: e.escrow }.consumed(ARBITER.try_into().unwrap(), pid(1)));
    assert!(e.pool.get_delivery_digest(before) == delivery_digest(payload(2)));
}

/// The arbiter cancels; the refund (outcome 0) settles before the deadline through the escrow.
#[test]
fn escrow_cancel_refunds_early() {
    let e = env();
    approve(@e, 1, 0);
    apply(@e, spend(@e, 3000, 1, 0));
}

/// After the deadline the refund settles without the controller, even one whose class changed.
#[test]
fn refund_after_deadline_needs_no_controller() {
    let e = env();
    start_cheat_block_number_global(DEADLINE + 1);
    let mut sp = spend(@e, 3000, 1, 0);
    sp.controller_class = 0x1234;
    apply(@e, sp);
}

/// The deadline block itself is still the controller's; a withdrawal outcome pays out.
#[test]
fn withdrawal_outcome_at_the_deadline() {
    let e = env();
    approve(@e, 1, 1);
    start_cheat_block_number_global(DEADLINE);
    let mut sp = spend(@e, 3000, 1, 1);
    sp.withdrawal = Withdrawal { recipient: 0x77.try_into().unwrap(), amount: 250 };
    apply(@e, sp);
    assert_eq!(e.token.balance_of(0x77.try_into().unwrap()), 250);
}

/// The controller receives exactly the proven fields.
#[test]
fn controller_receives_the_authorization() {
    let e = env();
    let c = deploy("MockPolicyController", array![0]);
    let mut sp = spend(@e, 3000, 1, 1);
    sp.controller = c;
    sp.controller_class = class_of(c);
    sp.kind = SPLIT;
    sp.x = 42;
    sp.not_before = 50;
    apply(@e, sp);
    let a = IMockPolicyControllerDispatcher { contract_address: c }.last_authorization();
    assert_eq!(a.len(), 16);
    assert!(*a.at(0) == 'TEMPLAR_POLICY_V1');
    assert!(*a.at(2) == e.pool.contract_address.into());
    assert!(*a.at(3) == e.token.contract_address.into());
    assert!(*a.at(4) == pid(1));
    assert!(*a.at(5) == ARBITER);
    assert!(*a.at(6) == 1 && *a.at(7) == 2 && *a.at(8) == 42);
    assert!(*a.at(9) == key(read_digest(digest(3000))));
    assert!(*a.at(10) == 50 && *a.at(11) == DEADLINE.into());
    assert!(*a.at(12) == key(read_digest(digest(3500))) && *a.at(13) == 0);
}

// ---------------------------------------------------------------- windows

#[test]
#[should_panic(expected: 'POLICY_EXPIRED')]
fn non_refund_after_deadline_rejected() {
    let e = env();
    approve(@e, 1, 1);
    start_cheat_block_number_global(DEADLINE + 1);
    apply(@e, spend(@e, 3000, 1, 1));
}

#[test]
#[should_panic(expected: 'POLICY_NOT_BEFORE')]
fn settlement_before_not_before_rejected() {
    let e = env();
    approve(@e, 1, 1);
    let mut sp = spend(@e, 3000, 1, 1);
    sp.not_before = 101;
    apply(@e, sp);
}

#[test]
#[should_panic(expected: 'REFUND_TYPE')]
fn split_refund_rejected() {
    let e = env();
    start_cheat_block_number_global(DEADLINE + 1);
    let mut sp = spend(@e, 3000, 1, 0);
    sp.kind = SPLIT;
    sp.x = 1;
    apply(@e, sp);
}

// ---------------------------------------------------------------- escrow approvals (N-1, N-2)

#[test]
#[should_panic(expected: 'ESCROW_NOT_APPROVED')]
fn unapproved_policy_rejected() {
    let e = env();
    apply(@e, spend(@e, 3000, 1, 1));
}

/// An unset approval never reads as cancel (review N-2).
#[test]
#[should_panic(expected: 'ESCROW_NOT_APPROVED')]
fn never_approved_refund_rejected_before_deadline() {
    let e = env();
    apply(@e, spend(@e, 3000, 1, 0));
}

#[test]
#[should_panic(expected: 'ESCROW_NOT_APPROVED')]
fn other_outcome_than_approved_rejected() {
    let e = env();
    approve(@e, 1, 1);
    apply(@e, spend(@e, 3000, 1, 0));
}

/// A decoy note naming the same arbiter under another policy id (review P-1/PN-1).
#[test]
#[should_panic(expected: 'ESCROW_NOT_APPROVED')]
fn decoy_policy_on_the_same_handle_rejected() {
    let e = env();
    approve(@e, 1, 1);
    apply(@e, spend(@e, 3000, 2, 1));
}

/// The approval is consumed once: a second note with the same policy id cannot reuse it.
#[test]
#[should_panic(expected: 'ESCROW_CONSUMED')]
fn approval_consumed_once() {
    let e = env();
    approve(@e, 1, 1);
    apply(@e, spend(@e, 3000, 1, 1));
    apply(@e, spend(@e, 4000, 1, 1));
}

/// A decoy by another "arbiter" (the handle) needs that arbiter's approval.
#[test]
#[should_panic(expected: 'ESCROW_NOT_APPROVED')]
fn other_arbiter_rejected() {
    let e = env();
    approve(@e, 1, 1);
    let mut sp = spend(@e, 3000, 1, 1);
    sp.handle = 0xbad;
    apply(@e, sp);
}

#[test]
#[should_panic(expected: 'ESCROW_DECIDED')]
fn approval_is_write_once() {
    let e = env();
    approve(@e, 1, 1);
    approve(@e, 1, 0);
}

#[test]
#[should_panic(expected: 'ESCROW_OUTCOME')]
fn approval_outcome_bounded() {
    let e = env();
    approve(@e, 1, 2);
}

#[test]
#[should_panic(expected: 'ESCROW_KIND')]
fn escrow_rejects_split() {
    let e = env();
    approve(@e, 1, 1);
    let mut sp = spend(@e, 3000, 1, 1);
    sp.kind = SPLIT;
    sp.x = 5;
    apply(@e, sp);
}

#[test]
#[should_panic(expected: 'ESCROW_CALLER')]
fn escrow_callback_only_from_pool() {
    let e = env();
    approve(@e, 1, 1);
    let mut auth = array!['TEMPLAR_POLICY_V1', get_tx_info().unbox().chain_id, e.pool.contract_address.into()];
    auth.append_span(array![0, pid(1), ARBITER, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0].span());
    m31_pool::policy::ITemplarPolicyControllerDispatcher { contract_address: e.escrow }
        .templar_apply_policy(auth.span(), array![].span());
}

// ---------------------------------------------------------------- the controller call

#[test]
#[should_panic(expected: 'NULLIFIER_USED')]
fn replay_rejected() {
    let e = env();
    start_cheat_block_number_global(DEADLINE + 1);
    apply(@e, spend(@e, 3000, 1, 0));
    apply(@e, spend(@e, 3000, 1, 0));
}

#[test]
#[should_panic(expected: 'CONTROLLER_CLASS')]
fn controller_class_mismatch_rejected() {
    let e = env();
    approve(@e, 1, 1);
    let mut sp = spend(@e, 3000, 1, 1);
    sp.controller_class = class_of(e.pool.contract_address);
    apply(@e, sp);
}

#[test]
#[should_panic(expected: 'CONTROLLER_CLASS')]
fn undeployed_controller_rejected() {
    let e = env();
    let mut sp = spend(@e, 3000, 1, 1);
    sp.controller = 0xdead.try_into().unwrap();
    apply(@e, sp);
}

#[test]
#[should_panic(expected: 'POLICY_CONTROLLER')]
fn pool_as_controller_rejected() {
    let e = env();
    let mut sp = spend(@e, 3000, 1, 1);
    sp.controller = e.pool.contract_address;
    apply(@e, sp);
}

#[test]
#[should_panic(expected: 'CONTROLLER_SAYS_NO')]
fn controller_revert_reverts() {
    let e = env();
    let c = deploy("MockPolicyController", array![1]);
    let mut sp = spend(@e, 3000, 1, 1);
    sp.controller = c;
    sp.controller_class = class_of(c);
    apply(@e, sp);
}

#[test]
#[should_panic(expected: 'CONTROLLER_RETURN')]
fn controller_wrong_return_rejected() {
    let e = env();
    let c = deploy("MockPolicyController", array![2]);
    let mut sp = spend(@e, 3000, 1, 1);
    sp.controller = c;
    sp.controller_class = class_of(c);
    apply(@e, sp);
}

#[test]
#[should_panic(expected: 'REENTRANCY')]
fn controller_cannot_reenter() {
    let e = env();
    let c = deploy("MockPolicyController", array![3]);
    let mut sp = spend(@e, 3000, 1, 1);
    sp.controller = c;
    sp.controller_class = class_of(c);
    apply(@e, sp);
}

/// A failed callback leaves nothing behind: no nullifier, no note, no controller state.
#[test]
#[feature("safe_dispatcher")]
fn failed_callback_leaves_no_partial_state() {
    let e = env();
    let c = deploy("MockPolicyController", array![1]);
    let mut sp = spend(@e, 3000, 1, 1);
    sp.controller = c;
    sp.controller_class = class_of(c);
    sp.binding = policy_binding(@sp);
    let before = e.tree.get_leaf_count();
    let safe = IM31PoolSafeDispatcher { contract_address: e.pool.contract_address };
    assert!(safe.apply_policy_spend(sp, array![].span(), cts(), array![].span()).is_err());
    assert_eq!(e.tree.get_leaf_count(), before);
    assert!(!e.pool.get_nullifier_spent(digest(3000)));
    assert_eq!(IMockPolicyControllerDispatcher { contract_address: c }.calls(), 0);
}

// ---------------------------------------------------------------- statement checks

#[test]
#[should_panic(expected: 'BAD_BINDING')]
fn tampered_field_after_binding_rejected() {
    let e = env();
    approve(@e, 1, 1);
    let mut sp = spend(@e, 3000, 1, 1);
    sp.binding = policy_binding(@sp);
    sp.handle = 0xbad;
    e.pool.apply_policy_spend(sp, array![].span(), cts(), array![].span());
}

#[test]
#[should_panic(expected: 'POLICY_DATA')]
fn data_mismatch_rejected() {
    let e = env();
    approve(@e, 1, 1);
    let mut sp = spend(@e, 3000, 1, 1);
    sp.binding = policy_binding(@sp);
    e.pool.apply_policy_spend(sp, array![1].span(), cts(), array![].span());
}

#[test]
#[should_panic(expected: 'DELIVERY')]
fn wrong_ciphertext_rejected() {
    let e = env();
    approve(@e, 1, 1);
    let mut sp = spend(@e, 3000, 1, 1);
    sp.binding = policy_binding(@sp);
    e.pool.apply_policy_spend(sp, array![].span(), array![payload(3), array![].span()].span(), array![].span());
}

#[test]
#[should_panic(expected: 'INACTIVE_PAYLOAD')]
fn ciphertext_for_an_absent_output_rejected() {
    let e = env();
    approve(@e, 1, 1);
    let mut sp = spend(@e, 3000, 1, 1);
    sp.binding = policy_binding(@sp);
    e.pool.apply_policy_spend(sp, array![].span(), array![payload(2), payload(3)].span(), array![].span());
}

#[test]
#[should_panic(expected: 'BAD_WITHDRAWAL')]
fn withdrawal_to_the_pool_rejected() {
    let e = env();
    approve(@e, 1, 1);
    let mut sp = spend(@e, 3000, 1, 1);
    sp.withdrawal = Withdrawal { recipient: e.pool.contract_address, amount: 5 };
    apply(@e, sp);
}

#[test]
#[should_panic(expected: 'UNKNOWN_ROOT')]
fn unknown_root_rejected() {
    let e = env();
    approve(@e, 1, 1);
    let mut sp = spend(@e, 3000, 1, 1);
    sp.root = digest(1);
    apply(@e, sp);
}

#[test]
#[should_panic(expected: 'WRONG_POOL')]
fn other_pool_rejected() {
    let e = env();
    let mut sp = spend(@e, 3000, 1, 1);
    sp.pool = 0x999.try_into().unwrap();
    apply(@e, sp);
}

#[test]
#[should_panic(expected: 'WRONG_CHAIN')]
fn other_chain_rejected() {
    let e = env();
    let mut sp = spend(@e, 3000, 1, 1);
    sp.chain = 'SN_MAIN';
    apply(@e, sp);
}

#[test]
#[should_panic(expected: 'PROOF_REJECTED')]
fn policy_verifier_verdict_used() {
    let e = env();
    // The R0 verifier accepts, the P1 verifier rejects: settlement uses the P1 one.
    let no = deploy("MockVerifier", array![0]);
    e.pool.set_policy_verifier(no);
    approve(@e, 1, 1);
    apply(@e, spend(@e, 3000, 1, 1));
}

#[test]
#[should_panic(expected: 'NO_POLICY_VERIFIER')]
fn no_policy_verifier_rejected() {
    let verifier = deploy("MockVerifier", array![1]);
    let pool = deploy("M31Pool", array![test_address().into(), verifier.into(), 1, 0]);
    let p = IM31PoolDispatcher { contract_address: pool };
    let token = IERC20Dispatcher { contract_address: deploy("E2EToken", array![test_address().into(), 1000000, 0]) };
    token.approve(pool, 1000000);
    p.deposit(token.contract_address, 1000, digest(7), payload(1));
    let e = Env { pool: p, tree: IM31TreeDispatcher { contract_address: pool }, token, escrow: deploy("PolicyEscrow", array![pool.into()]) };
    apply(@e, spend(@e, 3000, 1, 1));
}

#[test]
#[should_panic(expected: 'NOT_OWNER')]
fn policy_verifier_owner_only() {
    let e = env();
    start_cheat_caller_address(e.pool.contract_address, 0x5.try_into().unwrap());
    e.pool.set_policy_verifier(0x6.try_into().unwrap());
}

/// The reference escrow's class hash as snforge declares it (`policy_e2e.py` commits to it).
#[test]
fn print_policy_escrow_class() {
    let class = declare("PolicyEscrow").unwrap_syscall().contract_class();
    let h: felt252 = (*class.class_hash).into();
    println!("POLICY_ESCROW_CLASS {}", h);
}
