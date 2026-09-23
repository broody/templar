use core::testing::get_available_gas;
use snforge_std::{ContractClassTrait, DeclareResultTrait, declare, test_address};
use starknet::{ContractAddress, SyscallResultTrait, get_tx_info};
use m31_pool::hash::{COMPRESS, SPONGE};
use m31_pool::pool::{IM31PoolDispatcher, IM31PoolDispatcherTrait};
use m31_pool::spend::{IERC20Dispatcher, IERC20DispatcherTrait, Output, Spend, Withdrawal, compute_binding};
use m31_pool::tree::{IM31TreeDispatcher, IM31TreeDispatcherTrait};
use m31_pool::tree::m31_tree_component::M31TreeInternalTrait;
use super::vectors::*;

fn deploy(name: ByteArray, data: Array<felt252>) -> ContractAddress {
    let (address, _) = declare(name).unwrap_syscall().contract_class().deploy(@data).unwrap_syscall();
    address
}
fn payload() -> Span<felt252> {
    array![1, 2, 3, 4, 5, 6, 7, 8, 9, 10].span()
}
fn digest(seed: felt252) -> Span<felt252> {
    array![seed, seed + 1, seed + 2, seed + 3, seed + 4, seed + 5, seed + 6, seed + 7, seed + 8].span()
}
#[derive(Drop)]
struct Setup {
    pool: IM31PoolDispatcher,
    tree: IM31TreeDispatcher,
    token: IERC20Dispatcher,
}
fn setup(format: u8, store_nodes: bool) -> Setup {
    let verifier = deploy("MockVerifier", array![1]);
    let pool = deploy("M31Pool", array![test_address().into(), verifier.into(), format.into(), store_nodes.into()]);
    let token = deploy("E2EToken", array![test_address().into(), 1000000, 0]);
    let t = IERC20Dispatcher { contract_address: token };
    t.approve(pool, 1000000);
    Setup { pool: IM31PoolDispatcher { contract_address: pool }, tree: IM31TreeDispatcher { contract_address: pool }, token: t }
}
fn deposit(s: @Setup, seed: felt252) {
    (*s.pool).deposit((*s.token).contract_address, 100, digest(seed), payload());
}
const RECIPIENT: felt252 = 0xb0b;
#[starknet::interface]
trait IBalance<T> {
    fn balance_of(self: @T, account: ContractAddress) -> u256;
}
fn zero_digest() -> Span<felt252> {
    array![0, 0, 0, 0, 0, 0, 0, 0, 0].span()
}
/// A spend with `n_out` active outputs (0..2) and a withdrawal of `withdrawn` (0 for none).
fn spend_shape(s: @Setup, nf_seed: felt252, cm_seed: felt252, n_out: u32, withdrawn: u128) -> Spend {
    let mut nfs = array![];
    nfs.append_span(digest(nf_seed));
    nfs.append_span(digest(nf_seed + 100));
    let out = |j: u32| if j < n_out {
        Output { commitment: digest(cm_seed + (100 * j).into()), ciphertext: payload() }
    } else {
        Output { commitment: zero_digest(), ciphertext: array![].span() }
    };
    let recipient: ContractAddress = if withdrawn != 0 { RECIPIENT.try_into().unwrap() } else { 0.try_into().unwrap() };
    let mut sp = Spend {
        chain: get_tx_info().unbox().chain_id, pool: (*s.pool).contract_address, token: (*s.token).contract_address,
        root: (*s.tree).get_root(), nullifiers: nfs.span(), outputs: array![out(0), out(1)].span(),
        withdrawal: Withdrawal { recipient, amount: withdrawn }, intent: 0, identity: zero_digest(), binding: 0,
    };
    sp.binding = compute_binding(@sp);
    sp
}
fn spend(s: @Setup, nf_seed: felt252, cm_seed: felt252) -> Spend {
    spend_shape(s, nf_seed, cm_seed, 2, 0)
}

// ---------------------------------------------------------------- correctness

/// The tree's roots after each golden insert equal the client's (one fresh storage per case).
fn check_roots(format: u8, store_nodes: bool) {
    let mut state = m31_pool::pool::M31Pool::contract_state_for_testing();
    state.tree.initializer(format, store_nodes);
    let empty = if format == COMPRESS { EMPTY_ROOT_COMPRESS } else { EMPTY_ROOT_SPONGE };
    let (lo, hi) = state.tree.tree_root.read();
    assert!(m31_pool::hash::unpack(lo, hi).span() == empty.span());
    let roots = if format == COMPRESS { roots_compress() } else { roots_sponge() };
    let mut i = 0;
    for leaf in leaves() {
        state.tree.insert_leaf(leaf);
        let (lo, hi) = state.tree.tree_root.read();
        assert!(m31_pool::hash::unpack(lo, hi).span() == roots.at(i).span());
        i += 1;
    }
}
/// `insert_two` gives the client's roots: single and paired appends mixed, pairs starting at even
/// and odd indices (index 7 = 0b111 meets at level 4).
fn check_batched_roots(format: u8, store_nodes: bool) {
    let mut state = m31_pool::pool::M31Pool::contract_state_for_testing();
    state.tree.initializer(format, store_nodes);
    let roots = if format == COMPRESS { roots_compress() } else { roots_sponge() };
    let l = leaves();
    // (first index, pair?) steps covering all 12 leaves.
    let steps: Array<(u32, bool)> = array![(0, false), (1, true), (3, false), (4, true), (6, false), (7, true), (9, true), (11, false)];
    for (i, pair) in steps {
        if pair {
            let idx = state.tree.insert_two(*l.at(i), *l.at(i + 1));
            assert_eq!(idx, i.into());
            let (lo, hi) = state.tree.tree_root.read();
            assert!(m31_pool::hash::unpack(lo, hi).span() == roots.at(i + 1).span());
        } else {
            state.tree.insert_leaf(*l.at(i));
            let (lo, hi) = state.tree.tree_root.read();
            assert!(m31_pool::hash::unpack(lo, hi).span() == roots.at(i).span());
        }
    }
    assert_eq!(state.tree.tree_count.read(), 12);
}
#[test]
fn batched_roots_match_client_sponge_nodes() { check_batched_roots(SPONGE, true); }
#[test]
fn batched_roots_match_client_sponge_frontier() { check_batched_roots(SPONGE, false); }
#[test]
fn batched_roots_match_client_compress_nodes() { check_batched_roots(COMPRESS, true); }
#[test]
fn batched_roots_match_client_compress_frontier() { check_batched_roots(COMPRESS, false); }

#[test]
fn tree_roots_match_client_sponge_nodes() { check_roots(SPONGE, true); }
#[test]
fn tree_roots_match_client_sponge_frontier() { check_roots(SPONGE, false); }
#[test]
fn tree_roots_match_client_compress_nodes() { check_roots(COMPRESS, true); }
#[test]
fn tree_roots_match_client_compress_frontier() { check_roots(COMPRESS, false); }
use starknet::storage::StoragePointerReadAccess;

#[test]
fn spend_marks_nullifiers_and_publishes() {
    let s = setup(COMPRESS, false);
    deposit(@s, 7);
    s.pool.apply_spend(spend(@s, 1000, 2000), array![].span());
    assert!(s.pool.get_nullifier_spent(digest(1000)));
    assert!(s.pool.get_nullifier_spent(digest(1100)));
    assert_eq!(s.tree.get_leaf_count(), 3);
}
#[test]
#[should_panic(expected: ('NULLIFIER_USED',))]
fn replay_rejected() {
    let s = setup(COMPRESS, false);
    deposit(@s, 7);
    s.pool.apply_spend(spend(@s, 1000, 2000), array![].span());
    s.pool.apply_spend(spend(@s, 1000, 3000), array![].span());
}
#[test]
#[should_panic(expected: ('NULLIFIER_USED',))]
fn duplicate_nullifiers_rejected() {
    let s = setup(COMPRESS, false);
    deposit(@s, 7);
    let mut sp = spend(@s, 1000, 2000);
    let mut nfs = array![];
    nfs.append_span(digest(1000));
    nfs.append_span(digest(1000));
    sp.nullifiers = nfs.span();
    sp.binding = compute_binding(@sp);
    s.pool.apply_spend(sp, array![].span());
}
#[test]
#[should_panic(expected: ('UNKNOWN_ROOT',))]
fn unknown_root_rejected() {
    let s = setup(COMPRESS, false);
    deposit(@s, 7);
    let mut sp = spend(@s, 1000, 2000);
    sp.root = digest(5);
    sp.binding = compute_binding(@sp);
    s.pool.apply_spend(sp, array![].span());
}
#[test]
#[should_panic(expected: ('BAD_BINDING',))]
fn changed_output_rejected() {
    let s = setup(COMPRESS, false);
    deposit(@s, 7);
    let mut sp = spend(@s, 1000, 2000);
    sp.outputs = array![Output { commitment: digest(2001), ciphertext: payload() }, Output { commitment: digest(2100), ciphertext: payload() }].span();
    s.pool.apply_spend(sp, array![].span());
}
#[test]
#[should_panic(expected: ('DIGEST_WORD',))]
fn non_canonical_commitment_rejected() {
    let s = setup(COMPRESS, false);
    deposit(@s, 7);
    let mut sp = spend(@s, 1000, 2000);
    sp.outputs = array![Output { commitment: array![0x7fffffff, 1, 2, 3, 4, 5, 6, 7, 8].span(), ciphertext: payload() }, Output { commitment: digest(2100), ciphertext: payload() }].span();
    sp.binding = compute_binding(@sp);
    s.pool.apply_spend(sp, array![].span());
}
#[test]
fn withdrawals_pay_out_and_skip_inactive_slots() {
    let s = setup(COMPRESS, false);
    deposit(@s, 7);
    deposit(@s, 8);
    s.pool.apply_spend(spend_shape(@s, 1000, 2000, 1, 40), array![].span());
    assert_eq!(s.tree.get_leaf_count(), 3);
    s.pool.apply_spend(spend_shape(@s, 3000, 4000, 0, 60), array![].span());
    assert_eq!(s.tree.get_leaf_count(), 3);
    let bal = IBalanceDispatcher { contract_address: s.token.contract_address };
    assert_eq!(bal.balance_of(RECIPIENT.try_into().unwrap()), 100);
}
#[test]
#[should_panic(expected: ('BAD_WITHDRAWAL',))]
fn withdrawal_without_recipient_rejected() {
    let s = setup(COMPRESS, false);
    deposit(@s, 7);
    let mut sp = spend_shape(@s, 1000, 2000, 1, 40);
    sp.withdrawal = Withdrawal { recipient: 0.try_into().unwrap(), amount: 40 };
    sp.binding = compute_binding(@sp);
    s.pool.apply_spend(sp, array![].span());
}
#[test]
#[should_panic(expected: ('EMPTY_OUTPUT',))]
fn empty_spend_rejected() {
    let s = setup(COMPRESS, false);
    deposit(@s, 7);
    s.pool.apply_spend(spend_shape(@s, 1000, 2000, 0, 0), array![].span());
}
#[test]
#[should_panic(expected: ('BAD_BINDING',))]
fn redirected_withdrawal_rejected() {
    let s = setup(COMPRESS, false);
    deposit(@s, 7);
    let mut sp = spend_shape(@s, 1000, 2000, 1, 40);
    sp.withdrawal = Withdrawal { recipient: 0xabc.try_into().unwrap(), amount: 40 };
    s.pool.apply_spend(sp, array![].span());
}

#[test]
fn old_root_still_accepted() {
    let s = setup(COMPRESS, true);
    deposit(@s, 7);
    let sp = spend(@s, 1000, 2000);
    deposit(@s, 8);
    deposit(@s, 9);
    s.pool.apply_spend(sp, array![].span());
    // Nodes mode serves paths: the first leaf is the deposit commitment.
    assert_eq!(s.tree.get_node(0, 0).len(), 9);
}

// ---------------------------------------------------------------- cost
// Each test prints the L2 (Sierra) gas of one measured call on a warm pool (after `WARM`
// deposits and one spend), and the first (cold) call. `snforge test --gas-report` gives the
// per-selector view including L1 data gas.

const WARM: u32 = 4;

/// Warm pool: `WARM` deposits then one spend. With `measured`, one more deposit (or spend) is
/// timed; the twin without it lets per-call L1 data gas be read as the difference of test totals.
fn warm_pool(format: u8, store_nodes: bool) -> Setup {
    let s = setup(format, store_nodes);
    let mut i = 0;
    while i < WARM {
        deposit(@s, (i * 10 + 100).into());
        i += 1;
    }
    s.pool.apply_spend(spend(@s, 1000, 2000), array![].span());
    s
}

fn measure_deposit(format: u8, store_nodes: bool, measured: bool) {
    let s = warm_pool(format, store_nodes);
    if measured {
        let g = get_available_gas();
        deposit(@s, 999);
        println!("GAS deposit format={} store_nodes={} warm={}", format, store_nodes, g - get_available_gas());
    }
}

fn measure_spend(format: u8, store_nodes: bool, measured: bool) {
    measure_spend_shape(format, store_nodes, measured, 2, 0);
}

fn measure_spend_shape(format: u8, store_nodes: bool, measured: bool, n_out: u32, withdrawn: u128) {
    let s = warm_pool(format, store_nodes);
    let sp = spend_shape(@s, 3000, 4000, n_out, withdrawn);
    if measured {
        let g = get_available_gas();
        s.pool.apply_spend(sp, array![].span());
        println!("GAS apply_spend format={} store_nodes={} outputs={} withdrawal={} warm={}", format, store_nodes, n_out, withdrawn != 0, g - get_available_gas());
    }
}

#[test]
fn cost_base_compress_frontier() { measure_deposit(COMPRESS, false, false); }
#[test]
fn cost_base_compress_nodes() { measure_deposit(COMPRESS, true, false); }
#[test]
fn cost_base_sponge_frontier() { measure_deposit(SPONGE, false, false); }
#[test]
fn cost_base_sponge_nodes() { measure_deposit(SPONGE, true, false); }
#[test]
fn cost_deposit_compress_frontier() { measure_deposit(COMPRESS, false, true); }
#[test]
fn cost_deposit_compress_nodes() { measure_deposit(COMPRESS, true, true); }
#[test]
fn cost_deposit_sponge_frontier() { measure_deposit(SPONGE, false, true); }
#[test]
fn cost_deposit_sponge_nodes() { measure_deposit(SPONGE, true, true); }
#[test]
fn cost_spend_compress_frontier() { measure_spend(COMPRESS, false, true); }
#[test]
fn cost_spend_compress_nodes() { measure_spend(COMPRESS, true, true); }
#[test]
fn cost_spend_sponge_frontier() { measure_spend(SPONGE, false, true); }
#[test]
fn cost_spend_sponge_nodes() { measure_spend(SPONGE, true, true); }

#[test]
fn cost_partial_compress_frontier() { measure_spend_shape(COMPRESS, false, true, 1, 40); }
#[test]
fn cost_full_compress_frontier() { measure_spend_shape(COMPRESS, false, true, 0, 40); }
#[test]
fn cost_partial_sponge_frontier() { measure_spend_shape(SPONGE, false, true, 1, 40); }
#[test]
fn cost_full_sponge_frontier() { measure_spend_shape(SPONGE, false, true, 0, 40); }

// ---------------------------------------------------------------- batched transfer cost by start
// A transfer's two outputs start at the leaf count. Pool: `n` deposits then a transfer, so the
// measured transfer starts at n + 2: 5 (odd, +1 hash), 6 (even, 32 hashes), 7 (0b111, +3 hashes).

fn measure_transfer_at(format: u8, store_nodes: bool, n: u32, measured: bool) {
    let s = setup(format, store_nodes);
    let mut i = 0;
    while i < n {
        deposit(@s, (i * 10 + 100).into());
        i += 1;
    }
    s.pool.apply_spend(spend(@s, 1000, 2000), array![].span());
    let sp = spend(@s, 3000, 4000);
    if measured {
        let start = s.tree.get_leaf_count();
        let g = get_available_gas();
        s.pool.apply_spend(sp, array![].span());
        println!("GAS transfer_batched format={} store_nodes={} start={} warm={}", format, store_nodes, start, g - get_available_gas());
    }
}

#[test]
fn cost_tb_base_c_f_3() { measure_transfer_at(COMPRESS, false, 3, false); }
#[test]
fn cost_tb_base_c_f_4() { measure_transfer_at(COMPRESS, false, 4, false); }
#[test]
fn cost_tb_base_c_f_5() { measure_transfer_at(COMPRESS, false, 5, false); }
#[test]
fn cost_tb_c_f_3() { measure_transfer_at(COMPRESS, false, 3, true); }
#[test]
fn cost_tb_c_f_4() { measure_transfer_at(COMPRESS, false, 4, true); }
#[test]
fn cost_tb_c_f_5() { measure_transfer_at(COMPRESS, false, 5, true); }
#[test]
fn cost_tb_c_n_4() { measure_transfer_at(COMPRESS, true, 4, true); }
#[test]
fn cost_tb_base_c_n_4() { measure_transfer_at(COMPRESS, true, 4, false); }
#[test]
fn cost_tb_s_f_3() { measure_transfer_at(SPONGE, false, 3, true); }
#[test]
fn cost_tb_s_f_4() { measure_transfer_at(SPONGE, false, 4, true); }
#[test]
fn cost_tb_s_f_5() { measure_transfer_at(SPONGE, false, 5, true); }
