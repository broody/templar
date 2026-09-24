//! Open-note executions (`apply_spend_with_invoke`): functional paths with the test adapters.
//! Adversarial cases follow after the implementation review.
use core::testing::get_available_gas;
use snforge_std::{ContractClassTrait, DeclareResultTrait, declare, test_address};
use starknet::{ContractAddress, SyscallResultTrait, get_tx_info};
use m31_pool::open_note::{
    COMPUTE, ExecutionIntent, INVOKE, OpenDestination, hash_intent, identity_commitment, partial_commitment,
};
use m31_pool::pool::{IM31PoolDispatcher, IM31PoolDispatcherTrait};
use m31_pool::spend::{IERC20Dispatcher, IERC20DispatcherTrait, Output, Spend, Withdrawal, compute_binding};
use m31_pool::test_adapters::{IMockShadowAnonymizerDispatcher, IMockShadowAnonymizerDispatcherTrait, Proceeds};
use m31_pool::tree::{IM31TreeDispatcher, IM31TreeDispatcherTrait};

fn deploy(name: ByteArray, data: Array<felt252>) -> ContractAddress {
    let (address, _) = declare(name).unwrap_syscall().contract_class().deploy(@data).unwrap_syscall();
    address
}
#[starknet::interface]
trait IFaucet<T> {
    fn faucet(ref self: T, to: ContractAddress, amount: u256);
}
fn payload(seed: felt252) -> Span<felt252> {
    array![seed, 2, 3, 4, 5, 6, 7, 8, 9, 10].span()
}
fn digest(seed: felt252) -> Span<felt252> {
    array![seed, seed + 1, seed + 2, seed + 3, seed + 4, seed + 5, seed + 6, seed + 7, seed + 8].span()
}
fn zero_digest() -> Span<felt252> {
    array![0, 0, 0, 0, 0, 0, 0, 0, 0].span()
}
#[derive(Drop)]
struct Env {
    pool: IM31PoolDispatcher,
    tree: IM31TreeDispatcher,
    a: IERC20Dispatcher,
    b: IERC20Dispatcher,
    c: IERC20Dispatcher,
}
/// A pool (single-permutation nodes, frontier storage), three tokens, and one deposited note of
/// token A so the pool holds the budget.
fn env() -> Env {
    let verifier = deploy("MockVerifier", array![1]);
    let pool = deploy("M31Pool", array![test_address().into(), verifier.into(), 1, 0]);
    let (a, b, c) = (new_token(), new_token(), new_token());
    a.approve(pool, 1000000);
    let p = IM31PoolDispatcher { contract_address: pool };
    p.deposit(a.contract_address, 100, digest(7), payload(1));
    Env { pool: p, tree: IM31TreeDispatcher { contract_address: pool }, a, b, c }
}
fn new_token() -> IERC20Dispatcher {
    IERC20Dispatcher { contract_address: deploy("E2EToken", array![test_address().into(), 1000000, 0]) }
}
fn mint(token: IERC20Dispatcher, to: ContractAddress, amount: u256) {
    IFaucetDispatcher { contract_address: token.contract_address }.faucet(to, amount);
}
/// A spend of token A with `n_out` private outputs, a budget of `budget` to `recipient`, and the
/// identity handle `identity` (zero for none). Intent and binding are filled by `finish`.
fn spend(e: @Env, nf_seed: felt252, n_out: u32, budget: u128, recipient: ContractAddress, identity: Span<felt252>) -> Spend {
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
        withdrawal: Withdrawal { recipient, amount: budget }, intent: 0, identity, binding: 0,
    }
}
fn finish(ref sp: Spend, intent: @ExecutionIntent) {
    sp.intent = hash_intent(@sp, intent);
    sp.binding = compute_binding(@sp);
}
fn serialize_swap(in_token: ContractAddress, in_amount: u128, proceeds: Array<Proceeds>) -> Span<felt252> {
    let mut data = array![];
    in_token.serialize(ref data);
    in_amount.serialize(ref data);
    proceeds.span().serialize(ref data);
    data.span()
}

/// A swap: budget 40 of A to the adapter, 480 of B back into one open note; one private change
/// output. The pool holds the proceeds and two leaves are appended.
#[test]
fn invoke_swap_into_one_open_note() {
    let e = env();
    let adapter = deploy("MockSwapAdapter", array![]);
    mint(e.b, adapter, 500);
    let mut sp = spend(@e, 1000, 1, 40, adapter, zero_digest());
    let intent = ExecutionIntent {
        kind: INVOKE, adapter, nonce: 0, expiry: 1000000,
        calldata: serialize_swap(e.a.contract_address, 40, array![Proceeds { note_id: 77, token: e.b.contract_address, amount: 480 }]),
        destinations: array![OpenDestination { note_id: 77, token: e.b.contract_address, minimum: 450, inner: digest(900), ciphertext: payload(9) }].span(),
    };
    finish(ref sp, @intent);
    let before = e.tree.get_leaf_count();
    let g = get_available_gas();
    e.pool.apply_spend_with_invoke(sp, intent, array![].span());
    println!("GAS apply_spend_with_invoke one_open_note one_output={}", g - get_available_gas());
    assert_eq!(e.tree.get_leaf_count(), before + 2);
    assert_eq!(e.b.balance_of(e.pool.contract_address), 480);
    assert_eq!(e.a.balance_of(adapter), 40);
    assert!(e.pool.get_delivery_digest(before + 1) != 0);
}

/// Two open notes (tokens B and C) with two private outputs: the four-note cap.
#[test]
fn invoke_two_open_notes_with_two_outputs() {
    let e = env();
    let adapter = deploy("MockSwapAdapter", array![]);
    mint(e.b, adapter, 300);
    mint(e.c, adapter, 300);
    let mut sp = spend(@e, 2000, 2, 30, adapter, zero_digest());
    let intent = ExecutionIntent {
        kind: INVOKE, adapter, nonce: 0, expiry: 1000000,
        calldata: serialize_swap(
            e.a.contract_address, 30,
            array![Proceeds { note_id: 1, token: e.b.contract_address, amount: 120 }, Proceeds { note_id: 2, token: e.c.contract_address, amount: 250 }],
        ),
        destinations: array![
            OpenDestination { note_id: 1, token: e.b.contract_address, minimum: 100, inner: digest(910), ciphertext: payload(11) },
            OpenDestination { note_id: 2, token: e.c.contract_address, minimum: 200, inner: digest(920), ciphertext: payload(12) },
        ].span(),
    };
    finish(ref sp, @intent);
    let before = e.tree.get_leaf_count();
    let g = get_available_gas();
    e.pool.apply_spend_with_invoke(sp, intent, array![].span());
    println!("GAS apply_spend_with_invoke two_open_notes two_outputs={}", g - get_available_gas());
    assert_eq!(e.tree.get_leaf_count(), before + 4);
    assert_eq!(e.b.balance_of(e.pool.contract_address), 120);
    assert_eq!(e.c.balance_of(e.pool.contract_address), 250);
}

/// A shadow-account execution with a zero budget (collect only): the anonymizer receives
/// `Poseidon(partial(identity), 0)`, and the collected tokens fund an open note.
#[test]
fn shadow_compute_passes_identity_commitment() {
    let e = env();
    let shadow = deploy("MockShadowAnonymizer", array![]);
    mint(e.c, shadow, 100);
    let identity = digest(3000);
    let mut sp = spend(@e, 3000, 1, 0, 0.try_into().unwrap(), identity);
    let mut calldata = array![];
    array![Proceeds { note_id: 91, token: e.c.contract_address, amount: 60 }].span().serialize(ref calldata);
    let intent = ExecutionIntent {
        kind: COMPUTE, adapter: shadow, nonce: 0, expiry: 1000000, calldata: calldata.span(),
        destinations: array![OpenDestination { note_id: 91, token: e.c.contract_address, minimum: 60, inner: digest(930), ciphertext: payload(13) }].span(),
    };
    finish(ref sp, @intent);
    let before = e.tree.get_leaf_count();
    e.pool.apply_spend_with_invoke(sp, intent, array![].span());
    let expected = identity_commitment(partial_commitment(identity), 0);
    assert_eq!(IMockShadowAnonymizerDispatcher { contract_address: shadow }.last_identity_commitment(), expected);
    assert_eq!(e.c.balance_of(e.pool.contract_address), 60);
    assert_eq!(e.tree.get_leaf_count(), before + 2);
}
