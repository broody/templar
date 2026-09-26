//! R0 V5 end to end against M31 pool V3 (`docs/account-bound-note-spec.md` §15 P3b). Real client
//! proofs (`wallet prove5`) spend notes the pool holds. Each runs through the real statement
//! account, whose bridge verifies the proof; in bound mode, a mock account at `A` accepts only the
//! exact SNIP-12 hash starknet.js computed and the fixture's signature. The account's one L2→L1
//! message becomes the proof facts that the V5 `Proof2Adapter` checks for the pool, and the pool
//! recomputes the binding from its own calldata.
//!
//! The virtual OS and PROOF2 are P5. Here snforge runs the account with a cheated caller and
//! chain, and the facts carry the message hash the OS commits to: `Poseidon(from, to, n, payload)`.
//!
//! Fixtures (`bench/m31-pool/account_bound_e2e.py`, public data only): two deposits (a note bound
//! to `A` and an ordinary note), then S1, a bound withdrawal, and S2, an ordinary transfer. Both
//! are proved against the tree after the deposits.
use core::poseidon::poseidon_hash_span;
use core::testing::get_available_gas;
use snforge_std::fs::{FileTrait, read_txt};
use snforge_std::{
    ContractClassTrait, DeclareResultTrait, MessageToL1SpyTrait, declare, spy_messages_to_l1,
    start_cheat_block_number_global, start_cheat_caller_address, start_cheat_chain_id_global, start_cheat_proof_facts,
    stop_cheat_caller_address, test_address,
};
use starknet::syscalls::get_class_hash_at_syscall;
use starknet::{ContractAddress, SyscallResultTrait};
use m31_pool::pool_v3::{IM31PoolV3Dispatcher, IM31PoolV3DispatcherTrait};
use m31_pool::spend::{IERC20Dispatcher, IERC20DispatcherTrait};
use m31_pool::spend5::{Spend, compute_binding};
use m31_pool::tree_v3::{IM31TreeV3Dispatcher, IM31TreeV3DispatcherTrait};
use templar_account_tests::{IStatementAccountDispatcher, IStatementAccountDispatcherTrait, MODE_CHECK};

const SUBMITTER: felt252 = 0x5ab317;
const MAX_PROOF_AGE: u64 = 1024;

fn addr(x: felt252) -> ContractAddress {
    x.try_into().unwrap()
}
fn read(name: ByteArray) -> Span<felt252> {
    read_txt(@FileTrait::new(format!("fixtures/{name}.txt"))).span()
}
fn spend(name: ByteArray) -> Spend {
    let mut f = read(format!("{name}-spend"));
    let s: Spend = Serde::deserialize(ref f).unwrap();
    assert!(f.is_empty());
    s
}

/// `constants.txt`: chain, pool, token, account, recipient, E, Q, W, T, submit block, base block,
/// OS program, pool class, the root after the deposits (9), salt, hash, poseidon(signature), S1's
/// withdrawal amount, then the signature.
#[derive(Drop, Copy)]
struct C {
    chain: felt252,
    pool: felt252,
    token: felt252,
    account: felt252,
    recipient: felt252,
    e: felt252,
    q: u64,
    w: felt252,
    t: felt252,
    submit: u64,
    base: u64,
    os_program: felt252,
    pool_class: felt252,
    root: Span<felt252>,
    salt: felt252,
    hash: felt252,
    signature_hash: felt252,
    amount: u128,
    signature: Span<felt252>,
}
fn constants() -> C {
    let c = read("constants");
    C {
        chain: *c.at(0), pool: *c.at(1), token: *c.at(2), account: *c.at(3), recipient: *c.at(4), e: *c.at(5),
        q: (*c.at(6)).try_into().unwrap(), w: *c.at(7), t: *c.at(8), submit: (*c.at(9)).try_into().unwrap(),
        base: (*c.at(10)).try_into().unwrap(), os_program: *c.at(11), pool_class: *c.at(12), root: c.slice(13, 9),
        salt: *c.at(22), hash: *c.at(23), signature_hash: *c.at(24), amount: (*c.at(25)).try_into().unwrap(),
        signature: c.slice(26, c.len() - 26),
    }
}

#[derive(Drop, Copy)]
struct Env {
    c: C,
    pool: IM31PoolV3Dispatcher,
    tree: IM31TreeV3Dispatcher,
    token: IERC20Dispatcher,
    statement: IStatementAccountDispatcher,
    adapter: ContractAddress,
    deposited: u128,
    leaves: u64,
}

fn deploy_at(name: ByteArray, data: Array<felt252>, at: felt252) {
    declare(name).unwrap().contract_class().deploy_at(@data, addr(at)).unwrap_syscall();
}

/// The token, the statement account, the mock bound account at `A`, pool V3 at the proofs' pool
/// address with the V5 adapter as its R0 verifier, and the deposits replayed in the wallet's order.
fn setup() -> Env {
    let c = constants();
    start_cheat_chain_id_global(c.chain);
    start_cheat_block_number_global(c.submit);
    let me = test_address();
    deploy_at("E2EToken", array![me.into(), 1000000000, 0], c.token);
    let class = declare("PaymentVerifierAccount").unwrap().contract_class();
    let (statement, _) = class.deploy(@array![]).unwrap();
    deploy_at("MockAccount", array![MODE_CHECK, c.hash, c.signature_hash, statement.into()], c.account);
    deploy_at("M31PoolV3", array![me.into(), 1, c.e, c.q.into(), c.w, c.t], c.pool);
    let class_hash: felt252 = get_class_hash_at_syscall(addr(c.pool)).unwrap_syscall().into();
    assert!(class_hash == c.pool_class, "the pool is bench/m31-pool's M31PoolV3 class");
    let (adapter, _) = declare("Proof2Adapter")
        .unwrap()
        .contract_class()
        .deploy(@array![c.pool, statement.into(), (*class.class_hash).into(), c.os_program, MAX_PROOF_AGE.into(), 'TMPZR0_PAYMENT_V5'])
        .unwrap();
    let (p1, _) = declare("MockVerifier").unwrap().contract_class().deploy(@array![0]).unwrap();
    let pool = IM31PoolV3Dispatcher { contract_address: addr(c.pool) };
    pool.initialize(adapter, p1, array![].span());
    let token = IERC20Dispatcher { contract_address: addr(c.token) };
    token.approve(addr(c.pool), 1000000000);
    let mut d = read("deposits");
    let mut deposited = 0;
    let mut leaves = 0;
    while !d.is_empty() {
        let amount: u128 = (*d.pop_front().unwrap()).try_into().unwrap();
        pool.deposit(addr(c.token), amount, d.slice(0, 9), d.slice(9, 10));
        d = d.slice(19, d.len() - 19);
        deposited += amount;
        leaves += 1;
    }
    let tree = IM31TreeV3Dispatcher { contract_address: addr(c.pool) };
    assert!(tree.get_root() == c.root, "the pool's tree is the wallet's");
    Env {
        c, pool, tree, token, statement: IStatementAccountDispatcher { contract_address: statement }, adapter,
        deposited, leaves,
    }
}

/// Runs the statement account as the OS does (caller 0) and returns the proof facts of its one
/// message, for a virtual execution based on block `base`.
fn authorize(e: Env, name: ByteArray, salt: felt252, signature: Span<felt252>, base: u64) -> Span<felt252> {
    let mut spy = spy_messages_to_l1();
    start_cheat_caller_address(e.statement.contract_address, addr(0));
    e.statement.__execute__(read(format!("{name}-proof")), salt, signature);
    stop_cheat_caller_address(e.statement.contract_address);
    let messages = spy.get_messages().messages;
    assert_eq!(messages.len(), 1);
    let (from, m) = messages.at(0);
    let mut message = array![(*from).into(), (*m.to_address).into(), m.payload.len().into()];
    message.append_span(m.payload.span());
    array!['PROOF2', 'VIRTUAL_SNOS', e.c.os_program, 'VIRTUAL_SNOS0', base.into(), 0xb10c, 0, 1, poseidon_hash_span(message.span())]
        .span()
}
fn authorize_s1(e: Env) -> Span<felt252> {
    authorize(e, "s1", e.c.salt, e.c.signature, e.c.base)
}
fn authorize_s2(e: Env) -> Span<felt252> {
    authorize(e, "s2", 0, array![].span(), e.c.base)
}

/// A third party submits: nothing in the pool checks who.
fn submit(e: Env, facts: Span<felt252>, s: Spend) -> u128 {
    start_cheat_proof_facts(e.adapter, facts);
    start_cheat_caller_address(e.pool.contract_address, addr(SUBMITTER));
    let g = get_available_gas();
    e.pool.apply_spend(s, array![].span());
    let used = g - get_available_gas();
    stop_cheat_caller_address(e.pool.contract_address);
    used
}

#[test]
fn bound_withdrawal_then_ordinary_transfer() {
    let e = setup();
    let s1 = spend("s1");
    let s2 = spend("s2");
    assert!(s1.root == e.c.root && s2.root == e.c.root);
    // S1: bound to `A`, withdraws to the recipient.
    let nf1 = s1.nullifiers;
    let gas = submit(e, authorize_s1(e), s1);
    println!("GAS apply_spend v5 bound_withdrawal real_adapter={gas}");
    assert_eq!(e.token.balance_of(addr(e.c.recipient)), e.c.amount.into());
    assert_eq!(e.pool.get_held(e.c.token), (e.deposited - e.c.amount).into());
    assert_eq!(e.tree.get_leaf_count(), e.leaves + 2);
    assert!(e.pool.get_nullifier_spent(nf1.slice(0, 9)) && e.pool.get_nullifier_spent(nf1.slice(9, 9)));
    // S2's root was replaced by S1 and is still within the window.
    assert!(e.tree.get_root() != s2.root && e.tree.root_is_known(s2.root));
    let nf2 = s2.nullifiers;
    let gas = submit(e, authorize_s2(e), s2);
    println!("GAS apply_spend v5 ordinary_transfer real_adapter={gas}");
    assert_eq!(e.tree.get_leaf_count(), e.leaves + 4);
    assert!(e.pool.get_nullifier_spent(nf2.slice(0, 9)) && e.pool.get_nullifier_spent(nf2.slice(9, 9)));
    assert_eq!(e.pool.get_held(e.c.token), (e.deposited - e.c.amount).into());
    assert_eq!(e.token.balance_of(addr(SUBMITTER)), 0);
}

/// A bound spend lands at `valid_until` itself, with a proof based on a late enough block.
#[test]
fn bound_withdrawal_lands_at_valid_until() {
    let e = setup();
    let s1 = spend("s1");
    let last = s1.valid_until;
    assert!(last % e.c.q == 0 && last > e.c.submit);
    start_cheat_block_number_global(last);
    submit(e, authorize(e, "s1", e.c.salt, e.c.signature, last - 11), s1);
    assert_eq!(e.token.balance_of(addr(e.c.recipient)), e.c.amount.into());
}

/// Another salt changes the hash the account is asked to sign: the account refuses, so no message.
#[test]
#[should_panic(expected: "SIG_NOT_VALID")]
fn bound_spend_needs_the_accounts_signature() {
    let e = setup();
    authorize(e, "s1", e.c.salt + 1, e.c.signature, e.c.base);
}

#[test]
#[should_panic(expected: 'SPEND_EXPIRED')]
fn expired_spend_rejected() {
    let e = setup();
    let s1 = spend("s1");
    let facts = authorize_s1(e);
    start_cheat_block_number_global(s1.valid_until + 1);
    submit(e, facts, s1);
}

/// Moving `valid_until` (still on the grid) changes the binding the pool computes: the account's
/// message no longer matches.
#[test]
#[should_panic(expected: 'PROOF_BINDING')]
fn moved_expiry_rejected() {
    let e = setup();
    let mut s1 = spend("s1");
    s1.valid_until -= e.c.q;
    s1.binding = compute_binding(@s1);
    submit(e, authorize_s1(e), s1);
}

#[test]
#[should_panic(expected: 'PROOF_BINDING')]
fn another_spends_facts_rejected() {
    let e = setup();
    submit(e, authorize_s2(e), spend("s1"));
}

#[test]
#[should_panic(expected: 'BAD_BINDING')]
fn redirected_withdrawal_rejected() {
    let e = setup();
    let mut s1 = spend("s1");
    s1.withdrawal.recipient = addr(0xbad);
    submit(e, authorize_s1(e), s1);
}

#[test]
#[should_panic(expected: 'NULLIFIER_USED')]
fn replay_rejected() {
    let e = setup();
    let facts = authorize_s1(e);
    submit(e, facts, spend("s1"));
    submit(e, facts, spend("s1"));
}
