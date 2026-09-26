//! The routing adapter (`docs/pool-v3-spec.md` §6) against a real pool V3, with facts injected by
//! snforge: the constructor's checks, routing and `NO_ROUTE` (a V5 message included), per-route
//! proof ages, every row and edge case of §6.3's precondition table (the activation gate, the owner
//! read from the pool, the timelock window, `MAX_ROUTES` and `MAX_PENDING` with lapsed proposals,
//! same-key replacement, the class re-check at apply, the last-route refusal, cancel while inactive,
//! retired keys), the class re-check in `verify`, a pending route's proofs refused until apply, both
//! kinds' activation gates, the views, the events and the shared encoding vectors
//! (`sdk/vectors/routing.json`). Real statement-account messages run in
//! `client-port/cairo-r6/pool_e2e`; the P1 path through the pool runs in `test_pool_v3`.
use core::poseidon::poseidon_hash_span;
use snforge_std::{
    ContractClassTrait, DeclareResultTrait, EventSpyAssertionsTrait, declare, spy_events,
    start_cheat_block_number, start_cheat_block_number_global, start_cheat_block_timestamp_global,
    start_cheat_caller_address, start_cheat_chain_id, start_cheat_proof_facts, stop_cheat_caller_address, test_address,
};
use starknet::syscalls::get_class_hash_at_syscall;
use starknet::{ContractAddress, SyscallResultTrait};
use m31_pool::pool_v3::{IM31PoolV3Dispatcher, IM31PoolV3DispatcherTrait, P1, R0};
use m31_pool::routing_adapter::RoutingAdapter::{Event, RouteCancelled, RouteProposed, RouteSet};
use m31_pool::routing_adapter::{
    IRoutingAdapterDispatcher, IRoutingAdapterDispatcherTrait, IRoutingAdapterSafeDispatcher,
    IRoutingAdapterSafeDispatcherTrait, Route, RouteProposal,
};
use m31_pool::spend::{IVerifierSafeDispatcher, IVerifierSafeDispatcherTrait};
use m31_pool::spend5::compute_binding;
use m31_pool::test_adapters::{IReplaceableDispatcher, IReplaceableDispatcherTrait};
use super::binding_v6_vectors::vectors as v6_binding_vectors;
use super::routing_vectors;

const E: u64 = 1500;
const Q: u64 = 100;
const W: u64 = 4096;
const T: u64 = 7200;
const START: u64 = 1000;
const NOW: u64 = 1000000;
const OS: felt252 = 0x53f6c9fcfd31d27279ff7d7e422b44623550a732b59fe193354a7316a96daa1;
const TAG6: felt252 = 'TMPZR0_PAYMENT_V6';

fn addr(v: felt252) -> ContractAddress {
    v.try_into().unwrap()
}
fn deploy(name: ByteArray, data: Array<felt252>) -> ContractAddress {
    let (address, _) = declare(name).unwrap_syscall().contract_class().deploy(@data).unwrap_syscall();
    address
}
fn class_of(a: ContractAddress) -> felt252 {
    get_class_hash_at_syscall(a).unwrap_syscall().into()
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
}

/// A pool V3 owned by the test, at block `START` and time `NOW`, not initialized.
fn pool() -> Env {
    start_cheat_block_number_global(START);
    start_cheat_block_timestamp_global(NOW);
    let pool = deploy("M31PoolV3", array![test_address().into(), 1, E.into(), Q.into(), W.into(), T.into()]);
    Env { pool: IM31PoolV3Dispatcher { contract_address: pool } }
}

/// A deployed stand-in statement account (any class works; the route pins it).
fn statement() -> ContractAddress {
    deploy("MockVerifier", array![1])
}

fn route_at(statement: ContractAddress, age: u64) -> Route {
    Route {
        statement, statement_class: class_of(statement), account_tag: TAG6, os_program: OS, proof_version: 'PROOF2',
        proof_variant: 'VIRTUAL_SNOS', output_version: 'VIRTUAL_SNOS0', max_proof_age: age,
    }
}
fn route() -> Route {
    route_at(statement(), 1024)
}

fn adapter_args(pool: ContractAddress, kind: felt252, routes: Span<Route>) -> Array<felt252> {
    let mut a = array![pool.into(), kind];
    routes.serialize(ref a);
    a
}
fn try_adapter(pool: ContractAddress, kind: felt252, routes: Span<Route>) -> Result<ContractAddress, Array<felt252>> {
    match declare("RoutingAdapter").unwrap_syscall().contract_class().deploy(@adapter_args(pool, kind, routes)) {
        Ok((a, _)) => Ok(a),
        Err(e) => Err(e),
    }
}
fn adapter(e: Env, kind: felt252, routes: Span<Route>) -> IRoutingAdapterDispatcher {
    IRoutingAdapterDispatcher { contract_address: try_adapter(e.pool.contract_address, kind, routes).unwrap() }
}
fn safe(a: IRoutingAdapterDispatcher) -> IRoutingAdapterSafeDispatcher {
    IRoutingAdapterSafeDispatcher { contract_address: a.contract_address }
}

/// An R0 routing adapter with `routes`, made the pool's R0 verifier (active).
fn active(routes: Span<Route>) -> (Env, IRoutingAdapterDispatcher) {
    let e = pool();
    let a = adapter(e, R0, routes);
    e.pool.initialize(a.contract_address, deploy("MockVerifier", array![1]), array![].span());
    (e, a)
}

fn at(t: u64) {
    start_cheat_block_timestamp_global(t);
}

// ---------------------------------------------------------------- constructor

#[test]
fn constructor_sets_routes_and_emits() {
    let e = pool();
    let (r1, r2) = (route(), route());
    let mut spy = spy_events();
    let a = adapter(e, R0, array![r1, r2].span());
    assert!(a.get_pool() == e.pool.contract_address && a.get_kind() == R0);
    assert!(a.get_routes() == array![r1, r2]);
    assert!(a.get_route(r1.statement) == Option::Some(r1) && a.get_route(r2.statement) == Option::Some(r2));
    assert!(a.get_route(addr(0x999)) == Option::None);
    assert!(a.get_route_proposals() == array![]);
    spy.assert_emitted(@array![
        (a.contract_address, Event::RouteSet(RouteSet { statement: r1.statement, route: Option::Some(r1) })),
        (a.contract_address, Event::RouteSet(RouteSet { statement: r2.statement, route: Option::Some(r2) })),
    ]);
    // A P1 adapter, four routes (MAX_ROUTES).
    let p1 = adapter(e, P1, array![route(), route(), route(), route()].span());
    assert!(p1.get_kind() == P1 && p1.get_routes().len() == 4);
}

#[test]
fn constructor_rejects_bad_configuration() {
    let e = pool();
    let p = e.pool.contract_address;
    let r = route();
    assert!(reason(try_adapter(addr(0), R0, array![r].span())) == 'ZERO_ADDRESS');
    assert!(reason(try_adapter(p, 'R1', array![r].span())) == 'ADAPTER_KIND');
    assert!(reason(try_adapter(p, R0, array![].span())) == 'ROUTE_COUNT');
    assert!(reason(try_adapter(p, R0, array![route(), route(), route(), route(), route()].span())) == 'ROUTE_COUNT');
    assert!(reason(try_adapter(p, R0, array![r, r].span())) == 'DUPLICATE_ROUTE');
    // Every field nonzero.
    for k in 0..8_u32 {
        let mut b = r;
        match k {
            0 => b.statement = addr(0),
            1 => b.statement_class = 0,
            2 => b.account_tag = 0,
            3 => b.os_program = 0,
            4 => b.proof_version = 0,
            5 => b.proof_variant = 0,
            6 => b.output_version = 0,
            _ => b.max_proof_age = 0,
        }
        assert!(reason(try_adapter(p, R0, array![b].span())) == 'BAD_ROUTE', "field {}", k);
    }
    // 0 < max_proof_age ≤ E + Q.
    assert!(try_adapter(p, R0, array![route_at(statement(), E + Q)].span()).is_ok());
    assert!(reason(try_adapter(p, R0, array![route_at(statement(), E + Q + 1)].span())) == 'PROOF_AGE_BOUND');
    // Not the pool; the class on chain.
    let mut b = r;
    b.statement = p;
    b.statement_class = class_of(p);
    assert!(reason(try_adapter(p, R0, array![b].span())) == 'ROUTE_ADDRESS');
    let mut b = r;
    b.statement_class = r.statement_class + 1;
    assert!(reason(try_adapter(p, R0, array![b].span())) == 'ROUTE_CLASS');
    let mut b = r;
    b.statement = addr(0xdead);
    assert!(reason(try_adapter(p, R0, array![b].span())) == 'ROUTE_CLASS', "an undeployed statement");
}

// ---------------------------------------------------------------- verify

/// The facts of a virtual execution of `r`'s statement emitting `[class, tag, chain, pool,
/// binding]`, at base block `base`.
fn facts_for(r: Route, tag: felt252, chain: felt252, pool: ContractAddress, binding: felt252, base: u64) -> Array<felt252> {
    let message = array![r.statement.into(), 0, 5, r.statement_class, tag, chain, pool.into(), binding];
    array![
        r.proof_version, r.proof_variant, r.os_program, r.output_version, base.into(), 0xb10c, 0, 1,
        poseidon_hash_span(message.span()),
    ]
}

/// `verify` as the pool calls it, at block `current`, with `facts`.
#[feature("safe_dispatcher")]
fn verify_with(e: Env, a: IRoutingAdapterDispatcher, facts: Span<felt252>, current: u64, binding: felt252) -> Result<bool, Array<felt252>> {
    let v = IVerifierSafeDispatcher { contract_address: a.contract_address };
    start_cheat_caller_address(a.contract_address, e.pool.contract_address);
    start_cheat_chain_id(a.contract_address, 'SN_SEPOLIA');
    start_cheat_block_number(a.contract_address, current);
    start_cheat_proof_facts(a.contract_address, facts);
    let r = v.verify(array![].span(), array!['SN_SEPOLIA', e.pool.contract_address.into(), binding].span());
    stop_cheat_caller_address(a.contract_address);
    r
}

#[test]
#[feature("safe_dispatcher")]
fn verify_routes_and_rejects() {
    let e = pool();
    let r = route_at(statement(), 20);
    let a = adapter(e, R0, array![r].span());
    let good = facts_for(r, TAG6, 'SN_SEPOLIA', e.pool.contract_address, 0xb1d, 190);
    assert!(verify_with(e, a, good.span(), 200, 0xb1d) == Ok(true));
    // Age: base < current and current − base ≤ the route's age.
    assert!(verify_with(e, a, good.span(), 210, 0xb1d) == Ok(true));
    assert!(reason(verify_with(e, a, good.span(), 211, 0xb1d)) == 'PROOF_AGE');
    assert!(reason(verify_with(e, a, good.span(), 190, 0xb1d)) == 'PROOF_AGE');
    let mut f = good.clone();
    let mut over = array![];
    for (i, x) in f.span().into_iter().enumerate() {
        over.append(if i == 4 { 0x10000000000000000 } else { *x });
    }
    assert!(reason(verify_with(e, a, over.span(), 200, 0xb1d)) == 'BASE_BLOCK');
    // Each of facts[0], [1], [2], [3] and [8] off: no route matches.
    for i in array![0_usize, 1, 2, 3, 8] {
        let mut m = array![];
        for (k, x) in good.span().into_iter().enumerate() {
            m.append(if k == i { *x + 1 } else { *x });
        }
        assert!(reason(verify_with(e, a, m.span(), 200, 0xb1d)) == 'NO_ROUTE', "fact {}", i);
    }
    // Another binding: the message hash no longer matches.
    assert!(reason(verify_with(e, a, good.span(), 200, 0xb1e)) == 'NO_ROUTE');
    // A V5 message from the same statement (V5's tag): NO_ROUTE.
    let v5 = facts_for(r, 'TMPZR0_PAYMENT_V5', 'SN_SEPOLIA', e.pool.contract_address, 0xb1d, 190);
    assert!(reason(verify_with(e, a, v5.span(), 200, 0xb1d)) == 'NO_ROUTE');
    // Two messages; nine facts exactly.
    let mut two = array![];
    for (k, x) in good.span().into_iter().enumerate() {
        two.append(if k == 7 { 2 } else { *x });
    }
    assert!(reason(verify_with(e, a, two.span(), 200, 0xb1d)) == 'MESSAGE_COUNT');
    assert!(reason(verify_with(e, a, good.span().slice(0, 8), 200, 0xb1d)) == 'PROOF_FACTS_LENGTH');
    // Caller, chain, pool, inputs, proof.
    let v = IVerifierSafeDispatcher { contract_address: a.contract_address };
    start_cheat_proof_facts(a.contract_address, good.span());
    start_cheat_block_number(a.contract_address, 200);
    start_cheat_chain_id(a.contract_address, 'SN_SEPOLIA');
    let p: felt252 = e.pool.contract_address.into();
    start_cheat_caller_address(a.contract_address, addr(0x999));
    assert!(reason(v.verify(array![].span(), array!['SN_SEPOLIA', p, 0xb1d].span())) == 'ONLY_POOL');
    start_cheat_caller_address(a.contract_address, e.pool.contract_address);
    assert!(reason(v.verify(array![1].span(), array!['SN_SEPOLIA', p, 0xb1d].span())) == 'PROOF_IN_TX_ONLY');
    assert!(reason(v.verify(array![].span(), array!['SN_SEPOLIA', p].span())) == 'PUBLIC_LENGTH');
    assert!(reason(v.verify(array![].span(), array!['SN_MAIN', p, 0xb1d].span())) == 'WRONG_CHAIN');
    assert!(reason(v.verify(array![].span(), array!['SN_SEPOLIA', p + 1, 0xb1d].span())) == 'WRONG_POOL');
}

/// Two routes: each proof matches its own route and is bounded by that route's age.
#[test]
#[feature("safe_dispatcher")]
fn each_route_has_its_own_age() {
    let e = pool();
    let (short, long) = (route_at(statement(), 10), route_at(statement(), 100));
    let mut other_os = long;
    other_os.os_program = OS + 1;
    let a = adapter(e, R0, array![short, other_os].span());
    let s = facts_for(short, TAG6, 'SN_SEPOLIA', e.pool.contract_address, 0xb1d, 150);
    let l = facts_for(other_os, TAG6, 'SN_SEPOLIA', e.pool.contract_address, 0xb1d, 150);
    assert!(reason(verify_with(e, a, s.span(), 200, 0xb1d)) == 'PROOF_AGE', "50 blocks on the 10-block route");
    assert!(verify_with(e, a, l.span(), 200, 0xb1d) == Ok(true), "50 blocks on the 100-block route");
    // The short route's statement with the long route's OS program matches neither.
    let crossed = facts_for(Route { os_program: OS + 1, ..short }, TAG6, 'SN_SEPOLIA', e.pool.contract_address, 0xb1d, 150);
    assert!(reason(verify_with(e, a, crossed.span(), 200, 0xb1d)) == 'NO_ROUTE');
}

// ---------------------------------------------------------------- route changes

#[test]
#[feature("safe_dispatcher")]
fn activation_gate_and_owner() {
    let e = pool();
    let r = route();
    let a = adapter(e, R0, array![r].span());
    let s = safe(a);
    let new = route();
    // Inactive: before initialize, and while another adapter holds the slot.
    assert!(reason(s.propose_route(new.statement, Option::Some(new))) == 'NOT_ACTIVE');
    e.pool.initialize(deploy("MockVerifier", array![1]), deploy("MockVerifier", array![1]), array![].span());
    assert!(reason(s.propose_route(new.statement, Option::Some(new))) == 'NOT_ACTIVE');
    // A P1 adapter is gated on the P1 slot.
    let p1 = adapter(e, P1, array![route()].span());
    assert!(reason(safe(p1).propose_route(new.statement, Option::Some(new))) == 'NOT_ACTIVE');
    // Swap R0 to this adapter through the pool's own timelock: now it is active.
    e.pool.propose(R0, a.contract_address.into());
    at(NOW + T);
    e.pool.apply(R0);
    a.propose_route(new.statement, Option::Some(new));
    // Only the pool's owner.
    start_cheat_caller_address(a.contract_address, addr(0x5742));
    assert!(reason(s.propose_route(new.statement, Option::None)) == 'NOT_OWNER');
    assert!(reason(s.apply_route(new.statement)) == 'NOT_OWNER');
    assert!(reason(s.cancel_route(new.statement)) == 'NOT_OWNER');
    stop_cheat_caller_address(a.contract_address);
}

/// The P1 kind's gate follows the pool's P1 slot: active there, route changes apply; after the pool
/// moves P1 away, applying is refused and cancelling still works. An R0 adapter placed in the P1
/// slot is not active (its own kind's slot decides).
#[test]
#[feature("safe_dispatcher")]
fn p1_activation_gate() {
    let e = pool();
    let p1 = adapter(e, P1, array![route()].span());
    let s = safe(p1);
    e.pool.initialize(deploy("MockVerifier", array![1]), p1.contract_address, array![].span());
    let (x, y) = (route(), route());
    p1.propose_route(x.statement, Option::Some(x));
    at(NOW + T);
    p1.apply_route(x.statement);
    assert!(p1.get_route(x.statement) == Option::Some(x));
    p1.propose_route(y.statement, Option::Some(y));
    // The pool moves P1 to an R0-kind routing adapter.
    let r0_kind = adapter(e, R0, array![route()].span());
    e.pool.propose(P1, r0_kind.contract_address.into());
    at(NOW + 2 * T);
    e.pool.apply(P1);
    assert!(reason(s.apply_route(y.statement)) == 'NOT_ACTIVE');
    assert!(reason(s.propose_route(x.statement, Option::None)) == 'NOT_ACTIVE');
    p1.cancel_route(y.statement);
    assert!(p1.get_route_proposals() == array![]);
    let z = route();
    assert!(reason(safe(r0_kind).propose_route(z.statement, Option::Some(z))) == 'NOT_ACTIVE', "an R0 adapter in the P1 slot");
}

/// Transferring the pool's ownership transfers route governance (§6.3).
#[test]
#[feature("safe_dispatcher")]
fn pool_ownership_governs_routes() {
    let (e, a) = active(array![route()].span());
    let s = safe(a);
    let new_owner = addr(0x0a11ce);
    e.pool.transfer_ownership(new_owner);
    start_cheat_caller_address(e.pool.contract_address, new_owner);
    e.pool.accept_ownership();
    stop_cheat_caller_address(e.pool.contract_address);
    let n = route();
    assert!(reason(s.propose_route(n.statement, Option::Some(n))) == 'NOT_OWNER', "the former owner");
    start_cheat_caller_address(a.contract_address, new_owner);
    a.propose_route(n.statement, Option::Some(n));
    assert!(a.get_route_proposals().len() == 1);
}

#[test]
#[feature("safe_dispatcher")]
fn propose_checks() {
    let r = route();
    let (e, a) = active(array![r].span());
    let s = safe(a);
    let n = route();
    assert!(reason(s.propose_route(addr(0x777), Option::Some(n))) == 'ROUTE_KEY');
    assert!(reason(s.propose_route(r.statement, Option::Some(r))) == 'ROUTE_EXISTS');
    assert!(reason(s.propose_route(n.statement, Option::None)) == 'NOT_A_ROUTE');
    let mut b = n;
    b.account_tag = 0;
    assert!(reason(s.propose_route(n.statement, Option::Some(b))) == 'BAD_ROUTE');
    let mut b = n;
    b.max_proof_age = E + Q + 1;
    assert!(reason(s.propose_route(n.statement, Option::Some(b))) == 'PROOF_AGE_BOUND');
    let mut b = n;
    b.statement_class += 1;
    assert!(reason(s.propose_route(n.statement, Option::Some(b))) == 'ROUTE_CLASS');
    let p = e.pool.contract_address;
    let pool_route = Route { statement: p, statement_class: class_of(p), ..n };
    assert!(reason(s.propose_route(p, Option::Some(pool_route))) == 'ROUTE_ADDRESS');
    let me = a.contract_address;
    let self_route = Route { statement: me, statement_class: class_of(me), ..n };
    assert!(reason(s.propose_route(me, Option::Some(self_route))) == 'ROUTE_ADDRESS');
    // eta = now + T, read from the pool.
    let mut spy = spy_events();
    a.propose_route(n.statement, Option::Some(n));
    spy.assert_emitted(@array![
        (me, Event::RouteProposed(RouteProposed { statement: n.statement, route: Option::Some(n), eta: NOW + T })),
    ]);
    assert!(a.get_route_proposals() == array![RouteProposal { statement: n.statement, route: Option::Some(n), eta: NOW + T }]);
    // A removal proposal is listed as None.
    a.propose_route(r.statement, Option::None);
    let props = a.get_route_proposals();
    assert!(props.len() == 2 && *props.at(1) == RouteProposal { statement: r.statement, route: Option::None, eta: NOW + T });
}

#[test]
#[feature("safe_dispatcher")]
fn max_routes_at_propose_and_at_apply() {
    let (_e, a) = active(array![route(), route(), route()].span());
    let s = safe(a);
    // Three active: two additions can be pending (active + 1 ≤ 4 each), but only one can apply.
    let (x, y) = (route(), route());
    a.propose_route(x.statement, Option::Some(x));
    a.propose_route(y.statement, Option::Some(y));
    at(NOW + T);
    a.apply_route(x.statement);
    assert!(a.get_routes().len() == 4);
    assert!(reason(s.apply_route(y.statement)) == 'ROUTE_COUNT');
    // At four, a further addition cannot even be proposed.
    a.cancel_route(y.statement);
    let z = route();
    assert!(reason(s.propose_route(z.statement, Option::Some(z))) == 'ROUTE_COUNT');
}

#[test]
#[feature("safe_dispatcher")]
fn max_pending_counts_lapsed_proposals() {
    let r = route();
    let (_e, a) = active(array![r].span());
    let s = safe(a);
    let (x, y, z) = (route(), route(), route());
    a.propose_route(x.statement, Option::Some(x));
    a.propose_route(r.statement, Option::None);
    assert!(reason(s.propose_route(y.statement, Option::Some(y))) == 'PENDING_FULL');
    // Past eta + T both lapse, and still count.
    at(NOW + 2 * T + 1);
    assert!(reason(s.apply_route(x.statement)) == 'PROPOSAL_LAPSED');
    assert!(reason(s.propose_route(y.statement, Option::Some(y))) == 'PENDING_FULL');
    assert!(a.get_route_proposals().len() == 2, "lapsed proposals stay listed");
    // Replacing a same-key proposal is allowed at the cap, and cancels the old one.
    let mut x2 = x;
    x2.max_proof_age = 500;
    let mut spy = spy_events();
    a.propose_route(x.statement, Option::Some(x2));
    spy.assert_emitted(@array![
        (a.contract_address, Event::RouteCancelled(RouteCancelled { statement: x.statement, route: Option::Some(x) })),
        (a.contract_address, Event::RouteProposed(RouteProposed { statement: x.statement, route: Option::Some(x2), eta: NOW + 3 * T + 1 })),
    ]);
    assert!(a.get_route_proposals().len() == 2);
    // Cancelling frees a slot.
    a.cancel_route(r.statement);
    a.propose_route(z.statement, Option::Some(z));
    assert!(a.get_route_proposals().len() == 2);
}

#[test]
#[feature("safe_dispatcher")]
fn apply_window_and_effects() {
    let r = route();
    let (_e, a) = active(array![r].span());
    let s = safe(a);
    let n = route();
    assert!(reason(s.apply_route(n.statement)) == 'NO_PROPOSAL');
    a.propose_route(n.statement, Option::Some(n));
    at(NOW + T - 1);
    assert!(reason(s.apply_route(n.statement)) == 'TIMELOCK');
    // Applicable from eta to eta + T inclusive.
    at(NOW + T);
    let mut spy = spy_events();
    a.apply_route(n.statement);
    spy.assert_emitted(@array![
        (a.contract_address, Event::RouteSet(RouteSet { statement: n.statement, route: Option::Some(n) })),
    ]);
    assert!(a.get_route(n.statement) == Option::Some(n) && a.get_routes().len() == 2);
    assert!(a.get_route_proposals() == array![], "the proposal is cleared");
    assert!(reason(s.apply_route(n.statement)) == 'NO_PROPOSAL');
    // A removal at eta + T exactly.
    at(NOW + T);
    a.propose_route(r.statement, Option::None);
    at(NOW + 3 * T);
    let mut spy = spy_events();
    a.apply_route(r.statement);
    spy.assert_emitted(@array![
        (a.contract_address, Event::RouteSet(RouteSet { statement: r.statement, route: Option::None })),
    ]);
    assert!(a.get_route(r.statement) == Option::None && a.get_routes() == array![n]);
    assert!(a.get_route_proposals() == array![], "the removal proposal is cleared");
    assert!(reason(s.apply_route(r.statement)) == 'NO_PROPOSAL');
}

/// A same-key proposal replaces the pending value and its eta: the view shows the new value, and
/// apply installs it. A removal replaced by a removal gets the new eta.
#[test]
#[feature("safe_dispatcher")]
fn same_key_replacement_takes_the_new_value() {
    let r = route();
    let (_e, a) = active(array![r].span());
    let s = safe(a);
    let x = route();
    a.propose_route(x.statement, Option::Some(x));
    let mut x2 = x;
    x2.max_proof_age = 500;
    at(NOW + 10);
    a.propose_route(x.statement, Option::Some(x2));
    assert!(a.get_route_proposals() == array![RouteProposal { statement: x.statement, route: Option::Some(x2), eta: NOW + 10 + T }]);
    at(NOW + T);
    assert!(reason(s.apply_route(x.statement)) == 'TIMELOCK', "the replaced eta");
    at(NOW + 10 + T);
    a.apply_route(x.statement);
    assert!(a.get_route(x.statement) == Option::Some(x2), "the replacement value is installed");
    // A removal replaced by a removal.
    a.propose_route(r.statement, Option::None);
    at(NOW + 20 + T);
    let mut spy = spy_events();
    a.propose_route(r.statement, Option::None);
    spy.assert_emitted(@array![
        (a.contract_address, Event::RouteCancelled(RouteCancelled { statement: r.statement, route: Option::None })),
        (a.contract_address, Event::RouteProposed(RouteProposed { statement: r.statement, route: Option::None, eta: NOW + 20 + 2 * T })),
    ]);
    assert!(a.get_route_proposals() == array![RouteProposal { statement: r.statement, route: Option::None, eta: NOW + 20 + 2 * T }]);
    at(NOW + 10 + 2 * T);
    assert!(reason(s.apply_route(r.statement)) == 'TIMELOCK');
    at(NOW + 20 + 2 * T);
    a.apply_route(r.statement);
    assert!(a.get_routes() == array![x2]);
}

/// A removed key is retired: it can never be proposed again, with the same fields or others (§6.3).
#[test]
#[feature("safe_dispatcher")]
fn removed_keys_are_retired() {
    let (r, keep) = (route(), route());
    let (_e, a) = active(array![r, keep].span());
    let s = safe(a);
    a.propose_route(r.statement, Option::None);
    at(NOW + T);
    a.apply_route(r.statement);
    assert!(reason(s.propose_route(r.statement, Option::Some(r))) == 'ROUTE_RETIRED', "the same route");
    let mut r2 = r;
    r2.max_proof_age = 7;
    assert!(reason(s.propose_route(r.statement, Option::Some(r2))) == 'ROUTE_RETIRED', "other fields");
    assert!(reason(s.propose_route(r.statement, Option::None)) == 'NOT_A_ROUTE');
    // A cancelled addition does not retire its key; only an applied removal does.
    let n = route();
    a.propose_route(n.statement, Option::Some(n));
    a.cancel_route(n.statement);
    a.propose_route(n.statement, Option::Some(n));
    at(NOW + 2 * T);
    a.apply_route(n.statement);
    assert!(a.get_route(n.statement) == Option::Some(n));
}

/// `verify` re-reads the matched statement's class (§6.2): a class change still in place at
/// submission is refused, and restoring the pinned class restores routing.
#[test]
#[feature("safe_dispatcher")]
fn verify_rechecks_the_class() {
    let e = pool();
    let r = route_at(deploy("ReplaceableStatement", array![]), 20);
    let a = adapter(e, R0, array![r].span());
    let good = facts_for(r, TAG6, 'SN_SEPOLIA', e.pool.contract_address, 0xb1d, 190);
    assert!(verify_with(e, a, good.span(), 200, 0xb1d) == Ok(true));
    let pinned = get_class_hash_at_syscall(r.statement).unwrap_syscall();
    let other = *declare("ReplaceableStatementB").unwrap_syscall().contract_class().class_hash;
    let statement = IReplaceableDispatcher { contract_address: r.statement };
    statement.replace(other);
    assert!(reason(verify_with(e, a, good.span(), 200, 0xb1d)) == 'ROUTE_CLASS');
    // Swapped back before submission: accepted (the adapter cannot see the base block's class;
    // immutability after apply is an admission rule, §6.5).
    statement.replace(pinned);
    assert!(verify_with(e, a, good.span(), 200, 0xb1d) == Ok(true));
}

/// The class is re-checked at apply: a statement whose class changed after the proposal cannot be
/// added.
#[test]
#[feature("safe_dispatcher")]
fn apply_rechecks_the_class() {
    let (_e, a) = active(array![route()].span());
    let n = route_at(deploy("ReplaceableStatement", array![]), 1024);
    a.propose_route(n.statement, Option::Some(n));
    let other = *declare("E2EToken").unwrap_syscall().contract_class().class_hash;
    IReplaceableDispatcher { contract_address: n.statement }.replace(other);
    assert!(class_of(n.statement) == other.into());
    at(NOW + T);
    assert!(reason(safe(a).apply_route(n.statement)) == 'ROUTE_CLASS');
}

/// At least one route remains: the last route's removal can be proposed but not applied. Replacing
/// a sole route: propose the fixed route and the removal together, apply the addition first.
#[test]
#[feature("safe_dispatcher")]
fn last_route_cannot_be_removed() {
    let r = route();
    let (_e, a) = active(array![r].span());
    a.propose_route(r.statement, Option::None);
    at(NOW + T);
    assert!(reason(safe(a).apply_route(r.statement)) == 'LAST_ROUTE');
    // The replacement procedure.
    a.cancel_route(r.statement);
    let fixed = route();
    a.propose_route(fixed.statement, Option::Some(fixed));
    a.propose_route(r.statement, Option::None);
    at(NOW + 2 * T);
    a.apply_route(fixed.statement);
    a.apply_route(r.statement);
    assert!(a.get_routes() == array![fixed]);
}

/// Cancelling is allowed while inactive (after the pool moved the slot away), applying is not.
#[test]
#[feature("safe_dispatcher")]
fn cancel_while_inactive() {
    let (e, a) = active(array![route()].span());
    let s = safe(a);
    let (x, y) = (route(), route());
    a.propose_route(x.statement, Option::Some(x));
    a.propose_route(y.statement, Option::Some(y));
    // The pool swaps R0 away.
    e.pool.propose(R0, deploy("MockVerifier", array![1]).into());
    at(NOW + T);
    e.pool.apply(R0);
    assert!(reason(s.apply_route(x.statement)) == 'NOT_ACTIVE');
    assert!(reason(s.propose_route(x.statement, Option::None)) == 'NOT_ACTIVE');
    let mut spy = spy_events();
    a.cancel_route(x.statement);
    spy.assert_emitted(@array![
        (a.contract_address, Event::RouteCancelled(RouteCancelled { statement: x.statement, route: Option::Some(x) })),
    ]);
    assert!(a.get_route_proposals() == array![RouteProposal { statement: y.statement, route: Option::Some(y), eta: NOW + T }]);
    assert!(reason(s.cancel_route(x.statement)) == 'NO_PROPOSAL');
}

/// Routing survives route changes: a proof for an added route verifies, one for a removed route
/// gets `NO_ROUTE`.
#[test]
#[feature("safe_dispatcher")]
fn verify_follows_route_changes() {
    let old = route_at(statement(), 20);
    let (e, a) = active(array![old].span());
    let new = route_at(statement(), 20);
    let fnew = facts_for(new, TAG6, 'SN_SEPOLIA', e.pool.contract_address, 0xb1d, 190);
    let fold = facts_for(old, TAG6, 'SN_SEPOLIA', e.pool.contract_address, 0xb1d, 190);
    a.propose_route(new.statement, Option::Some(new));
    // Proposed, not applied: the new route's proofs are refused, even once eta has passed.
    assert!(reason(verify_with(e, a, fnew.span(), 200, 0xb1d)) == 'NO_ROUTE', "a pending route");
    at(NOW + T);
    assert!(reason(verify_with(e, a, fnew.span(), 200, 0xb1d)) == 'NO_ROUTE', "past eta, not applied");
    a.apply_route(new.statement);
    a.propose_route(old.statement, Option::None);
    assert!(verify_with(e, a, fnew.span(), 200, 0xb1d) == Ok(true));
    assert!(verify_with(e, a, fold.span(), 200, 0xb1d) == Ok(true));
    at(NOW + 2 * T);
    a.apply_route(old.statement);
    assert!(reason(verify_with(e, a, fold.span(), 200, 0xb1d)) == 'NO_ROUTE');
    assert!(verify_with(e, a, fnew.span(), 200, 0xb1d) == Ok(true));
}

/// `Route`'s Serde order, the known-answer vector the SDK and the server share (§6.1).
#[test]
fn route_serde_order() {
    let r = Route {
        statement: addr(0x5a7e), statement_class: 0xc1a5, account_tag: TAG6, os_program: OS, proof_version: 'PROOF2',
        proof_variant: 'VIRTUAL_SNOS', output_version: 'VIRTUAL_SNOS0', max_proof_age: 1024,
    };
    let mut out = array![];
    r.serialize(ref out);
    assert!(out == array![0x5a7e, 0xc1a5, TAG6, OS, 'PROOF2', 'VIRTUAL_SNOS', 'VIRTUAL_SNOS0', 1024]);
    let mut some = array![];
    Option::Some(r).serialize(ref some);
    assert!(*some.at(0) == 0 && some.len() == 9, "Some is tag 0 then the route");
    let mut none = array![];
    Option::<Route>::None.serialize(ref none);
    assert!(none == array![1]);
}

/// The class re-check reads the matched route's own statement (PR-RC-1): with two routes of
/// different classes, a class change on the first route bricks only that route, and the second
/// route, whose class differs from the first's, keeps routing.
#[test]
#[feature("safe_dispatcher")]
fn class_change_bricks_only_its_route() {
    let e = pool();
    let a_route = route_at(deploy("ReplaceableStatement", array![]), 20);
    let b_route = route_at(statement(), 20);
    assert!(a_route.statement_class != b_route.statement_class);
    let a = adapter(e, R0, array![a_route, b_route].span());
    let fa = facts_for(a_route, TAG6, 'SN_SEPOLIA', e.pool.contract_address, 0xb1d, 190);
    let fb = facts_for(b_route, TAG6, 'SN_SEPOLIA', e.pool.contract_address, 0xb1d, 190);
    assert!(verify_with(e, a, fa.span(), 200, 0xb1d) == Ok(true));
    assert!(verify_with(e, a, fb.span(), 200, 0xb1d) == Ok(true), "the second route, another class");
    let other = *declare("ReplaceableStatementB").unwrap_syscall().contract_class().class_hash;
    IReplaceableDispatcher { contract_address: a_route.statement }.replace(other);
    assert!(reason(verify_with(e, a, fa.span(), 200, 0xb1d)) == 'ROUTE_CLASS');
    assert!(verify_with(e, a, fb.span(), 200, 0xb1d) == Ok(true), "the other route keeps routing");
}

/// The shared encoding vectors (`sdk/vectors/routing.json`, read by the server and the SDK): a
/// route, `Some`, `None`, a two-route `get_routes()` and a `get_route_proposals()` with an addition
/// and a removal, each as Serde writes the adapter's return values.
#[test]
fn routing_vectors_match_serde() {
    let (a, b) = (routing_vectors::r0_v6(), routing_vectors::p1_v1());
    let mut out = array![];
    a.serialize(ref out);
    assert!(out == routing_vectors::r0_v6_felts());
    let mut out = array![];
    Option::Some(a).serialize(ref out);
    assert!(out == routing_vectors::some_r0_v6_felts());
    let mut out = array![];
    Option::<Route>::None.serialize(ref out);
    assert!(out == array![1]);
    let mut out = array![];
    array![a, b].serialize(ref out);
    assert!(out == routing_vectors::get_routes_felts());
    let mut out = array![];
    routing_vectors::proposals().serialize(ref out);
    assert!(out == routing_vectors::get_route_proposals_felts());
}

/// R0 V6's binding anchors (starknet.js, `cairo-r6/kat`) equal pool V3's `spend5::compute_binding`
/// over spends whose ciphertexts give the same delivery digests (spec §4.4, re-check F3).
#[test]
fn v6_binding_anchors_match_the_pool() {
    let mut n = 0;
    for (name, sp) in v6_binding_vectors() {
        assert!(compute_binding(@sp) == sp.binding, "{}", name);
        n += 1;
    }
    assert!(n == 3);
}
