//! Routing adapter for pool V3's `IVerifier` seam (`docs/pool-v3-spec.md` §6). One instance fills
//! one of the pool's verifier slots (`'R0'` or `'P1'`) and holds up to `MAX_ROUTES` routes, so a new
//! statement account (an OS rotation, a device route) is added under the pool's timelock without a
//! verifier swap.
//!
//! - **A route** pins eight fields (§6.1): the statement account's address (the route's key), its
//!   class, the message tag it emits, the OS program (`facts[2]`), the proof version (`facts[0]`),
//!   variant (`facts[1]`) and output version (`facts[3]`), and a maximum proof age in blocks. Every
//!   route has its own statement account, so routes never replace each other in place: a removed
//!   key is retired and can never be added again.
//! - **Verification** (§6.2) keeps `Proof2Adapter`'s checks and matches exactly one active route:
//!   facts `[proof_version, proof_variant, os_program, output_version, base_block, base_hash, _,
//!   n_messages = 1, message_hash]` with `message_hash = Poseidon(statement, 0, 5, statement_class,
//!   account_tag, chain, pool, binding)`, the statement account's single L2→L1 message, whose
//!   `from_address` the OS enforces. A proof that matches no active route is rejected (`NO_ROUTE`).
//!   The matched statement's class is re-read and must still be the pinned one (`ROUTE_CLASS`): a
//!   defence in depth that catches a class change still in place at submission. It makes no
//!   external call.
//! - **Route changes** (§6.3) are timelocked like the pool's own levers, and governed by the pool:
//!   the adapter has no owner. It reads the pool's owner and timelock `T` at propose and at apply.
//!   Proposing and applying are allowed only while this adapter is the pool's verifier for its kind
//!   (the activation gate); cancelling is allowed at any time. Lapsed proposals stay listed and
//!   count toward `MAX_PENDING` until cancelled or replaced.
//!
//! The class is immutable: no `replace_class`, no `library_call` and no owner storage.
use starknet::ContractAddress;

/// A route: the eight pinned fields, in their Serde order (a known-answer vector shared with the
/// SDK and the server fixes it).
#[derive(Copy, Drop, Serde, PartialEq, Debug, starknet::Store)]
pub struct Route {
    pub statement: ContractAddress,
    pub statement_class: felt252,
    pub account_tag: felt252,
    pub os_program: felt252,
    pub proof_version: felt252,
    pub proof_variant: felt252,
    pub output_version: felt252,
    pub max_proof_age: u64,
}

/// A pending route change: an addition (`Some(route)`) or a removal (`None`) of `statement`,
/// applicable within `[eta, eta + T]`.
#[derive(Copy, Drop, Serde, PartialEq, Debug)]
pub struct RouteProposal {
    pub statement: ContractAddress,
    pub route: Option<Route>,
    pub eta: u64,
}

pub const MAX_ROUTES: u32 = 4;
pub const MAX_PENDING: u32 = 2;

#[starknet::interface]
pub trait IRoutingAdapter<TState> {
    fn get_pool(self: @TState) -> ContractAddress;
    fn get_kind(self: @TState) -> felt252;
    /// The full active set, in no meaningful order (compared as a set).
    fn get_routes(self: @TState) -> Array<Route>;
    fn get_route(self: @TState, statement: ContractAddress) -> Option<Route>;
    /// Every pending proposal, lapsed ones included: the normative source of pending route changes.
    fn get_route_proposals(self: @TState) -> Array<RouteProposal>;
    fn propose_route(ref self: TState, statement: ContractAddress, route: Option<Route>);
    fn apply_route(ref self: TState, statement: ContractAddress);
    fn cancel_route(ref self: TState, statement: ContractAddress);
}

#[starknet::contract]
pub mod RoutingAdapter {
    use core::poseidon::poseidon_hash_span;
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess, StoragePointerWriteAccess,
    };
    use starknet::syscalls::{get_class_hash_at_syscall, get_execution_info_v3_syscall};
    use starknet::{
        ContractAddress, SyscallResultTrait, get_block_timestamp, get_caller_address, get_contract_address,
    };
    use crate::pool_v3::{IM31PoolV3Dispatcher, IM31PoolV3DispatcherTrait, P1, R0};
    use crate::spend::IVerifier;
    use super::{IRoutingAdapter, MAX_PENDING, MAX_ROUTES, Route, RouteProposal};

    /// No proposal for a key.
    const NONE: u8 = 0;
    const ADDITION: u8 = 1;
    const REMOVAL: u8 = 2;

    #[storage]
    struct Storage {
        pool: ContractAddress,
        kind: felt252,
        /// Active routes by statement; `statement == 0` marks an absent key.
        routes: Map<ContractAddress, Route>,
        /// The active keys, `route_keys[0 .. n_routes]`.
        route_keys: Map<u32, ContractAddress>,
        n_routes: u32,
        /// Pending proposals by statement: `NONE`, `ADDITION` or `REMOVAL`.
        proposal_kind: Map<ContractAddress, u8>,
        proposal_route: Map<ContractAddress, Route>,
        proposal_eta: Map<ContractAddress, u64>,
        /// The pending keys, `proposal_keys[0 .. n_proposals]`.
        proposal_keys: Map<u32, ContractAddress>,
        n_proposals: u32,
        /// Keys whose removal applied: never added again (§6.3).
        retired: Map<ContractAddress, bool>,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        RouteProposed: RouteProposed,
        RouteCancelled: RouteCancelled,
        RouteSet: RouteSet,
    }

    #[derive(Drop, starknet::Event)]
    pub struct RouteProposed {
        #[key]
        pub statement: ContractAddress,
        pub route: Option<Route>,
        pub eta: u64,
    }

    #[derive(Drop, starknet::Event)]
    pub struct RouteCancelled {
        #[key]
        pub statement: ContractAddress,
        pub route: Option<Route>,
    }

    /// A route added (`Some`) or removed (`None`), at construction or at apply.
    #[derive(Drop, starknet::Event)]
    pub struct RouteSet {
        #[key]
        pub statement: ContractAddress,
        pub route: Option<Route>,
    }

    #[constructor]
    fn constructor(ref self: ContractState, pool: ContractAddress, kind: felt252, routes: Span<Route>) {
        assert(pool.into() != 0, 'ZERO_ADDRESS');
        assert(kind == R0 || kind == P1, 'ADAPTER_KIND');
        assert(routes.len() >= 1 && routes.len() <= MAX_ROUTES, 'ROUTE_COUNT');
        self.pool.write(pool);
        self.kind.write(kind);
        for route in routes {
            assert(!self.is_active(*route.statement), 'DUPLICATE_ROUTE');
            self.check_route(*route);
            self.add(*route);
        }
    }

    #[abi(embed_v0)]
    impl VerifierImpl of IVerifier<ContractState> {
        fn verify(self: @ContractState, proof: Span<felt252>, public_inputs: Span<felt252>) -> bool {
            assert(proof.is_empty(), 'PROOF_IN_TX_ONLY');
            let pool = self.pool.read();
            assert(get_caller_address() == pool, 'ONLY_POOL');
            // The pool passes [chain, pool, binding].
            assert(public_inputs.len() == 3, 'PUBLIC_LENGTH');
            let info = get_execution_info_v3_syscall().unwrap_syscall();
            let chain = *public_inputs.at(0);
            assert(chain == info.tx_info.chain_id, 'WRONG_CHAIN');
            assert(*public_inputs.at(1) == pool.into(), 'WRONG_POOL');
            let facts = info.tx_info.proof_facts;
            assert(facts.len() == 9, 'PROOF_FACTS_LENGTH');
            assert(*facts.at(7) == 1, 'MESSAGE_COUNT');
            // The first active route whose facts and message hash match; at most one can, since
            // the message hash covers the OS-enforced statement address, the route's key.
            let mut matched: Option<Route> = Option::None;
            let mut i = 0;
            let n = self.n_routes.read();
            while i < n {
                let r = self.routes.read(self.route_keys.read(i));
                if *facts.at(0) == r.proof_version
                    && *facts.at(1) == r.proof_variant
                    && *facts.at(2) == r.os_program
                    && *facts.at(3) == r.output_version {
                    let message = array![
                        r.statement.into(), 0, 5, r.statement_class, r.account_tag, chain, *public_inputs.at(1),
                        *public_inputs.at(2),
                    ];
                    if *facts.at(8) == poseidon_hash_span(message.span()) {
                        matched = Option::Some(r);
                        break;
                    }
                }
                i += 1;
            }
            let route = matched.expect('NO_ROUTE');
            // The statement's class is still the pinned one (§6.2). This cannot see a class swapped
            // away and back before submission; immutability after apply is an admission rule (§6.5).
            assert(self.class_of(route.statement) == route.statement_class, 'ROUTE_CLASS');
            // That route's age bound; the sequencer checks the base block's hash.
            let base: u64 = (*facts.at(4)).try_into().expect('BASE_BLOCK');
            let current = info.block_info.block_number;
            assert(base < current, 'PROOF_AGE');
            assert(current - base <= route.max_proof_age, 'PROOF_AGE');
            true
        }
    }

    #[abi(embed_v0)]
    impl RoutingAdapterImpl of IRoutingAdapter<ContractState> {
        fn get_pool(self: @ContractState) -> ContractAddress {
            self.pool.read()
        }

        fn get_kind(self: @ContractState) -> felt252 {
            self.kind.read()
        }

        fn get_routes(self: @ContractState) -> Array<Route> {
            let mut out = array![];
            let mut i = 0;
            let n = self.n_routes.read();
            while i < n {
                out.append(self.routes.read(self.route_keys.read(i)));
                i += 1;
            }
            out
        }

        fn get_route(self: @ContractState, statement: ContractAddress) -> Option<Route> {
            if self.is_active(statement) {
                Option::Some(self.routes.read(statement))
            } else {
                Option::None
            }
        }

        fn get_route_proposals(self: @ContractState) -> Array<RouteProposal> {
            let mut out = array![];
            let mut i = 0;
            let n = self.n_proposals.read();
            while i < n {
                let statement = self.proposal_keys.read(i);
                out.append(RouteProposal { statement, route: self.proposed(statement), eta: self.proposal_eta.read(statement) });
                i += 1;
            }
            out
        }

        fn propose_route(ref self: ContractState, statement: ContractAddress, route: Option<Route>) {
            self.only_owner();
            self.only_active();
            match route {
                Option::Some(r) => {
                    assert(r.statement == statement, 'ROUTE_KEY');
                    assert(!self.is_active(statement), 'ROUTE_EXISTS');
                    assert(!self.retired.read(statement), 'ROUTE_RETIRED');
                    self.check_route(r);
                    assert(self.n_routes.read() + 1 <= MAX_ROUTES, 'ROUTE_COUNT');
                },
                Option::None => { assert(self.is_active(statement), 'NOT_A_ROUTE'); },
            }
            let old = self.proposal_kind.read(statement);
            if old != NONE {
                // A same-key proposal is replaced, whether lapsed or not.
                self.emit(RouteCancelled { statement, route: self.proposed(statement) });
            } else {
                assert(self.n_proposals.read() < MAX_PENDING, 'PENDING_FULL');
                let n = self.n_proposals.read();
                self.proposal_keys.write(n, statement);
                self.n_proposals.write(n + 1);
            }
            let eta = get_block_timestamp() + self.timelock();
            match route {
                Option::Some(r) => {
                    self.proposal_kind.write(statement, ADDITION);
                    self.proposal_route.write(statement, r);
                },
                Option::None => { self.proposal_kind.write(statement, REMOVAL); },
            }
            self.proposal_eta.write(statement, eta);
            self.emit(RouteProposed { statement, route, eta });
        }

        fn apply_route(ref self: ContractState, statement: ContractAddress) {
            self.only_owner();
            self.only_active();
            let kind = self.proposal_kind.read(statement);
            assert(kind != NONE, 'NO_PROPOSAL');
            let eta = self.proposal_eta.read(statement);
            let now = get_block_timestamp();
            assert(now >= eta, 'TIMELOCK');
            assert(now <= eta + self.timelock(), 'PROPOSAL_LAPSED');
            if kind == ADDITION {
                let r = self.proposal_route.read(statement);
                assert(!self.is_active(statement), 'ROUTE_EXISTS');
                assert(!self.retired.read(statement), 'ROUTE_RETIRED');
                assert(self.class_of(statement) == r.statement_class, 'ROUTE_CLASS');
                assert(self.n_routes.read() + 1 <= MAX_ROUTES, 'ROUTE_COUNT');
                self.clear(statement);
                self.add(r);
            } else {
                assert(self.is_active(statement), 'NOT_A_ROUTE');
                assert(self.n_routes.read() > 1, 'LAST_ROUTE');
                self.clear(statement);
                self.remove(statement);
                self.retired.write(statement, true);
                self.emit(RouteSet { statement, route: Option::None });
            }
        }

        fn cancel_route(ref self: ContractState, statement: ContractAddress) {
            self.only_owner();
            assert(self.proposal_kind.read(statement) != NONE, 'NO_PROPOSAL');
            let route = self.proposed(statement);
            self.clear(statement);
            self.emit(RouteCancelled { statement, route });
        }
    }

    #[generate_trait]
    impl InternalImpl of InternalTrait {
        fn pool(self: @ContractState) -> IM31PoolV3Dispatcher {
            IM31PoolV3Dispatcher { contract_address: self.pool.read() }
        }

        /// The pool's owner governs routes; a view that takes no lock (§6.3).
        fn only_owner(self: @ContractState) {
            assert(get_caller_address() == self.pool().get_owner(), 'NOT_OWNER');
        }

        /// The activation gate: routes change only while this adapter is the pool's verifier for
        /// its kind; before that, routes come only from the constructor.
        fn only_active(self: @ContractState) {
            assert(self.pool().get_verifier(self.kind.read()) == get_contract_address(), 'NOT_ACTIVE');
        }

        fn timelock(self: @ContractState) -> u64 {
            self.pool().get_parameters().timelock
        }

        fn class_of(self: @ContractState, address: ContractAddress) -> felt252 {
            // An undeployed address has class 0.
            get_class_hash_at_syscall(address).unwrap_syscall().into()
        }

        fn is_active(self: @ContractState, statement: ContractAddress) -> bool {
            statement.into() != 0 && self.routes.read(statement).statement == statement
        }

        /// The per-route checks of the constructor and `propose_route` (§6.3): every field nonzero,
        /// `0 < max_proof_age ≤ E + Q`, the statement neither the pool nor this adapter, and its
        /// class on chain equal to the pinned one.
        fn check_route(self: @ContractState, r: Route) {
            assert(
                r.statement.into() != 0
                    && r.statement_class != 0
                    && r.account_tag != 0
                    && r.os_program != 0
                    && r.proof_version != 0
                    && r.proof_variant != 0
                    && r.output_version != 0
                    && r.max_proof_age != 0,
                'BAD_ROUTE',
            );
            let p = self.pool().get_parameters();
            assert(r.max_proof_age <= p.expiry_window + p.quantum, 'PROOF_AGE_BOUND');
            assert(r.statement != self.pool.read() && r.statement != get_contract_address(), 'ROUTE_ADDRESS');
            assert(self.class_of(r.statement) == r.statement_class, 'ROUTE_CLASS');
        }

        fn add(ref self: ContractState, r: Route) {
            let n = self.n_routes.read();
            self.route_keys.write(n, r.statement);
            self.n_routes.write(n + 1);
            self.routes.write(r.statement, r);
            self.emit(RouteSet { statement: r.statement, route: Option::Some(r) });
        }

        fn remove(ref self: ContractState, statement: ContractAddress) {
            let n = self.n_routes.read();
            let mut i = 0;
            while i < n {
                if self.route_keys.read(i) == statement {
                    self.route_keys.write(i, self.route_keys.read(n - 1));
                    break;
                }
                i += 1;
            }
            self.n_routes.write(n - 1);
            self.routes.write(statement, zero_route());
        }

        /// The proposal's value: `Some(route)` for an addition, `None` for a removal.
        fn proposed(self: @ContractState, statement: ContractAddress) -> Option<Route> {
            if self.proposal_kind.read(statement) == ADDITION {
                Option::Some(self.proposal_route.read(statement))
            } else {
                Option::None
            }
        }

        fn clear(ref self: ContractState, statement: ContractAddress) {
            let n = self.n_proposals.read();
            let mut i = 0;
            while i < n {
                if self.proposal_keys.read(i) == statement {
                    self.proposal_keys.write(i, self.proposal_keys.read(n - 1));
                    break;
                }
                i += 1;
            }
            self.n_proposals.write(n - 1);
            self.proposal_kind.write(statement, NONE);
            self.proposal_route.write(statement, zero_route());
            self.proposal_eta.write(statement, 0);
        }
    }

    fn zero_route() -> Route {
        Route {
            statement: 0.try_into().unwrap(), statement_class: 0, account_tag: 0, os_program: 0, proof_version: 0,
            proof_variant: 0, output_version: 0, max_proof_age: 0,
        }
    }
}
