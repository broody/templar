//! TemplarPool v2 — server phase + gating, spec §5–§8.
//!
//! The pool executes `apply_spend`: it validates that the bundle's public
//! inputs were established by a valid inner proof and bound to the exact
//! server actions (§7.3.6), re-checks every on-chain-verifiable fact (§7.4),
//! then applies actions atomically. It performs NO secret-dependent logic —
//! it never sees openings.

#[starknet::interface]
pub trait IPool<TState> {
    fn apply_spend(
        ref self: TState,
        public_inputs: pool::spend::SpendPublicInputs,
        proof: Span<felt252>,
        server_actions: Span<pool::spend::ServerAction>,
    );
    /// Proofless deposit (ADR-0011): the commitment is recomputed on-chain
    /// from the public fields + the depositor-supplied `inner`, so the
    /// deposited amount is bound by construction and no proof is needed. The
    /// depositor is always the caller (review §D.1). `controller = 0` and
    /// `policy_commitment = 0` create an ordinary note.
    fn deposit(
        ref self: TState,
        token: starknet::ContractAddress,
        amount: u128,
        controller: starknet::ContractAddress,
        policy_commitment: felt252,
        inner: felt252,
        note_id: felt252,
    );
    /// M1 seam: fee is settable until governance wiring lands (M3). `token`
    /// defaults to the canonical STRK (§4) but stays configurable so tests can
    /// plug a mock; production governance pins STRK.
    fn set_fee(
        ref self: TState,
        token: starknet::ContractAddress,
        amount: u128,
        collector: starknet::ContractAddress,
    );
    fn get_nullifier_spent(self: @TState, nullifier: felt252) -> bool;
    /// M1 governance fix (review §B): the three trust anchors — verifier,
    /// sig_verifier, fee config — are owner-gated. Full upstream
    /// Roles/AccessControl lands in M3.
    fn set_verifier(ref self: TState, verifier: starknet::ContractAddress);
    fn set_sig_verifier(ref self: TState, sig_verifier: starknet::ContractAddress);
    fn get_verifier(self: @TState) -> starknet::ContractAddress;
    fn get_sig_verifier(self: @TState) -> starknet::ContractAddress;
    fn get_owner(self: @TState) -> starknet::ContractAddress;
    fn transfer_ownership(ref self: TState, new_owner: starknet::ContractAddress);
}

#[starknet::contract]
pub mod Pool {
    use core::starknet::{
        get_block_number, get_caller_address, get_contract_address, ContractAddress,
    };
    use starknet::get_tx_info;
    use pool::hashes::compute_note_commitment;
    use pool::spend::{
        compute_actions_hash, compute_statement_binding, IERC20Dispatcher, IERC20DispatcherTrait,
        ISigVerifierDispatcher, ISigVerifierDispatcherTrait, IVerifierDispatcher,
        IVerifierDispatcherTrait, ServerAction, SpendPublicInputs, MAX_INPUT_NOTES,
        MAX_OUTPUT_NOTES, MAX_WITHDRAWALS, PROTOCOL_VERSION,
    };
    use pool::tree::tree_component;
    use pool::tree::tree_component::TreeInternalTrait;
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };

    /// Canonical STRK (upstream-compatible) — the fee token, outside private
    /// accounting (§4).
    const STRK_TOKEN_ADDRESS: felt252 =
        0x04718f5a0fc34cc1af16a70cde8ff893b576ca30423eca852ce4ab014b6b52ac;

    component!(path: tree_component, storage: tree, event: TreeEvent);

    #[storage]
    pub struct Storage {
        /// Inner-proof verifier seam (M1 mock → M2 real on-chain verifier;
        /// single-phase per ADR-0010).
        verifier: ContractAddress,
        /// Controller signature seam (M1 mock → on-chain cairo-ec, M3).
        sig_verifier: ContractAddress,
        /// Nullifier set — single domain, WriteOnce (§4).
        nullifiers: Map<felt252, bool>,
        owner: ContractAddress,
        fee_token: ContractAddress,
        fee_amount: u128,
        fee_collector: ContractAddress,
        reentrancy_locked: bool,
        #[substorage(v0)]
        pub tree: tree_component::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        TreeEvent: tree_component::Event,
        /// §8 — discovery artifact. `note_id` is unproven metadata supplied by
        /// the client; `commitment` is proven (or recomputed on-chain, for
        /// deposits).
        NoteCommitted: NoteCommitted,
        NullifierSpent: NullifierSpent,
        /// §8 — NO depositor field (ADR-0007).
        Deposited: Deposited,
        Withdrawal: Withdrawal,
        ControllerAuthorized: ControllerAuthorized,
        OwnershipTransferred: OwnershipTransferred,
    }

    #[derive(Drop, starknet::Event)]
    pub struct NoteCommitted {
        pub note_id: felt252,
        pub leaf_index: u64,
        pub commitment: felt252,
        pub controller: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    pub struct NullifierSpent {
        pub nullifier: felt252,
        pub controller: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    pub struct Deposited {
        pub token: ContractAddress,
        pub amount: u256,
    }

    #[derive(Drop, starknet::Event)]
    pub struct Withdrawal {
        pub to_addr: ContractAddress,
        pub token: ContractAddress,
        pub amount: u256,
    }

    #[derive(Drop, starknet::Event)]
    pub struct ControllerAuthorized {
        pub transition_commitment: felt252,
        pub controller: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    pub struct OwnershipTransferred {
        pub from: ContractAddress,
        pub to: ContractAddress,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        owner: ContractAddress,
        verifier: ContractAddress,
        sig_verifier: ContractAddress,
    ) {
        self.owner.write(owner);
        self.verifier.write(verifier);
        self.sig_verifier.write(sig_verifier);
        self.fee_token.write(STRK_TOKEN_ADDRESS.try_into().unwrap());
        // Seed the zero chain + empty root so root_is_known(empty_root) holds
        // from genesis — otherwise the first spend bundle would have no
        // acceptable root (tree.cairo seeds lazily on first insert).
        self.tree._init_zeros();
    }

    #[abi(embed_v0)]
    impl PoolTreeImpl = tree_component::Tree<ContractState>;

    #[abi(embed_v0)]
    impl PoolImpl of super::IPool<ContractState> {
        /// Server phase (§5.1). Reverts unless every §7.4 check holds; all
        /// application is atomic.
        fn apply_spend(
            ref self: ContractState,
            public_inputs: SpendPublicInputs,
            proof: Span<felt252>,
            server_actions: Span<ServerAction>,
        ) {
            self._start();
            let actions_hash = compute_actions_hash(@server_actions);
            self._validate_statement(@public_inputs, actions_hash, proof);
            self._collect_fee();
            self._apply_actions(@public_inputs, @server_actions);
            self._end();
        }

        /// Standalone proofless deposit (ADR-0011). The commitment is
        /// recomputed on-chain from public fields + the caller's secret
        /// `inner`, binding the deposited amount by construction.
        fn deposit(
            ref self: ContractState,
            token: ContractAddress,
            amount: u128,
            controller: ContractAddress,
            policy_commitment: felt252,
            inner: felt252,
            note_id: felt252,
        ) {
            self._start();
            assert(token.into() != 0, 'ZERO_TOKEN');
            assert(amount != 0, 'ZERO_AMOUNT');
            assert(inner != 0, 'ZERO_INNER');
            let commitment = compute_note_commitment(
                token, amount, controller, policy_commitment, inner,
            );
            let ok = IERC20Dispatcher { contract_address: token }.transfer_from(
                get_caller_address(), get_contract_address(), amount.into(),
            );
            assert(ok, 'TRANSFER_FAILED');
            let leaf_index = self.tree.insert_leaf(commitment);
            self.emit(Event::Deposited(Deposited { token, amount: amount.into() }));
            self
                .emit(
                    Event::NoteCommitted(
                        NoteCommitted { note_id, leaf_index, commitment, controller },
                    ),
                );
            self._end();
        }

        fn set_fee(
            ref self: ContractState, token: ContractAddress, amount: u128, collector: ContractAddress,
        ) {
            self._assert_owner();
            self.fee_token.write(token);
            self.fee_amount.write(amount);
            self.fee_collector.write(collector);
        }

        fn get_nullifier_spent(self: @ContractState, nullifier: felt252) -> bool {
            self.nullifiers.read(nullifier)
        }

        fn set_verifier(ref self: ContractState, verifier: ContractAddress) {
            self._assert_owner();
            self.verifier.write(verifier);
        }

        fn set_sig_verifier(ref self: ContractState, sig_verifier: ContractAddress) {
            self._assert_owner();
            self.sig_verifier.write(sig_verifier);
        }

        fn get_verifier(self: @ContractState) -> ContractAddress {
            self.verifier.read()
        }

        fn get_sig_verifier(self: @ContractState) -> ContractAddress {
            self.sig_verifier.read()
        }

        fn get_owner(self: @ContractState) -> ContractAddress {
            self.owner.read()
        }

        fn transfer_ownership(ref self: ContractState, new_owner: ContractAddress) {
            self._assert_owner();
            let from = self.owner.read();
            self.owner.write(new_owner);
            self.emit(Event::OwnershipTransferred(OwnershipTransferred { from, to: new_owner }));
        }
    }

    #[generate_trait]
    impl PoolInternalImpl of PoolInternalTrait {
        fn _assert_owner(self: @ContractState) {
            assert(self.owner.read() == get_caller_address(), 'NOT_OWNER');
        }

        fn _start(ref self: ContractState) {
            assert(!self.reentrancy_locked.read(), 'REENTRANCY');
            self.reentrancy_locked.write(true);
        }

        fn _end(ref self: ContractState) {
            self.reentrancy_locked.write(false);
        }

        /// §7.4 on-chain checks + the authorization gate. Order: cheap
        /// context asserts → binding → proof → root, before any state change.
        fn _validate_statement(
            self: @ContractState,
            pi: @SpendPublicInputs,
            actions_hash: felt252, proof: Span<felt252>,
        ) {
            assert(*pi.protocol_version == PROTOCOL_VERSION, 'WRONG_VERSION');
            assert(*pi.pool_address == get_contract_address(), 'WRONG_POOL');
            assert(*pi.chain_id == get_tx_info().unbox().chain_id, 'WRONG_CHAIN');
            assert(pi.input_nullifiers.len() <= MAX_INPUT_NOTES, 'TOO_MANY_INPUTS');
            assert(pi.output_commitments.len() <= MAX_OUTPUT_NOTES, 'TOO_MANY_OUTPUTS');
            assert(pi.withdrawals.len() <= MAX_WITHDRAWALS, 'TOO_MANY_WITHDRAWALS');

            // The binding ties the proven public inputs to these exact actions
            // (§7.3.6). The circuit asserts the same equation; rechecking it
            // here binds actions to the verified statement. A permissive
            // verifier still compromises the pool; this is not a substitute for proof verification.
            let binding = compute_statement_binding(pi, actions_hash);
            assert(binding == *pi.statement_binding, 'BAD_BINDING');

            // Inner-proof seam (M1 mock → M2 real on-chain verifier, §5; ADR-0010).
            // The Groth16 public-input vector is the fixed 8-scalar subset
            // (ADR-0014); the arrays enter the proof via the binding.
            let serialized = array![
                *pi.protocol_version,
                *pi.chain_id,
                (*pi.pool_address).into(),
                *pi.tree_root,
                (*pi.controller).into(),
                (*pi.deadline).into(),
                *pi.transition_commitment,
                *pi.statement_binding,
            ];
            let verifier = IVerifierDispatcher { contract_address: self.verifier.read() };
            assert(verifier.verify(proof, serialized.span()), 'PROOF_REJECTED');

            // Root must still be in the acceptable ring (§7.4).
            assert(self.tree.root_is_known(*pi.tree_root), 'UNKNOWN_ROOT');
        }

        fn _collect_fee(ref self: ContractState) {
            let fee_amount = self.fee_amount.read();
            if fee_amount != 0 {
                let ok = IERC20Dispatcher { contract_address: self.fee_token.read() }.transfer_from(
                    get_caller_address(),
                    self.fee_collector.read(),
                    fee_amount.into(),
                );
                assert(ok, 'FEE_FAILED');
            }
        }

        /// Applies actions with strict 1:1 zipping against public inputs —
        /// this zip is load-bearing, not hygiene (see `ServerAction` docs).
        fn _apply_actions(
            ref self: ContractState, pi: @SpendPublicInputs, actions: @Span<ServerAction>,
        ) {
            let mut in_i: usize = 0;
            let mut out_i: usize = 0;
            let mut wd_i: usize = 0;
            let mut controller_applied = false;

            let mut i: usize = 0;
            while i < actions.len() {
                match *actions.at(i) {
                    ServerAction::NullifierWrite(nullifier) => {
                        assert(nullifier != 0, 'ZERO_NULLIFIER');
                        assert(in_i < pi.input_nullifiers.len(), 'NULLIFIER_MISMATCH');
                        assert(nullifier == *pi.input_nullifiers.at(in_i), 'NULLIFIER_MISMATCH');
                        // WriteOnce (§4): first spend wins, replays revert.
                        assert(!self.nullifiers.read(nullifier), 'NULLIFIER_USED');
                        self.nullifiers.write(nullifier, true);
                        self
                            .emit(
                                Event::NullifierSpent(
                                    NullifierSpent {
                                        nullifier, controller: *pi.controller,
                                    },
                                ),
                            );
                        in_i += 1;
                    },
                    ServerAction::LeafInsert(leaf_action) => {
                        let (commitment, note_id) = leaf_action;
                        assert(out_i < pi.output_commitments.len(), 'COMMITMENT_MISMATCH');
                        assert(
                            commitment == *pi.output_commitments.at(out_i), 'COMMITMENT_MISMATCH',
                        );
                        let leaf_index = self.tree.insert_leaf(commitment);
                        self
                            .emit(
                                Event::NoteCommitted(
                                    NoteCommitted {
                                        note_id, leaf_index, commitment, controller: *pi.controller,
                                    },
                                ),
                            );
                        out_i += 1;
                    },
                    ServerAction::Withdrawal(withdrawal) => {
                        let (token, amount, to_addr) = withdrawal;
                        assert(token.into() != 0, 'ZERO_TOKEN');
                        assert(to_addr.into() != 0, 'ZERO_RECIPIENT');
                        assert(wd_i < pi.withdrawals.len(), 'WITHDRAWAL_MISMATCH');
                        let entry = *pi.withdrawals.at(wd_i);
                        assert(
                            token == entry.token && amount == entry.amount, 'WITHDRAWAL_MISMATCH',
                        );
                        let ok = IERC20Dispatcher { contract_address: token }.transfer(
                            to_addr, amount,
                        );
                        assert(ok, 'TRANSFER_FAILED');
                        self.emit(Event::Withdrawal(Withdrawal { to_addr, token, amount }));
                        wd_i += 1;
                    },
                    ServerAction::ControllerApply(apply) => {
                        let (controller, transition_commitment, deadline, sig_r, sig_s) = apply;
                        assert(!controller_applied, 'MULTIPLE_APPLY');
                        // A controller apply is only meaningful for a
                        // controlled spend (§3.2, §6).
                        assert((*pi.controller).into() != 0, 'UNEXPECTED_APPLY');
                        assert(controller == *pi.controller, 'CONTROLLER_MISMATCH');
                        // The action's deadline is the one the controller
                        // signed into the transition commitment (§6, ADR-0014).
                        assert(deadline == *pi.deadline, 'DEADLINE_MISMATCH');
                        assert(
                            transition_commitment != 0
                                && transition_commitment == *pi.transition_commitment,
                            'BAD_TRANSITION',
                        );
                        // On-chain staleness (§6.4).
                        assert(get_block_number() <= deadline, 'DEADLINE_EXCEEDED');
                        let sig_verifier = ISigVerifierDispatcher {
                            contract_address: self.sig_verifier.read(),
                        };
                        assert(
                            sig_verifier.verify_transition(
                                controller, transition_commitment, sig_r, sig_s,
                            ),
                            'SIG_REJECTED',
                        );
                        self
                            .emit(
                                Event::ControllerAuthorized(
                                    ControllerAuthorized { transition_commitment, controller },
                                ),
                            );
                        controller_applied = true;
                    },
                }
                i += 1;
            }

            // Exact 1:1 counts in both directions.
            assert(in_i == pi.input_nullifiers.len(), 'NULLIFIER_MISMATCH');
            assert(out_i == pi.output_commitments.len(), 'COMMITMENT_MISMATCH');
            assert(wd_i == pi.withdrawals.len(), 'WITHDRAWAL_MISMATCH');

            // Controller field/action consistency (§6): a controlled spend
            // requires exactly one matching apply; an ordinary spend forbids
            // one and pins the commitment and deadline to zero.
            if (*pi.controller).into() != 0 {
                assert(controller_applied, 'CONTROLLER_REQUIRED');
                assert(*pi.transition_commitment != 0, 'BAD_TRANSITION');
            } else {
                assert(*pi.transition_commitment == 0, 'BAD_TRANSITION');
                assert(*pi.deadline == 0, 'BAD_DEADLINE');
            }
        }
    }
}
