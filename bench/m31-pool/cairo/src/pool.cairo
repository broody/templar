//! Option A pool for R0: the reference ordinary pool's `deposit` and `apply_spend`
//! (`controlled-push-e2e/cairo/src/pool.cairo`) over the M31 note tree. Deposits compute the
//! commitment on chain from `inner`; spends check the binding, fact verdict, known root and
//! unused nullifiers, then publish both outputs. `apply_spend_with_invoke` additionally runs one
//! open-note execution (`open_note`): it pays the budget, calls the adapter and appends the
//! funded open notes, all under the pool's lock.
use starknet::ContractAddress;

#[starknet::interface]
pub trait IM31Pool<TState> {
    fn deposit(ref self: TState, token: ContractAddress, amount: u128, inner: Span<felt252>, ciphertext: Span<felt252>);
    fn apply_spend(ref self: TState, spend: crate::spend::Spend, proof: Span<felt252>);
    fn apply_spend_with_invoke(
        ref self: TState, spend: crate::spend::Spend, intent: crate::open_note::ExecutionIntent, proof: Span<felt252>,
    );
    fn get_nullifier_spent(self: @TState, nullifier: Span<felt252>) -> bool;
    fn get_delivery_digest(self: @TState, index: u64) -> felt252;
    fn set_verifier(ref self: TState, verifier: ContractAddress);
    fn get_verifier(self: @TState) -> ContractAddress;
    fn set_shadow_class(ref self: TState, class_hash: starknet::ClassHash, allowed: bool);
    fn is_shadow_class(self: @TState, class_hash: starknet::ClassHash) -> bool;
}

#[starknet::contract]
pub mod M31Pool {
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };
    use starknet::syscalls::{call_contract_syscall, get_class_hash_at_syscall};
    use starknet::{ClassHash, ContractAddress, SyscallResultTrait, get_block_number, get_caller_address, get_contract_address, get_tx_info};
    use crate::hash::{Digest, commitment, is_zero, key, read_digest};
    use crate::open_note::{
        COMPUTE, ExecutionIntent, INVOKE, MAX_NOTES, OpenNoteDeposit, hash_intent, identity_commitment,
        partial_commitment, selector_of,
    };
    use crate::spend::{
        IERC20Dispatcher, IERC20DispatcherTrait, IVerifierDispatcher, IVerifierDispatcherTrait,
        Spend, compute_binding, delivery_digest, is_active,
    };
    use crate::tree::m31_tree_component;
    use crate::tree::m31_tree_component::M31TreeInternalTrait;
    component!(path: m31_tree_component, storage: tree, event: TreeEvent);

    #[storage]
    pub struct Storage {
        owner: ContractAddress,
        verifier: ContractAddress,
        nullifiers: Map<felt252, bool>,
        delivery_digests: Map<u64, felt252>,
        /// Classes a `COMPUTE` execution may call (upstream's shadow-account anonymizer).
        shadow_classes: Map<ClassHash, bool>,
        locked: bool,
        #[substorage(v0)]
        pub tree: m31_tree_component::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        TreeEvent: m31_tree_component::Event,
        NotePublished: NotePublished,
        NullifierSpent: NullifierSpent,
        Deposited: Deposited,
        ShadowClassSet: ShadowClassSet,
        Withdrawn: Withdrawn,
        OpenNoteFunded: OpenNoteFunded,
    }
    /// An open note funded by an execution; its `NotePublished` carries the same index.
    #[derive(Drop, starknet::Event)]
    pub struct OpenNoteFunded {
        pub note_id: felt252,
        pub index: u64,
        pub token: ContractAddress,
        pub amount: u128,
    }
    #[derive(Drop, starknet::Event)]
    pub struct Withdrawn {
        pub token: ContractAddress,
        pub recipient: ContractAddress,
        pub amount: u128,
    }
    #[derive(Drop, starknet::Event)]
    pub struct NotePublished {
        pub index: u64,
        pub commitment: Span<felt252>,
        pub digest: felt252,
        pub ciphertext: Span<felt252>,
    }
    #[derive(Drop, starknet::Event)]
    pub struct NullifierSpent {
        pub nullifier: Span<felt252>,
    }
    #[derive(Drop, starknet::Event)]
    pub struct ShadowClassSet {
        pub class_hash: ClassHash,
        pub allowed: bool,
    }

    #[derive(Drop, starknet::Event)]
    pub struct Deposited {
        pub token: ContractAddress,
        pub amount: u128,
    }

    #[constructor]
    fn constructor(ref self: ContractState, owner: ContractAddress, verifier: ContractAddress, format: u8, store_nodes: bool) {
        assert(owner.into() != 0, 'ZERO_OWNER');
        self.owner.write(owner);
        self.verifier.write(verifier);
        self.tree.initializer(format, store_nodes);
    }

    #[abi(embed_v0)]
    impl TreeImpl = m31_tree_component::M31Tree<ContractState>;

    #[abi(embed_v0)]
    impl PoolImpl of super::IM31Pool<ContractState> {
        fn deposit(ref self: ContractState, token: ContractAddress, amount: u128, inner: Span<felt252>, ciphertext: Span<felt252>) {
            self.start();
            let inner = read_digest(inner);
            assert(token.into() != 0 && amount != 0 && !is_zero(inner), 'BAD_DEPOSIT');
            let digest = delivery_digest(ciphertext);
            let cm = commitment(get_tx_info().unbox().chain_id, get_contract_address().into(), token.into(), amount, inner);
            assert(
                IERC20Dispatcher { contract_address: token }.transfer_from(get_caller_address(), get_contract_address(), amount.into()),
                'TRANSFER_FAILED',
            );
            self.publish(cm, digest, ciphertext);
            self.emit(Deposited { token, amount });
            self.locked.write(false);
        }

        fn apply_spend(ref self: ContractState, spend: Spend, proof: Span<felt252>) {
            self.start();
            assert(spend.intent == 0 && !is_active(spend.identity), 'INTENT_NEEDS_INVOKE');
            self.verify_spend(@spend, proof);
            let created = self.publish_outputs(@spend);
            self.pay_withdrawal(@spend, created > 0);
            self.locked.write(false);
        }

        fn apply_spend_with_invoke(ref self: ContractState, spend: Spend, intent: ExecutionIntent, proof: Span<felt252>) {
            self.start();
            assert(spend.intent != 0 && spend.intent == hash_intent(@spend, @intent), 'EXECUTION_INTENT');
            assert(get_block_number() <= intent.expiry, 'EXECUTION_EXPIRED');
            let this = get_contract_address();
            assert(intent.adapter.into() != 0 && intent.adapter != this, 'EXECUTION_ADAPTER');
            // A shadow-account execution needs the proven identity handle; a plain one publishes none.
            if intent.kind == COMPUTE {
                assert(is_active(spend.identity), 'IDENTITY_REQUIRED');
                // Upstream targets trust `privacy_invoke_with_computation`'s calldata prefix as
                // their own `privacy_compute` output. Ours is `[identity commitment] ++ user
                // calldata`, which matches only the shadow anonymizer's compute; other targets
                // would read user data as proven output.
                let class = get_class_hash_at_syscall(intent.adapter).unwrap_syscall();
                assert(self.shadow_classes.read(class), 'COMPUTE_TARGET');
            } else {
                assert(intent.kind == INVOKE && !is_active(spend.identity), 'IDENTITY_UNEXPECTED');
            }
            self.verify_spend(@spend, proof);
            // Private outputs first, then the funded open notes; all appended together below.
            let mut pending = self.pending_outputs(@spend);
            let created = pending.len();
            let n = intent.destinations.len();
            assert(created + n <= MAX_NOTES, 'TOTAL_NOTE_COUNT');
            // The budget (possibly zero) goes to the recipient the intent names, never the pool.
            assert(spend.withdrawal.recipient != this, 'BUDGET_RECIPIENT');
            self.pay_withdrawal(@spend, true);
            // The external call; the adapter may not re-enter the pool (the lock is held).
            let mut calldata = array![];
            if intent.kind == COMPUTE {
                calldata.append(identity_commitment(partial_commitment(spend.identity), 0));
            }
            calldata.append_span(intent.calldata);
            let mut ret = call_contract_syscall(intent.adapter, selector_of(intent.kind), calldata.span()).unwrap_syscall();
            let deposits: Span<OpenNoteDeposit> = Serde::deserialize(ref ret).expect('INVOKE_RETURN');
            if intent.kind == COMPUTE && !ret.is_empty() {
                // Upstream's shadow anonymizer also returns the shadow account's address.
                let _associated: Span<ContractAddress> = Serde::deserialize(ref ret).expect('INVOKE_RETURN');
            }
            assert(ret.is_empty(), 'INVOKE_RETURN');
            assert(deposits.len() == n, 'OPEN_NOTE_COUNT');
            // Match each deposit to its destination, in order; pull the actual proceeds.
            for i in 0..n {
                let d = *deposits.at(i);
                let dest = *intent.destinations.at(i);
                assert(d.note_id == dest.note_id, 'OPEN_NOTE_ID');
                assert(d.token == dest.token, 'OPEN_NOTE_TOKEN');
                assert(d.amount != 0 && d.amount >= dest.minimum, 'OPEN_NOTE_AMOUNT');
                let erc = IERC20Dispatcher { contract_address: dest.token };
                let before = erc.balance_of(this);
                assert(erc.transfer_from(intent.adapter, this, d.amount.into()), 'TRANSFER_FAILED');
                assert(erc.balance_of(this) - before == d.amount.into(), 'OPEN_NOTE_FUNDING');
                let cm = commitment(spend.chain, this.into(), dest.token.into(), d.amount, read_digest(dest.inner));
                pending.append((cm, delivery_digest(dest.ciphertext), dest.ciphertext));
            }
            // Every new note of the transaction, appended in pairs (`insert_two`).
            let first = self.append_notes(pending.span());
            for i in 0..n {
                let dest = *intent.destinations.at(i);
                let index = first + created.into() + i.into();
                self.emit(OpenNoteFunded { note_id: dest.note_id, index, token: dest.token, amount: (*deposits.at(i)).amount });
            }
            self.locked.write(false);
        }

        fn get_nullifier_spent(self: @ContractState, nullifier: Span<felt252>) -> bool {
            self.nullifiers.read(key(read_digest(nullifier)))
        }

        fn get_delivery_digest(self: @ContractState, index: u64) -> felt252 {
            assert(index < self.tree.tree_count.read(), 'UNKNOWN_INDEX');
            self.delivery_digests.read(index)
        }

        /// Owner only: the adapter needs the pool's address, so it is attached after deployment.
        fn set_verifier(ref self: ContractState, verifier: ContractAddress) {
            assert(get_caller_address() == self.owner.read(), 'NOT_OWNER');
            assert(verifier.into() != 0, 'ZERO_VERIFIER');
            self.verifier.write(verifier);
        }

        fn get_verifier(self: @ContractState) -> ContractAddress {
            self.verifier.read()
        }

        /// Owner only: allow or revoke a shadow-anonymizer class as a `COMPUTE` target. An
        /// upgrade of an anonymizer changes its class and disables it until its new class is
        /// allowed.
        fn set_shadow_class(ref self: ContractState, class_hash: ClassHash, allowed: bool) {
            assert(get_caller_address() == self.owner.read(), 'NOT_OWNER');
            assert(class_hash.into() != 0, 'ZERO_CLASS');
            self.shadow_classes.write(class_hash, allowed);
            self.emit(ShadowClassSet { class_hash, allowed });
        }

        fn is_shadow_class(self: @ContractState, class_hash: ClassHash) -> bool {
            self.shadow_classes.read(class_hash)
        }
    }

    #[generate_trait]
    impl InternalImpl of InternalTrait {
        /// Chain, pool and token context, the binding, the fact verdict, a known root, and fresh
        /// nullifiers (marked spent).
        fn verify_spend(ref self: ContractState, spend: @Spend, proof: Span<felt252>) {
            assert(*spend.chain == get_tx_info().unbox().chain_id, 'WRONG_CHAIN');
            assert(*spend.pool == get_contract_address(), 'WRONG_POOL');
            assert((*spend.token).into() != 0, 'ZERO_TOKEN');
            let binding = compute_binding(spend);
            assert(binding == *spend.binding, 'BAD_BINDING');
            let public = array![*spend.chain, (*spend.pool).into(), binding];
            assert(IVerifierDispatcher { contract_address: self.verifier.read() }.verify(proof, public.span()), 'PROOF_REJECTED');
            assert(self.tree.root_history.read(key(read_digest(*spend.root))), 'UNKNOWN_ROOT');
            let mut nullifiers = *spend.nullifiers;
            while let Some(words) = nullifiers.multi_pop_front::<9>() {
                let nf = read_digest(words.unbox().span());
                assert(!is_zero(nf), 'ZERO_NULLIFIER');
                let k = key(nf);
                assert(!self.nullifiers.read(k), 'NULLIFIER_USED');
                self.nullifiers.write(k, true);
                self.emit(NullifierSpent { nullifier: nf.span() });
            }
        }

        /// Appends the active private outputs (two in one pass when both are active); returns how
        /// many were created.
        fn publish_outputs(ref self: ContractState, spend: @Spend) -> u32 {
            let o0 = spend.outputs.at(0);
            let o1 = spend.outputs.at(1);
            let (a0, a1) = (is_active(*o0.commitment), is_active(*o1.commitment));
            if a0 && a1 {
                let (d0, d1) = (delivery_digest(*o0.ciphertext), delivery_digest(*o1.ciphertext));
                assert(d0 != 0 && d1 != 0, 'ZERO_DELIVERY');
                let (cm0, cm1) = (read_digest(*o0.commitment), read_digest(*o1.commitment));
                let index = self.tree.insert_two(cm0, cm1);
                self.delivery_digests.write(index, d0);
                self.delivery_digests.write(index + 1, d1);
                self.emit(NotePublished { index, commitment: cm0.span(), digest: d0, ciphertext: *o0.ciphertext });
                self.emit(NotePublished { index: index + 1, commitment: cm1.span(), digest: d1, ciphertext: *o1.ciphertext });
                return 2;
            }
            let mut created = 0_u32;
            for output in *spend.outputs {
                if is_active(*output.commitment) {
                    self.publish(read_digest(*output.commitment), delivery_digest(*output.ciphertext), *output.ciphertext);
                    created += 1;
                }
            }
            created
        }

        /// The active private outputs as `(commitment, delivery digest, ciphertext)`, not yet appended.
        fn pending_outputs(self: @ContractState, spend: @Spend) -> Array<(Digest, felt252, Span<felt252>)> {
            let mut pending = array![];
            for output in *spend.outputs {
                if is_active(*output.commitment) {
                    pending.append((read_digest(*output.commitment), delivery_digest(*output.ciphertext), *output.ciphertext));
                }
            }
            pending
        }

        /// Appends `notes` in order, two per `insert_two` pass (and a last single one), records
        /// their delivery digests and emits `NotePublished`; returns the first index.
        fn append_notes(ref self: ContractState, notes: Span<(Digest, felt252, Span<felt252>)>) -> u64 {
            let first = self.tree.tree_count.read();
            let mut i = 0;
            while i < notes.len() {
                if i + 1 < notes.len() {
                    let (cm0, _, _) = *notes.at(i);
                    let (cm1, _, _) = *notes.at(i + 1);
                    self.tree.insert_two(cm0, cm1);
                    i += 2;
                } else {
                    let (cm, _, _) = *notes.at(i);
                    self.tree.insert_leaf(cm);
                    i += 1;
                }
            }
            for k in 0..notes.len() {
                let (cm, digest, ciphertext) = *notes.at(k);
                assert(digest != 0, 'ZERO_DELIVERY');
                let index = first + k.into();
                self.delivery_digests.write(index, digest);
                self.emit(NotePublished { index, commitment: cm.span(), digest, ciphertext });
            }
            first
        }

        /// Pays the withdrawal, if any. Without one, the spend must have produced something
        /// (`produced`): a private output or, under an execution, open notes.
        fn pay_withdrawal(ref self: ContractState, spend: @Spend, produced: bool) {
            let w = *spend.withdrawal;
            if w.amount != 0 {
                assert(w.recipient.into() != 0, 'BAD_WITHDRAWAL');
                assert(
                    IERC20Dispatcher { contract_address: *spend.token }.transfer(w.recipient, w.amount.into()),
                    'TRANSFER_FAILED',
                );
                self.emit(Withdrawn { token: *spend.token, recipient: w.recipient, amount: w.amount });
            } else {
                assert(w.recipient.into() == 0, 'BAD_WITHDRAWAL');
                assert(produced, 'EMPTY_OUTPUT');
            }
        }

        fn start(ref self: ContractState) {
            assert(!self.locked.read(), 'REENTRANCY');
            self.locked.write(true);
        }

        fn publish(ref self: ContractState, commitment: Digest, digest: felt252, ciphertext: Span<felt252>) {
            assert(digest != 0, 'ZERO_DELIVERY');
            let index = self.tree.insert_leaf(commitment);
            self.delivery_digests.write(index, digest);
            self.emit(NotePublished { index, commitment: commitment.span(), digest, ciphertext });
        }
    }
}
