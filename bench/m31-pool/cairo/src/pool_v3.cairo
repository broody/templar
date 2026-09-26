//! M31 pool V3 (`docs/account-bound-note-spec.md` §8): a fresh deployment whose spends are R0 V5.
//! Deposits, assets, `held`, payouts, open-note invokes, policy notes and shadow classes are pool
//! V2's (`pool_v2.cairo`, `docs/hidden-asset-spec.md` §5). The changes:
//!
//! - **Spends** take a V5 `Spend` (V4's plus `valid_until`) bound by `TMR0_BIND_V5`, and must land
//!   by `valid_until`: `block ≤ valid_until`, `valid_until % Q = 0`, `valid_until ≤ block + E + Q`
//!   (§8.2).
//! - **Roots** are accepted by block height (`tree_v3.cairo`, §8.3), on every spend path.
//! - **Owner levers are timelocked** (§8.4): the verifiers (R0 V5 and P1) and the shadow-class
//!   allowlist change only by `propose` → `apply` (from `eta = now + T` until `eta + T`), with
//!   `cancel`, events and views. The constructor takes no verifier: a one-time `initialize` sets
//!   both and the first allowlist, and deposits and spends revert until it has run. Ownership moves
//!   in two steps.
//! - **Carried fixes** (§8.5): the tree format is fixed to the compress tree (F30); every ERC20
//!   pull checks the payer's balance fell by the amount, and every ERC20 payout the pool's (F17); an
//!   `INVOKE` target is not an allowlisted shadow class (F18); verifier changes emit events (F19).
//! - **No fees and no gating** (§8.6): any account deposits, and any account submits a proved spend.
use starknet::ContractAddress;

/// The verifier kinds the pool trusts.
pub const R0: felt252 = 'R0';
pub const P1: felt252 = 'P1';

#[derive(Copy, Drop, Serde, PartialEq, Debug)]
pub struct Parameters {
    /// `E`, in blocks.
    pub expiry_window: u64,
    /// `Q`, in blocks.
    pub quantum: u64,
    /// `W`, in blocks.
    pub root_window: u64,
    /// `T`, in seconds.
    pub timelock: u64,
}

#[starknet::interface]
pub trait IM31PoolV3<TState> {
    fn deposit(ref self: TState, token: ContractAddress, amount: u128, inner: Span<felt252>, ciphertext: Span<felt252>);
    fn apply_spend(ref self: TState, spend: crate::spend5::Spend, proof: Span<felt252>);
    fn apply_spend_with_invoke(
        ref self: TState, spend: crate::spend5::Spend, intent: crate::open_note::ExecutionIntent, proof: Span<felt252>,
    );
    fn apply_policy_spend(
        ref self: TState, spend: crate::policy::PolicySpend, data: Span<felt252>, ciphertexts: Span<Span<felt252>>,
        proof: Span<felt252>,
    );
    fn get_nullifier_spent(self: @TState, nullifier: Span<felt252>) -> bool;
    fn get_delivery_digest(self: @TState, index: u64) -> felt252;
    fn get_asset(self: @TState, asset: felt252) -> crate::assets::AssetInfo;
    fn get_contract_standard(self: @TState, contract: ContractAddress) -> u16;
    fn get_held(self: @TState, asset: felt252) -> u256;
    fn get_parameters(self: @TState) -> Parameters;
    /// Sets both verifiers and the first shadow-class allowlist once, before any deposit.
    fn initialize(
        ref self: TState, r0_verifier: ContractAddress, p1_verifier: ContractAddress,
        shadow_classes: Span<starknet::ClassHash>,
    );
    /// Proposes an owner change, applicable from `eta = now + T` until `eta + T`. `key` is `R0` or
    /// `P1` for that verifier (`value`: its address), or a shadow class hash (`value`: 1 to allow,
    /// 0 to disallow). A new proposal for a key replaces a pending one, with a fresh `eta`.
    fn propose(ref self: TState, key: felt252, value: felt252);
    fn apply(ref self: TState, key: felt252);
    fn cancel(ref self: TState, key: felt252);
    /// The pending value for `key` and its `eta` (zero when none).
    fn get_proposal(self: @TState, key: felt252) -> (felt252, u64);
    fn get_verifier(self: @TState, kind: felt252) -> ContractAddress;
    /// Starts a transfer to `new_owner`; zero cancels a pending one.
    fn transfer_ownership(ref self: TState, new_owner: ContractAddress);
    fn accept_ownership(ref self: TState);
    fn get_owner(self: @TState) -> ContractAddress;
    fn get_pending_owner(self: @TState) -> ContractAddress;
    fn is_shadow_class(self: @TState, class_hash: starknet::ClassHash) -> bool;
}

#[starknet::contract]
pub mod M31PoolV3 {
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess, StoragePointerWriteAccess,
    };
    use starknet::syscalls::{call_contract_syscall, get_class_hash_at_syscall};
    use starknet::{
        ClassHash, ContractAddress, SyscallResultTrait, get_block_number, get_block_timestamp, get_caller_address,
        get_contract_address, get_tx_info,
    };
    use crate::assets::{
        AssetInfo, ERC1155, ERC20, ERC721, IAssetReceiver, IERC1155Dispatcher, IERC1155DispatcherTrait,
        IERC1155_ID, IERC1155_RECEIVER_ID, IERC721Dispatcher, IERC721DispatcherTrait, IERC721_ID,
        IERC721_RECEIVER_ID, ISRC5Dispatcher, ISRC5DispatcherTrait, ISRC5_ID, asset_id, below_bound,
    };
    use crate::hash::{Digest, commitment, is_zero, key, read_digest};
    use crate::open_note::{
        COMPUTE, ExecutionIntent, INVOKE, MAX_NOTES, OpenNoteDeposit, hash_intent_of, identity_commitment,
        partial_commitment, selector_of,
    };
    use crate::policy::{FIXED, MAX_POLICY_DATA, PolicySpend, call_controller, policy_binding};
    use crate::spend::{IERC20Dispatcher, IERC20DispatcherTrait, IVerifierDispatcher, IVerifierDispatcherTrait, delivery_digest, is_active};
    use crate::spend5::{Spend, compute_binding};
    use crate::tree_v3::m31_tree_v3_component;
    use crate::tree_v3::m31_tree_v3_component::M31TreeInternalTrait;
    use super::{P1, Parameters, R0};
    component!(path: m31_tree_v3_component, storage: tree, event: TreeEvent);

    /// Hook `data`: nine `inner` words, then the ten-word ciphertext.
    const HOOK_DATA_LEN: u32 = 19;
    /// Bound on `E` and `Q`, so `block + E + Q` never overflows.
    const MAX_BLOCKS: u64 = 0xffffffff;

    #[storage]
    pub struct Storage {
        owner: ContractAddress,
        pending_owner: ContractAddress,
        /// Keyed by kind (`R0`, `P1`).
        verifiers: Map<felt252, ContractAddress>,
        /// Proposals, keyed by a verifier kind or a shadow class hash: the proposed value and its
        /// `eta` (zero: none).
        pending_values: Map<felt252, felt252>,
        pending_etas: Map<felt252, u64>,
        expiry_window: u64,
        quantum: u64,
        timelock: u64,
        nullifiers: Map<felt252, bool>,
        delivery_digests: Map<u64, felt252>,
        shadow_classes: Map<ClassHash, bool>,
        locked: bool,
        assets: Map<felt252, AssetInfo>,
        contract_standard: Map<ContractAddress, u16>,
        held: Map<felt252, u256>,
        #[substorage(v0)]
        pub tree: m31_tree_v3_component::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        TreeEvent: m31_tree_v3_component::Event,
        NotePublished: NotePublished,
        NullifierSpent: NullifierSpent,
        Deposited: Deposited,
        Withdrawn: Withdrawn,
        AssetRegistered: AssetRegistered,
        ShadowClassSet: ShadowClassSet,
        OpenNoteFunded: OpenNoteFunded,
        PolicySettled: PolicySettled,
        VerifierChanged: VerifierChanged,
        Proposed: Proposed,
        Cancelled: Cancelled,
        OwnershipTransferStarted: OwnershipTransferStarted,
        OwnershipTransferred: OwnershipTransferred,
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
    pub struct Deposited {
        pub asset: felt252,
        pub amount: u128,
    }
    #[derive(Drop, starknet::Event)]
    pub struct Withdrawn {
        pub asset: felt252,
        pub recipient: ContractAddress,
        pub amount: u128,
    }
    /// Indexers must read this event from the pool's address only.
    #[derive(Drop, starknet::Event)]
    pub struct AssetRegistered {
        pub asset: felt252,
        pub standard: u16,
        pub contract: ContractAddress,
        pub id: u256,
    }
    #[derive(Drop, starknet::Event, PartialEq, Debug)]
    pub struct ShadowClassSet {
        pub class_hash: ClassHash,
        pub allowed: bool,
    }

    #[derive(Drop, starknet::Event)]
    pub struct OpenNoteFunded {
        pub note_id: felt252,
        pub index: u64,
        pub token: ContractAddress,
        pub amount: u128,
    }
    #[derive(Drop, starknet::Event)]
    pub struct PolicySettled {
        pub nullifier: felt252,
        pub controller: ContractAddress,
        pub handle: felt252,
        pub policy_id: felt252,
        pub outcome: u8,
        pub x: u128,
        pub first_index: u64,
        pub by_controller: bool,
    }
    #[derive(Drop, starknet::Event, PartialEq, Debug)]
    pub struct VerifierChanged {
        #[key]
        pub kind: felt252,
        pub verifier: ContractAddress,
    }
    /// A proposal (`key`: a verifier kind or a shadow class hash), applicable from `eta`.
    #[derive(Drop, starknet::Event, PartialEq, Debug)]
    pub struct Proposed {
        #[key]
        pub key: felt252,
        pub value: felt252,
        pub eta: u64,
    }
    /// A proposal withdrawn, or replaced by a newer one for the same key (AB-PV3).
    #[derive(Drop, starknet::Event, PartialEq, Debug)]
    pub struct Cancelled {
        #[key]
        pub key: felt252,
        pub value: felt252,
    }
    #[derive(Drop, starknet::Event, PartialEq, Debug)]
    pub struct OwnershipTransferStarted {
        pub previous_owner: ContractAddress,
        pub new_owner: ContractAddress,
    }
    #[derive(Drop, starknet::Event, PartialEq, Debug)]
    pub struct OwnershipTransferred {
        pub previous_owner: ContractAddress,
        pub new_owner: ContractAddress,
    }

    /// `E`, `Q` and `W` in blocks, `T` in seconds. `W ≥ E + Q`, so a root that was current when
    /// the client read the latest block stays accepted through the `valid_until` it derived.
    #[constructor]
    fn constructor(
        ref self: ContractState, owner: ContractAddress, store_nodes: bool, expiry_window: u64, quantum: u64,
        root_window: u64, timelock: u64,
    ) {
        assert(owner.into() != 0, 'ZERO_OWNER');
        assert(quantum != 0 && quantum <= MAX_BLOCKS && expiry_window <= MAX_BLOCKS, 'EXPIRY_RULES');
        assert(root_window >= expiry_window + quantum, 'ROOT_WINDOW');
        assert(timelock != 0, 'TIMELOCK');
        self.owner.write(owner);
        self.expiry_window.write(expiry_window);
        self.quantum.write(quantum);
        self.timelock.write(timelock);
        self.tree.initializer(store_nodes, root_window);
        self.emit(OwnershipTransferred { previous_owner: 0.try_into().unwrap(), new_owner: owner });
    }

    #[abi(embed_v0)]
    impl TreeImpl = m31_tree_v3_component::M31TreeV3<ContractState>;

    #[abi(embed_v0)]
    impl PoolImpl of super::IM31PoolV3<ContractState> {
        /// ERC20 deposit: pulls `amount`; the pool's balance must rise, and the caller's fall, by
        /// exactly `amount` (F17).
        fn deposit(ref self: ContractState, token: ContractAddress, amount: u128, inner: Span<felt252>, ciphertext: Span<felt252>) {
            self.start();
            let inner = read_digest(inner);
            assert(token.into() != 0 && amount != 0 && !is_zero(inner), 'BAD_DEPOSIT');
            let asset: felt252 = token.into();
            // An identifier registered as an NFT asset is never an ERC20 address.
            assert(self.assets.read(asset).standard == 0, 'ASSET_REGISTERED');
            self.record_standard(token, ERC20);
            let digest = delivery_digest(ciphertext);
            pull_exact(token, get_caller_address(), amount, 'DEPOSIT_AMOUNT');
            self.held.write(asset, self.held.read(asset) + amount.into());
            self.publish(self.note(asset, amount, inner), digest, ciphertext);
            self.emit(Deposited { asset, amount });
            self.locked.write(false);
        }

        fn apply_spend(ref self: ContractState, spend: Spend, proof: Span<felt252>) {
            self.start();
            assert(spend.intent == 0 && !is_active(spend.identity), 'INTENT_NEEDS_INVOKE');
            self.verify_spend(@spend, proof);
            let pending = self.outputs(@spend);
            self.append_notes(pending.span());
            let w = spend.withdrawal;
            if w.amount != 0 {
                self.pay_out(spend.asset, w.recipient, w.amount);
            }
            self.locked.write(false);
        }

        fn apply_spend_with_invoke(ref self: ContractState, spend: Spend, intent: ExecutionIntent, proof: Span<felt252>) {
            self.start();
            let this = get_contract_address();
            assert(
                spend.intent != 0
                    && spend.intent == hash_intent_of(spend.chain, spend.pool.into(), spend.asset, spend.withdrawal, @intent),
                'EXECUTION_INTENT',
            );
            assert(get_block_number() <= intent.expiry, 'EXECUTION_EXPIRED');
            assert(intent.adapter.into() != 0 && intent.adapter != this, 'EXECUTION_ADAPTER');
            let class = get_class_hash_at_syscall(intent.adapter).unwrap_syscall();
            if intent.kind == COMPUTE {
                assert(is_active(spend.identity), 'IDENTITY_REQUIRED');
                assert(self.shadow_classes.read(class), 'COMPUTE_TARGET');
            } else {
                assert(intent.kind == INVOKE && !is_active(spend.identity), 'IDENTITY_UNEXPECTED');
                // A shadow class acts for an identity; INVOKE carries no proven one (F18).
                assert(!self.shadow_classes.read(class), 'INVOKE_TARGET');
            }
            self.verify_spend(@spend, proof);
            // Executions move ERC20 only, on both sides.
            let asset: ContractAddress = spend.asset.try_into().expect('EXECUTION_ASSET');
            assert(self.contract_standard.read(asset) == ERC20, 'EXECUTION_ASSET');
            let mut pending = self.outputs(@spend);
            let created = pending.len();
            let n = intent.destinations.len();
            assert(created + n <= MAX_NOTES, 'TOTAL_NOTE_COUNT');
            // Destinations are ERC20, checked before any external effect.
            for dest in intent.destinations {
                let token: felt252 = (*dest.token).into();
                assert(self.assets.read(token).standard == 0, 'ASSET_REGISTERED');
                self.record_standard(*dest.token, ERC20);
            }
            // The budget (possibly zero; `verify_spend` ties a zero one to a zero recipient) goes
            // to the recipient the intent names, never the pool.
            let w = spend.withdrawal;
            if w.amount != 0 {
                self.pay_out(spend.asset, w.recipient, w.amount);
            }
            let mut calldata = array![];
            if intent.kind == COMPUTE {
                calldata.append(identity_commitment(partial_commitment(spend.identity), 0));
            }
            calldata.append_span(intent.calldata);
            let mut ret = call_contract_syscall(intent.adapter, selector_of(intent.kind), calldata.span()).unwrap_syscall();
            let deposits: Span<OpenNoteDeposit> = Serde::deserialize(ref ret).expect('INVOKE_RETURN');
            if intent.kind == COMPUTE && !ret.is_empty() {
                let _associated: Span<ContractAddress> = Serde::deserialize(ref ret).expect('INVOKE_RETURN');
            }
            assert(ret.is_empty(), 'INVOKE_RETURN');
            assert(deposits.len() == n, 'OPEN_NOTE_COUNT');
            for i in 0..n {
                let d = *deposits.at(i);
                let dest = *intent.destinations.at(i);
                assert(d.note_id == dest.note_id, 'OPEN_NOTE_ID');
                assert(d.token == dest.token, 'OPEN_NOTE_TOKEN');
                assert(d.amount != 0 && d.amount >= dest.minimum, 'OPEN_NOTE_AMOUNT');
                let token: felt252 = dest.token.into();
                pull_exact(dest.token, intent.adapter, d.amount, 'OPEN_NOTE_FUNDING');
                self.held.write(token, self.held.read(token) + d.amount.into());
                let cm = self.note(token, d.amount, read_digest(dest.inner));
                pending.append((cm, delivery_digest(dest.ciphertext), dest.ciphertext));
            }
            let first = self.append_notes(pending.span());
            for i in 0..n {
                let dest = *intent.destinations.at(i);
                let index = first + created.into() + i.into();
                self.emit(OpenNoteFunded { note_id: dest.note_id, index, token: dest.token, amount: (*deposits.at(i)).amount });
            }
            self.locked.write(false);
        }

        /// Settles a policy note from a P1 statement, as pool V2, with the root rule of §8.3.
        fn apply_policy_spend(
            ref self: ContractState, spend: PolicySpend, data: Span<felt252>, ciphertexts: Span<Span<felt252>>,
            proof: Span<felt252>,
        ) {
            self.start();
            let this = get_contract_address();
            assert(spend.chain == get_tx_info().unbox().chain_id, 'WRONG_CHAIN');
            assert(spend.pool == this, 'WRONG_POOL');
            assert(spend.token.into() != 0, 'ZERO_TOKEN');
            assert(ciphertexts.len() == 2, 'CIPHERTEXT_COUNT');
            let mut notes: Array<(Digest, felt252, Span<felt252>)> = array![];
            let deliveries = [spend.delivery0, spend.delivery1];
            for j in 0..2_u32 {
                let cm = read_digest(spend.commitments.slice(9 * j, 9));
                let ct = *ciphertexts.at(j);
                let d = *deliveries.span().at(j);
                if is_zero(cm) {
                    assert(ct.len() == 0 && d == 0, 'INACTIVE_PAYLOAD');
                } else {
                    assert(d != 0 && delivery_digest(ct) == d, 'DELIVERY');
                    notes.append((cm, d, ct));
                }
            }
            let binding = policy_binding(@spend);
            assert(binding == spend.binding, 'BAD_BINDING');
            let public = array![spend.chain, this.into(), binding];
            let verifier = self.verifiers.read(P1);
            assert(IVerifierDispatcher { contract_address: verifier }.verify(proof, public.span()), 'PROOF_REJECTED');
            assert(self.tree.root_is_valid(read_digest(spend.root)), 'UNKNOWN_ROOT');
            let nf = read_digest(spend.nullifier);
            assert(!is_zero(nf), 'ZERO_NULLIFIER');
            let nf_key = key(nf);
            assert(!self.nullifiers.read(nf_key), 'NULLIFIER_USED');
            self.nullifiers.write(nf_key, true);
            self.emit(NullifierSpent { nullifier: nf.span() });
            assert(data.len() <= MAX_POLICY_DATA, 'POLICY_DATA_LIMIT');
            assert(core::poseidon::poseidon_hash_span(data) == spend.data, 'POLICY_DATA');
            let b = get_block_number();
            assert(b >= spend.not_before, 'POLICY_NOT_BEFORE');
            assert(spend.index != 0 || spend.kind == FIXED, 'REFUND_TYPE');
            if spend.index == 0 {
                let w = spend.withdrawal;
                assert(w.amount == 0 && w.recipient.into() == 0 && notes.len() > 0, 'REFUND_SHAPE');
            }
            let by_controller = b <= spend.deadline;
            if by_controller {
                call_controller(@spend, this, data);
            } else {
                assert(spend.index == 0, 'POLICY_EXPIRED');
            }
            let first = self.tree.tree_count.read();
            if notes.len() > 0 {
                self.append_notes(notes.span());
            }
            let w = spend.withdrawal;
            if w.amount != 0 {
                self.pay_out(spend.token.into(), w.recipient, w.amount);
            } else {
                assert(w.recipient.into() == 0, 'BAD_WITHDRAWAL');
                assert(notes.len() > 0, 'EMPTY_OUTPUT');
            }
            self.emit(PolicySettled {
                nullifier: nf_key, controller: spend.controller, handle: spend.handle,
                policy_id: key(read_digest(spend.policy_id)), outcome: spend.index, x: spend.x,
                first_index: first, by_controller,
            });
            self.locked.write(false);
        }

        fn get_nullifier_spent(self: @ContractState, nullifier: Span<felt252>) -> bool {
            self.nullifiers.read(key(read_digest(nullifier)))
        }

        fn get_delivery_digest(self: @ContractState, index: u64) -> felt252 {
            assert(index < self.tree.tree_count.read(), 'UNKNOWN_INDEX');
            self.delivery_digests.read(index)
        }

        fn get_asset(self: @ContractState, asset: felt252) -> AssetInfo {
            self.assets.read(asset)
        }

        fn get_contract_standard(self: @ContractState, contract: ContractAddress) -> u16 {
            self.contract_standard.read(contract)
        }

        fn get_held(self: @ContractState, asset: felt252) -> u256 {
            self.held.read(asset)
        }

        fn get_parameters(self: @ContractState) -> Parameters {
            Parameters {
                expiry_window: self.expiry_window.read(), quantum: self.quantum.read(),
                root_window: self.tree.root_window.read(), timelock: self.timelock.read(),
            }
        }

        /// Allowed once, while no verifier is set and the tree is empty (§8.4).
        fn initialize(
            ref self: ContractState, r0_verifier: ContractAddress, p1_verifier: ContractAddress,
            shadow_classes: Span<ClassHash>,
        ) {
            self.only_owner();
            assert(self.verifiers.read(R0).into() == 0 && self.verifiers.read(P1).into() == 0, 'INITIALIZED');
            assert(self.tree.tree_count.read() == 0, 'TREE_NOT_EMPTY');
            assert(r0_verifier.into() != 0 && p1_verifier.into() != 0, 'ZERO_VERIFIER');
            self.verifiers.write(R0, r0_verifier);
            self.verifiers.write(P1, p1_verifier);
            self.emit(VerifierChanged { kind: R0, verifier: r0_verifier });
            self.emit(VerifierChanged { kind: P1, verifier: p1_verifier });
            for class_hash in shadow_classes {
                assert((*class_hash).into() != 0, 'ZERO_CLASS');
                self.shadow_classes.write(*class_hash, true);
                self.emit(ShadowClassSet { class_hash: *class_hash, allowed: true });
            }
        }

        fn propose(ref self: ContractState, key: felt252, value: felt252) {
            self.only_owner();
            if is_kind(key) {
                assert(self.verifiers.read(R0).into() != 0, 'NOT_INITIALIZED');
                let verifier: ContractAddress = value.try_into().expect('VERIFIER_ADDRESS');
                assert(verifier.into() != 0, 'ZERO_VERIFIER');
            } else {
                let class_hash: ClassHash = key.try_into().expect('SHADOW_CLASS');
                assert(class_hash.into() != 0, 'ZERO_CLASS');
                assert(value == 0 || value == 1, 'SHADOW_VALUE');
            }
            let (old, old_eta) = self.pending(key);
            if old_eta != 0 {
                self.emit(Cancelled { key, value: old });
            }
            let eta = get_block_timestamp() + self.timelock.read();
            self.pending_values.write(key, value);
            self.pending_etas.write(key, eta);
            self.emit(Proposed { key, value, eta });
        }

        /// From `eta` until `eta + T` (AB-PV2); after that the proposal lapses and must be made again.
        fn apply(ref self: ContractState, key: felt252) {
            self.only_owner();
            let (value, eta) = self.pending(key);
            let now = get_block_timestamp();
            assert(eta != 0, 'NO_PROPOSAL');
            assert(now >= eta, 'TIMELOCK');
            assert(now <= eta + self.timelock.read(), 'PROPOSAL_LAPSED');
            self.clear(key);
            if is_kind(key) {
                let verifier: ContractAddress = value.try_into().unwrap();
                self.verifiers.write(key, verifier);
                self.emit(VerifierChanged { kind: key, verifier });
            } else {
                let class_hash: ClassHash = key.try_into().unwrap();
                let allowed = value != 0;
                self.shadow_classes.write(class_hash, allowed);
                self.emit(ShadowClassSet { class_hash, allowed });
            }
        }

        fn cancel(ref self: ContractState, key: felt252) {
            self.only_owner();
            let (value, eta) = self.pending(key);
            assert(eta != 0, 'NO_PROPOSAL');
            self.clear(key);
            self.emit(Cancelled { key, value });
        }

        fn get_proposal(self: @ContractState, key: felt252) -> (felt252, u64) {
            self.pending(key)
        }

        fn get_verifier(self: @ContractState, kind: felt252) -> ContractAddress {
            assert(is_kind(kind), 'VERIFIER_KIND');
            self.verifiers.read(kind)
        }

        fn transfer_ownership(ref self: ContractState, new_owner: ContractAddress) {
            self.only_owner();
            self.pending_owner.write(new_owner);
            self.emit(OwnershipTransferStarted { previous_owner: self.owner.read(), new_owner });
        }

        fn accept_ownership(ref self: ContractState) {
            let caller = get_caller_address();
            assert(caller.into() != 0 && caller == self.pending_owner.read(), 'NOT_PENDING_OWNER');
            let previous_owner = self.owner.read();
            self.owner.write(caller);
            self.pending_owner.write(0.try_into().unwrap());
            self.emit(OwnershipTransferred { previous_owner, new_owner: caller });
        }

        fn get_owner(self: @ContractState) -> ContractAddress {
            self.owner.read()
        }

        fn get_pending_owner(self: @ContractState) -> ContractAddress {
            self.pending_owner.read()
        }

        /// Changed only through `propose`/`apply` (AB-PV1): allowlisting cannot move funds, but it
        /// opens and closes routes (INVOKE cannot target an allowlisted class, COMPUTE needs one).
        fn is_shadow_class(self: @ContractState, class_hash: ClassHash) -> bool {
            self.shadow_classes.read(class_hash)
        }
    }

    /// Push deposits of ERC721 and ERC1155, and the pool's SRC5 answers.
    #[abi(embed_v0)]
    impl ReceiverImpl of IAssetReceiver<ContractState> {
        fn on_erc721_received(
            ref self: ContractState, operator: ContractAddress, from: ContractAddress, token_id: u256, data: Span<felt252>,
        ) -> felt252 {
            self.start();
            let contract = get_caller_address();
            let (inner, ciphertext) = parse_hook_data(data);
            let asset = self.register(ERC721, contract, token_id);
            // The token credits the pool before calling the hook.
            let this = get_contract_address();
            assert(IERC721Dispatcher { contract_address: contract }.owner_of(token_id) == this, 'NOT_RECEIVED');
            assert(self.held.read(asset) == 0, 'ALREADY_HELD');
            self.held.write(asset, 1);
            self.publish(self.note(asset, 1, inner), delivery_digest(ciphertext), ciphertext);
            self.emit(Deposited { asset, amount: 1 });
            self.locked.write(false);
            IERC721_RECEIVER_ID
        }

        fn on_erc1155_received(
            ref self: ContractState, operator: ContractAddress, from: ContractAddress, token_id: u256, value: u256,
            data: Span<felt252>,
        ) -> felt252 {
            self.start();
            let contract = get_caller_address();
            // Note amounts are u128.
            let amount: u128 = value.try_into().expect('AMOUNT_RANGE');
            assert(amount != 0, 'BAD_DEPOSIT');
            let (inner, ciphertext) = parse_hook_data(data);
            let asset = self.register(ERC1155, contract, token_id);
            // The token credits the pool before calling the hook, so its balance already
            // includes `value`. `≥` rather than `=`: a hook-less mint to the pool must not block
            // the id forever.
            let held = self.held.read(asset) + value;
            let this = get_contract_address();
            assert(IERC1155Dispatcher { contract_address: contract }.balance_of(this, token_id) >= held, 'NOT_RECEIVED');
            self.held.write(asset, held);
            self.publish(self.note(asset, amount, inner), delivery_digest(ciphertext), ciphertext);
            self.emit(Deposited { asset, amount });
            self.locked.write(false);
            IERC1155_RECEIVER_ID
        }

        fn on_erc1155_batch_received(
            ref self: ContractState, operator: ContractAddress, from: ContractAddress, token_ids: Span<u256>,
            values: Span<u256>, data: Span<felt252>,
        ) -> felt252 {
            core::panic_with_felt252('BATCH_DEPOSIT')
        }

        fn supports_interface(self: @ContractState, interface_id: felt252) -> bool {
            interface_id == ISRC5_ID || interface_id == IERC1155_RECEIVER_ID || interface_id == IERC721_RECEIVER_ID
        }
    }

    /// `data = inner₉ ‖ ciphertext₁₀`, with a nonzero canonical `inner`.
    fn parse_hook_data(data: Span<felt252>) -> (Digest, Span<felt252>) {
        assert(data.len() == HOOK_DATA_LEN, 'HOOK_DATA');
        let inner = read_digest(data.slice(0, 9));
        assert(!is_zero(inner), 'BAD_DEPOSIT');
        (inner, data.slice(9, 10))
    }

    /// Whether a proposal key names a verifier. Any other key is a shadow class hash: no class
    /// hash is the two-byte `'R0'` or `'P1'`.
    fn is_kind(key: felt252) -> bool {
        key == R0 || key == P1
    }

    /// Pulls `amount` of an ERC20 from `from`: the pool's balance must rise, and `from`'s fall, by
    /// exactly `amount` (F17: a token that takes a fee from either side is refused).
    fn pull_exact(token: ContractAddress, from: ContractAddress, amount: u128, error: felt252) {
        let this = get_contract_address();
        let erc = IERC20Dispatcher { contract_address: token };
        let before = erc.balance_of(this);
        let from_before = erc.balance_of(from);
        assert(erc.transfer_from(from, this, amount.into()), 'TRANSFER_FAILED');
        let after = erc.balance_of(this);
        let from_after = erc.balance_of(from);
        let a: u256 = amount.into();
        assert(after >= before && after - before == a, error);
        assert(from_before >= from_after && from_before - from_after == a, error);
    }

    #[generate_trait]
    impl InternalImpl of InternalTrait {
        /// The lock, and the bootstrap gate: nothing enters the pool before `initialize`.
        fn start(ref self: ContractState) {
            assert(self.verifiers.read(R0).into() != 0, 'NOT_INITIALIZED');
            assert(!self.locked.read(), 'REENTRANCY');
            self.locked.write(true);
        }

        fn only_owner(self: @ContractState) {
            assert(get_caller_address() == self.owner.read(), 'NOT_OWNER');
        }

        fn pending(self: @ContractState, key: felt252) -> (felt252, u64) {
            (self.pending_values.read(key), self.pending_etas.read(key))
        }

        fn clear(ref self: ContractState, key: felt252) {
            self.pending_values.write(key, 0);
            self.pending_etas.write(key, 0);
        }

        /// A note of `asset` for this chain and pool.
        fn note(self: @ContractState, asset: felt252, amount: u128, inner: Digest) -> Digest {
            commitment(get_tx_info().unbox().chain_id, get_contract_address().into(), asset, amount, inner)
        }

        /// Fixes `contract` to `standard` on first use; rejects any other standard afterwards.
        fn record_standard(ref self: ContractState, contract: ContractAddress, standard: u16) {
            let recorded = self.contract_standard.read(contract);
            if recorded == 0 {
                self.contract_standard.write(contract, standard);
            } else {
                assert(recorded == standard, 'STANDARD_MISMATCH');
            }
        }

        /// The identifier of an ERC721/ERC1155 token id, registered on its first deposit.
        fn register(ref self: ContractState, standard: u16, contract: ContractAddress, id: u256) -> felt252 {
            self.record_standard(contract, standard);
            let asset = asset_id(standard, contract, id);
            if self.assets.read(asset).standard != 0 {
                return asset;
            }
            assert(below_bound(asset), 'ASSET_RANGE');
            // No contract lives at the identifier, so it can never be taken for an ERC20.
            let at: ContractAddress = asset.try_into().unwrap();
            assert(get_class_hash_at_syscall(at).unwrap_syscall().into() == 0, 'ASSET_COLLISION');
            let interface = if standard == ERC721 { IERC721_ID } else { IERC1155_ID };
            assert(ISRC5Dispatcher { contract_address: contract }.supports_interface(interface), 'NOT_A_TOKEN');
            self.assets.write(asset, AssetInfo { standard, contract, id });
            self.emit(AssetRegistered { asset, standard, contract, id });
            asset
        }

        /// Chain, pool, expiry, binding and verdict, the exit rule, an accepted root, and two
        /// fresh nullifiers (marked spent, a dummy's included).
        fn verify_spend(ref self: ContractState, spend: @Spend, proof: Span<felt252>) {
            let this = get_contract_address();
            assert(*spend.chain == get_tx_info().unbox().chain_id, 'WRONG_CHAIN');
            assert(*spend.pool == this, 'WRONG_POOL');
            // Expiry (§8.2): lands by `valid_until`, which is on the grid and not far ahead.
            let b = get_block_number();
            let valid_until = *spend.valid_until;
            assert(valid_until != 0 && b <= valid_until, 'SPEND_EXPIRED');
            let quantum = self.quantum.read();
            assert(valid_until % quantum == 0, 'VALID_UNTIL_GRID');
            assert(valid_until <= b + self.expiry_window.read() + quantum, 'VALID_UNTIL_AHEAD');
            let w = *spend.withdrawal;
            // Withdrawal: recipient and amount together, never to the pool.
            assert((w.recipient.into() != 0) == (w.amount != 0), 'BAD_WITHDRAWAL');
            // The exit rule: the asset is public exactly when value leaves the pool.
            let exits = w.amount != 0 || *spend.intent != 0;
            assert((*spend.asset != 0) == exits, 'EXIT_RULE');
            assert(below_bound(*spend.asset), 'ASSET_RANGE');
            let binding = compute_binding(spend);
            assert(binding == *spend.binding, 'BAD_BINDING');
            let public = array![*spend.chain, this.into(), binding];
            let verifier = self.verifiers.read(R0);
            assert(IVerifierDispatcher { contract_address: verifier }.verify(proof, public.span()), 'PROOF_REJECTED');
            assert(self.tree.root_is_valid(read_digest(*spend.root)), 'UNKNOWN_ROOT');
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

        /// Both outputs as `(commitment, delivery digest, ciphertext)`, not yet appended.
        fn outputs(self: @ContractState, spend: @Spend) -> Array<(Digest, felt252, Span<felt252>)> {
            let mut pending = array![];
            for output in *spend.outputs {
                pending.append((read_digest(*output.commitment), delivery_digest(*output.ciphertext), *output.ciphertext));
            }
            pending
        }

        /// Pays `amount` of `asset` to `recipient` by the asset's standard. `held` is decremented
        /// (checked) before the external call; the contract's own view is checked after it.
        fn pay_out(ref self: ContractState, asset: felt252, recipient: ContractAddress, amount: u128) {
            let this = get_contract_address();
            assert(recipient.into() != 0 && recipient != this, 'BAD_RECIPIENT');
            let held = self.held.read(asset);
            assert(held >= amount.into(), 'HELD_UNDERFLOW');
            self.held.write(asset, held - amount.into());
            let info = self.assets.read(asset);
            if info.standard == 0 {
                let erc = IERC20Dispatcher { contract_address: asset.try_into().unwrap() };
                let before = erc.balance_of(this);
                assert(erc.transfer(recipient, amount.into()), 'TRANSFER_FAILED');
                let after = erc.balance_of(this);
                assert(before >= after && before - after == amount.into(), 'PAYOUT_AMOUNT');
            } else if info.standard == ERC1155 {
                let erc = IERC1155Dispatcher { contract_address: info.contract };
                let before = erc.balance_of(this, info.id);
                erc.safe_transfer_from(this, recipient, info.id, amount.into(), array![].span());
                assert(before - erc.balance_of(this, info.id) == amount.into(), 'PAYOUT_AMOUNT');
            } else {
                assert(info.standard == ERC721 && amount == 1, 'NFT_AMOUNT');
                let erc = IERC721Dispatcher { contract_address: info.contract };
                erc.transfer_from(this, recipient, info.id);
                assert(erc.owner_of(info.id) == recipient, 'PAYOUT_OWNER');
            }
            self.emit(Withdrawn { asset, recipient, amount });
        }

        /// Appends `notes` in order, two per `insert_two` pass; returns the first index.
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

        fn publish(ref self: ContractState, commitment: Digest, digest: felt252, ciphertext: Span<felt252>) {
            assert(digest != 0, 'ZERO_DELIVERY');
            let index = self.tree.insert_leaf(commitment);
            self.delivery_digests.write(index, digest);
            self.emit(NotePublished { index, commitment: commitment.span(), digest, ciphertext });
        }
    }
}
