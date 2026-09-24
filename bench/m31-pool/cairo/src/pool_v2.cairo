//! M31 pool V2 (`docs/hidden-asset-spec.md` §5): a fresh deployment whose spends are R0 V4.
//!
//! - **Assets.** A note's token field holds an asset identifier (`assets`): an ERC20 address, or
//!   a hashed ERC721/ERC1155 token id registered on its first deposit. Each contract is fixed to
//!   one standard on its first deposit through any path (`contract_standard`), so one contract
//!   cannot back notes under two standards.
//! - **Deposits.** ERC20 by `deposit` (pull, exact balance delta). ERC721 and ERC1155 are pushed:
//!   the user safe-transfers to the pool with `data = inner₉ ‖ ciphertext₁₀`, and the pool's
//!   receiver hook appends the note. No approval to the pool is needed.
//! - **Holdings.** `held[a]` equals the sum of unspent notes of `a`; it is checked against the
//!   contract's own view at every deposit and payout.
//! - **Spends.** `apply_spend` and `apply_spend_with_invoke` take R0 V4 statements: two nullifiers
//!   and two outputs always; the asset is public only on exit (the exit rule).
//! - **Payout.** `pay_out` is the single path for withdrawals, open-note budgets and policy
//!   settlements; it never pays the pool and decrements `held` before the external call.
//! - **Policy notes.** `apply_policy_spend` settles P1 as the V3 pool does, paying through
//!   `pay_out`.
use starknet::ContractAddress;

#[starknet::interface]
pub trait IM31PoolV2<TState> {
    fn deposit(ref self: TState, token: ContractAddress, amount: u128, inner: Span<felt252>, ciphertext: Span<felt252>);
    fn apply_spend(ref self: TState, spend: crate::spend4::Spend, proof: Span<felt252>);
    fn apply_spend_with_invoke(
        ref self: TState, spend: crate::spend4::Spend, intent: crate::open_note::ExecutionIntent, proof: Span<felt252>,
    );
    fn apply_policy_spend(
        ref self: TState, spend: crate::policy::PolicySpend, data: Span<felt252>, ciphertexts: Span<Span<felt252>>,
        proof: Span<felt252>,
    );
    fn get_nullifier_spent(self: @TState, nullifier: Span<felt252>) -> bool;
    fn get_delivery_digest(self: @TState, index: u64) -> felt252;
    fn get_asset(self: @TState, asset: felt252) -> crate::assets::AssetInfo;
    fn asset_id(self: @TState, standard: u16, contract: ContractAddress, id: u256) -> felt252;
    fn get_contract_standard(self: @TState, contract: ContractAddress) -> u16;
    fn get_held(self: @TState, asset: felt252) -> u256;
    fn set_verifier(ref self: TState, verifier: ContractAddress);
    fn get_verifier(self: @TState) -> ContractAddress;
    fn set_policy_verifier(ref self: TState, verifier: ContractAddress);
    fn get_policy_verifier(self: @TState) -> ContractAddress;
    fn set_shadow_class(ref self: TState, class_hash: starknet::ClassHash, allowed: bool);
    fn is_shadow_class(self: @TState, class_hash: starknet::ClassHash) -> bool;
}

#[starknet::contract]
pub mod M31PoolV2 {
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess, StoragePointerWriteAccess,
    };
    use starknet::syscalls::{call_contract_syscall, get_class_hash_at_syscall};
    use starknet::{
        ClassHash, ContractAddress, SyscallResultTrait, get_block_number, get_caller_address, get_contract_address,
        get_tx_info,
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
    use crate::spend4::{Spend, compute_binding};
    use crate::tree::m31_tree_component;
    use crate::tree::m31_tree_component::M31TreeInternalTrait;
    component!(path: m31_tree_component, storage: tree, event: TreeEvent);

    /// Hook `data`: nine `inner` words, then the ten-word ciphertext.
    const HOOK_DATA_LEN: u32 = 19;

    #[storage]
    pub struct Storage {
        owner: ContractAddress,
        verifier: ContractAddress,
        policy_verifier: ContractAddress,
        nullifiers: Map<felt252, bool>,
        delivery_digests: Map<u64, felt252>,
        shadow_classes: Map<ClassHash, bool>,
        locked: bool,
        assets: Map<felt252, AssetInfo>,
        contract_standard: Map<ContractAddress, u16>,
        held: Map<felt252, u256>,
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
        Withdrawn: Withdrawn,
        AssetRegistered: AssetRegistered,
        ShadowClassSet: ShadowClassSet,
        OpenNoteFunded: OpenNoteFunded,
        PolicySettled: PolicySettled,
        PolicyVerifierSet: PolicyVerifierSet,
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
    #[derive(Drop, starknet::Event)]
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
    #[derive(Drop, starknet::Event)]
    pub struct PolicyVerifierSet {
        pub verifier: ContractAddress,
    }

    #[constructor]
    fn constructor(ref self: ContractState, owner: ContractAddress, verifier: ContractAddress, format: u8, store_nodes: bool) {
        assert(owner.into() != 0, 'ZERO_OWNER');
        assert(verifier.into() != 0, 'ZERO_VERIFIER');
        self.owner.write(owner);
        self.verifier.write(verifier);
        self.tree.initializer(format, store_nodes);
    }

    #[abi(embed_v0)]
    impl TreeImpl = m31_tree_component::M31Tree<ContractState>;

    #[abi(embed_v0)]
    impl PoolImpl of super::IM31PoolV2<ContractState> {
        /// ERC20 deposit: pulls `amount` and credits exactly the balance delta.
        fn deposit(ref self: ContractState, token: ContractAddress, amount: u128, inner: Span<felt252>, ciphertext: Span<felt252>) {
            self.start();
            let inner = read_digest(inner);
            assert(token.into() != 0 && amount != 0 && !is_zero(inner), 'BAD_DEPOSIT');
            let asset: felt252 = token.into();
            // An identifier registered as an NFT asset is never an ERC20 address.
            assert(self.assets.read(asset).standard == 0, 'ASSET_REGISTERED');
            self.record_standard(token, ERC20);
            let digest = delivery_digest(ciphertext);
            let this = get_contract_address();
            let erc = IERC20Dispatcher { contract_address: token };
            let before = erc.balance_of(this);
            assert(erc.transfer_from(get_caller_address(), this, amount.into()), 'TRANSFER_FAILED');
            assert(erc.balance_of(this) - before == amount.into(), 'DEPOSIT_AMOUNT');
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
            if intent.kind == COMPUTE {
                assert(is_active(spend.identity), 'IDENTITY_REQUIRED');
                let class = get_class_hash_at_syscall(intent.adapter).unwrap_syscall();
                assert(self.shadow_classes.read(class), 'COMPUTE_TARGET');
            } else {
                assert(intent.kind == INVOKE && !is_active(spend.identity), 'IDENTITY_UNEXPECTED');
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
                let erc = IERC20Dispatcher { contract_address: dest.token };
                let before = erc.balance_of(this);
                assert(erc.transfer_from(intent.adapter, this, d.amount.into()), 'TRANSFER_FAILED');
                assert(erc.balance_of(this) - before == d.amount.into(), 'OPEN_NOTE_FUNDING');
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

        /// Settles a policy note from a P1 statement, as the V3 pool (`pool.cairo`), paying any
        /// withdrawal through `pay_out`.
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
            let verifier = self.policy_verifier.read();
            assert(verifier.into() != 0, 'NO_POLICY_VERIFIER');
            assert(IVerifierDispatcher { contract_address: verifier }.verify(proof, public.span()), 'PROOF_REJECTED');
            assert(self.tree.root_history.read(key(read_digest(spend.root))), 'UNKNOWN_ROOT');
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

        fn asset_id(self: @ContractState, standard: u16, contract: ContractAddress, id: u256) -> felt252 {
            asset_id(standard, contract, id)
        }

        fn get_contract_standard(self: @ContractState, contract: ContractAddress) -> u16 {
            self.contract_standard.read(contract)
        }

        fn get_held(self: @ContractState, asset: felt252) -> u256 {
            self.held.read(asset)
        }

        fn set_verifier(ref self: ContractState, verifier: ContractAddress) {
            assert(get_caller_address() == self.owner.read(), 'NOT_OWNER');
            assert(verifier.into() != 0, 'ZERO_VERIFIER');
            self.verifier.write(verifier);
        }

        fn get_verifier(self: @ContractState) -> ContractAddress {
            self.verifier.read()
        }

        fn set_policy_verifier(ref self: ContractState, verifier: ContractAddress) {
            assert(get_caller_address() == self.owner.read(), 'NOT_OWNER');
            assert(verifier.into() != 0, 'ZERO_VERIFIER');
            self.policy_verifier.write(verifier);
            self.emit(PolicyVerifierSet { verifier });
        }

        fn get_policy_verifier(self: @ContractState) -> ContractAddress {
            self.policy_verifier.read()
        }

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
            panic!("BATCH_DEPOSIT")
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

    #[generate_trait]
    impl InternalImpl of InternalTrait {
        fn start(ref self: ContractState) {
            assert(!self.locked.read(), 'REENTRANCY');
            self.locked.write(true);
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

        /// Chain, pool, binding and verdict, the exit rule, a known root, and two fresh
        /// nullifiers (marked spent, a dummy's included).
        fn verify_spend(ref self: ContractState, spend: @Spend, proof: Span<felt252>) {
            let this = get_contract_address();
            assert(*spend.chain == get_tx_info().unbox().chain_id, 'WRONG_CHAIN');
            assert(*spend.pool == this, 'WRONG_POOL');
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
                let token: ContractAddress = asset.try_into().unwrap();
                assert(IERC20Dispatcher { contract_address: token }.transfer(recipient, amount.into()), 'TRANSFER_FAILED');
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
