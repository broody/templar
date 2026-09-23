//! Option A pool for R0: the reference ordinary pool's `deposit` and `apply_spend`
//! (`controlled-push-e2e/cairo/src/pool.cairo`) over the M31 note tree. Deposits compute the
//! commitment on chain from `inner`; spends check the binding, fact verdict, known root and
//! unused nullifiers, then publish both outputs.
use starknet::ContractAddress;

#[starknet::interface]
pub trait IM31Pool<TState> {
    fn deposit(ref self: TState, token: ContractAddress, amount: u128, inner: Span<felt252>, ciphertext: Span<felt252>);
    fn apply_spend(ref self: TState, spend: crate::spend::Spend, proof: Span<felt252>);
    fn get_nullifier_spent(self: @TState, nullifier: Span<felt252>) -> bool;
    fn get_delivery_digest(self: @TState, index: u64) -> felt252;
}

#[starknet::contract]
pub mod M31Pool {
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };
    use starknet::{ContractAddress, get_caller_address, get_contract_address, get_tx_info};
    use crate::hash::{Digest, commitment, is_zero, key, read_digest};
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
        Withdrawn: Withdrawn,
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
            assert(spend.chain == get_tx_info().unbox().chain_id, 'WRONG_CHAIN');
            assert(spend.pool == get_contract_address(), 'WRONG_POOL');
            assert(spend.token.into() != 0, 'ZERO_TOKEN');
            let binding = compute_binding(@spend);
            assert(binding == spend.binding, 'BAD_BINDING');
            let public = array![spend.chain, spend.pool.into(), binding];
            assert(IVerifierDispatcher { contract_address: self.verifier.read() }.verify(proof, public.span()), 'PROOF_REJECTED');
            assert(self.tree.root_history.read(key(read_digest(spend.root))), 'UNKNOWN_ROOT');
            let mut nullifiers = spend.nullifiers;
            while let Some(words) = nullifiers.multi_pop_front::<9>() {
                let nf = read_digest(words.unbox().span());
                assert(!is_zero(nf), 'ZERO_NULLIFIER');
                let k = key(nf);
                assert(!self.nullifiers.read(k), 'NULLIFIER_USED');
                self.nullifiers.write(k, true);
                self.emit(NullifierSpent { nullifier: nf.span() });
            }
            // Inactive slots (zero commitment) create no note. Two new notes are appended in one
            // pass (`insert_two`), sharing the upper path.
            let o0 = spend.outputs.at(0);
            let o1 = spend.outputs.at(1);
            let (a0, a1) = (is_active(*o0.commitment), is_active(*o1.commitment));
            let mut created = 0_u32;
            if a0 && a1 {
                let (d0, d1) = (delivery_digest(*o0.ciphertext), delivery_digest(*o1.ciphertext));
                assert(d0 != 0 && d1 != 0, 'ZERO_DELIVERY');
                let (cm0, cm1) = (read_digest(*o0.commitment), read_digest(*o1.commitment));
                let index = self.tree.insert_two(cm0, cm1);
                self.delivery_digests.write(index, d0);
                self.delivery_digests.write(index + 1, d1);
                self.emit(NotePublished { index, commitment: cm0.span(), digest: d0, ciphertext: *o0.ciphertext });
                self.emit(NotePublished { index: index + 1, commitment: cm1.span(), digest: d1, ciphertext: *o1.ciphertext });
                created = 2;
            } else {
                for output in spend.outputs {
                    if is_active(*output.commitment) {
                        self.publish(read_digest(*output.commitment), delivery_digest(*output.ciphertext), *output.ciphertext);
                        created += 1;
                    }
                }
            }
            let w = spend.withdrawal;
            if w.amount != 0 {
                assert(w.recipient.into() != 0, 'BAD_WITHDRAWAL');
                assert(
                    IERC20Dispatcher { contract_address: spend.token }.transfer(w.recipient, w.amount.into()),
                    'TRANSFER_FAILED',
                );
                self.emit(Withdrawn { token: spend.token, recipient: w.recipient, amount: w.amount });
            } else {
                assert(w.recipient.into() == 0, 'BAD_WITHDRAWAL');
                assert(created > 0, 'EMPTY_OUTPUT');
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
    }

    #[generate_trait]
    impl InternalImpl of InternalTrait {
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
