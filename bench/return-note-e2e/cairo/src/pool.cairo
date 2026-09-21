//! Ordinary push notes with upstream-compatible atomic return-note funding.
#[starknet::interface]
pub trait IPool<TState> {
    fn deposit(ref self: TState, token: starknet::ContractAddress, amount: u128,
               controller: starknet::ContractAddress, policy: felt252, inner: felt252, ciphertext: Span<felt252>);
    fn apply_spend(ref self: TState, spend: pool::spend::Spend, proof: Span<felt252>);
    fn execute_returns(ref self: TState, spend: pool::spend::Spend, intent: pool::return_note::ExecutionIntent, proof: Span<felt252>);
    fn set_verifier(ref self: TState, verifier: starknet::ContractAddress);
    fn set_fee(ref self: TState, token: starknet::ContractAddress, amount: u128,
               collector: starknet::ContractAddress);
    fn get_verifier(self: @TState) -> starknet::ContractAddress;
    fn get_nullifier_spent(self: @TState, nullifier: felt252) -> bool;
    fn get_delivery_digest(self: @TState, index: u64) -> felt252;
}

#[starknet::contract]
pub mod Pool {
    use core::poseidon::poseidon_hash_span;
    use starknet::{ContractAddress, get_caller_address, get_contract_address, get_tx_info, get_block_number};
    use starknet::storage::{Map, StorageMapReadAccess, StorageMapWriteAccess,
                           StoragePointerReadAccess, StoragePointerWriteAccess};
    use pool::spend::{Spend, PROTOCOL_VERSION, compute_binding, delivery_digest,
        IERC20Dispatcher, IERC20DispatcherTrait, IVerifierDispatcher, IVerifierDispatcherTrait,
        IControllerDispatcher, IControllerDispatcherTrait};
    use pool::return_note::{ExecutionIntent, OpenNoteDeposit, hash_intent, return_digest, IBalanceDispatcher, IBalanceDispatcherTrait};
    use starknet::{SyscallResultTrait};
    use starknet::syscalls::call_contract_syscall;
    use pool::tree::tree_component;
    use pool::tree::tree_component::TreeInternalTrait;
    component!(path: tree_component, storage: tree, event: TreeEvent);

    #[storage]
    pub struct Storage {
        owner: ContractAddress,
        verifier: ContractAddress,
        nullifiers: Map<felt252, bool>,
        delivery_digests: Map<u64, felt252>,
        fee_token: ContractAddress,
        fee_amount: u128,
        fee_collector: ContractAddress,
        locked: bool,
        #[substorage(v0)]
        pub tree: tree_component::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        TreeEvent: tree_component::Event,
        NotePublished: NotePublished,
        NullifierSpent: NullifierSpent,
        Deposited: Deposited,
        Withdrawn: Withdrawn,
    }
    #[derive(Drop, starknet::Event)]
    pub struct NotePublished {
        pub index: u64,
        pub commitment: felt252,
        pub digest: felt252,
        pub settled_amount: u128,
        pub ciphertext: Span<felt252>,
    }
    #[derive(Drop, starknet::Event)]
    pub struct NullifierSpent { pub nullifier: felt252 }
    #[derive(Drop, starknet::Event)]
    pub struct Deposited { pub token: ContractAddress, pub amount: u128 }
    #[derive(Drop, starknet::Event)]
    pub struct Withdrawn { pub token: ContractAddress, pub recipient: ContractAddress, pub amount: u128 }

    #[constructor]
    fn constructor(ref self: ContractState, owner: ContractAddress, verifier: ContractAddress) {
        assert(owner.into() != 0, 'ZERO_OWNER');
        self.owner.write(owner);
        self.verifier.write(verifier);
        self.tree._init_zeros();
    }
    #[abi(embed_v0)]
    impl PoolTreeImpl = tree_component::Tree<ContractState>;

    #[abi(embed_v0)]
    impl PoolImpl of super::IPool<ContractState> {
        fn deposit(ref self: ContractState, token: ContractAddress, amount: u128,
                   controller: ContractAddress, policy: felt252, inner: felt252, ciphertext: Span<felt252>) {
            self.start();
            assert(token.into() != 0 && amount != 0 && inner != 0, 'BAD_DEPOSIT');
            assert(controller.into() == 0 && policy == 0, 'ORDINARY_ONLY');
            let digest = delivery_digest(ciphertext);
            let commitment = poseidon_hash_span(array!['RTN_NOTE_V1', get_tx_info().unbox().chain_id,
                get_contract_address().into(), token.into(), amount.into(), controller.into(), policy, inner].span());
            assert(IERC20Dispatcher { contract_address: token }.transfer_from(
                get_caller_address(),get_contract_address(),amount.into()), 'TRANSFER_FAILED');
            self.publish(commitment,digest,0,ciphertext);
            self.emit(Deposited { token, amount });
            self.locked.write(false);
        }

        fn apply_spend(ref self: ContractState, spend: Spend, proof: Span<felt252>) {
            self.start();
            assert(spend.intent == 0, 'EXECUTION_REQUIRED');
            self.settle_spend(spend,proof);
            self.locked.write(false);
        }
        fn execute_returns(ref self: ContractState, spend: Spend, intent: ExecutionIntent, proof: Span<felt252>) {
            self.start();
            assert(spend.controller.into() == 0, 'ORDINARY_ONLY');
            assert(spend.intent != 0 && spend.intent == hash_intent(@spend,@intent), 'EXECUTION_INTENT');
            assert(get_block_number() <= intent.expiry, 'EXECUTION_EXPIRED');
            assert(intent.adapter.into() != 0 && intent.adapter != get_contract_address()
                && intent.amount != 0, 'EXECUTION_ARGS');
            assert(spend.outputs.len() + intent.notes.len() <= 4, 'TOTAL_OUTPUT_COUNT');
            assert(spend.withdrawals.len() == 1, 'EXECUTION_WITHDRAW_COUNT');
            let leg = spend.withdrawals.at(0);
            assert(*leg.recipient == intent.adapter && *leg.amount == intent.amount, 'EXECUTION_BUDGET');
            for i in 0..intent.notes.len() {
                let note = intent.notes.at(i);
                assert(*note.note_id != 0 && (*note.token).into() != 0
                    && *note.minimum != 0 && *note.inner != 0, 'RETURN_ARGS');
                for j in 0..i {
                    assert(*intent.notes.at(j).note_id != *note.note_id, 'DUPLICATE_RETURN_ID');
                };
            };
            // The proof binds the entire external call and every required return.
            // Input funding, invocation, output pulls and publication are one transaction.
            self.settle_spend(spend,proof);
            let mut result = call_contract_syscall(intent.adapter,selector!("privacy_invoke"),intent.calldata).unwrap_syscall();
            // Bound length BEFORE deserializing: exact upstream span ABI, no extensions.
            assert(result.len() == 1 + 3 * intent.notes.len(), 'RETURN_ENCODING');
            assert(*result.at(0) == intent.notes.len().into(), 'RETURN_COUNT');
            let deposits: Span<OpenNoteDeposit> = Serde::deserialize(ref result).expect('RETURN_ENCODING');
            assert(result.is_empty(), 'RETURN_TRAILING');
            for i in 0..intent.notes.len() {
                let note = intent.notes.at(i); let deposit = deposits.at(i);
                assert(*deposit.note_id == *note.note_id, 'RETURN_ID');
                assert(*deposit.token == *note.token, 'RETURN_TOKEN');
                assert(*deposit.amount >= *note.minimum, 'RETURN_MINIMUM');
                let token = *note.token; let amount = *deposit.amount;
                // Per-pull checks work for refunds and repeated output tokens too.
                let output = IBalanceDispatcher { contract_address: token };
                let before = output.balance_of(get_contract_address());
                assert(IERC20Dispatcher { contract_address: token }.transfer_from(
                    intent.adapter,get_contract_address(),amount.into()), 'RETURN_TRANSFER');
                assert(output.balance_of(get_contract_address()) == before + amount.into(), 'RETURN_FUNDING');
                let commitment = poseidon_hash_span(array!['RTN_NOTE_V1',get_tx_info().unbox().chain_id,
                    get_contract_address().into(),token.into(),amount.into(),0,0,*note.inner].span());
                self.publish(commitment,return_digest(*note.ciphertext,amount),amount,*note.ciphertext);
            };
            self.locked.write(false);
        }
        fn set_verifier(ref self: ContractState, verifier: ContractAddress) {
            self.assert_owner();
            assert(verifier.into() != 0, 'ZERO_VERIFIER');
            self.verifier.write(verifier);
        }
        fn set_fee(ref self: ContractState, token: ContractAddress, amount: u128, collector: ContractAddress) {
            self.assert_owner();
            assert(amount == 0 || (token.into() != 0 && collector.into() != 0), 'BAD_FEE');
            self.fee_token.write(token); self.fee_amount.write(amount); self.fee_collector.write(collector);
        }
        fn get_verifier(self: @ContractState) -> ContractAddress { self.verifier.read() }
        fn get_nullifier_spent(self: @ContractState, nullifier: felt252) -> bool { self.nullifiers.read(nullifier) }
        fn get_delivery_digest(self: @ContractState, index: u64) -> felt252 {
            assert(index < self.tree.get_leaf_count(), 'UNKNOWN_INDEX');
            self.delivery_digests.read(index)
        }
    }
    #[generate_trait]
    impl InternalImpl of InternalTrait {
        fn settle_spend(ref self: ContractState, spend: Spend, proof: Span<felt252>) {
            assert(spend.controller.into() == 0, 'ORDINARY_ONLY');
            assert(spend.version == PROTOCOL_VERSION, 'WRONG_VERSION');
            assert(spend.chain == get_tx_info().unbox().chain_id, 'WRONG_CHAIN');
            assert(spend.pool == get_contract_address(), 'WRONG_POOL');
            assert(spend.token.into() != 0, 'ZERO_TOKEN');
            assert(compute_binding(@spend) == spend.binding, 'BAD_BINDING');
            let public = array![spend.version,spend.chain,spend.pool.into(),spend.root,spend.controller.into(),spend.deadline.into(),spend.transition,spend.binding];
            assert(IVerifierDispatcher { contract_address: self.verifier.read() }
                .verify(proof,public.span()), 'PROOF_REJECTED');
            assert(self.tree.root_is_known(spend.root), 'UNKNOWN_ROOT');
            if spend.controller.into() == 0 {
                assert(spend.deadline == 0 && spend.nonce == 0 && spend.transition == 0
                    && spend.sig_r == 0 && spend.sig_s == 0, 'ORDINARY_AUTH');
            } else {
                assert(spend.deadline != 0 && spend.nonce != 0 && spend.transition != 0, 'CONTROL_AUTH');
                assert(get_block_number() <= spend.deadline, 'CONTROL_EXPIRED');
                assert(IControllerDispatcher { contract_address: spend.controller }.verify_transition(
                    spend.transition,spend.sig_r,spend.sig_s), 'CONTROL_SIGNATURE');
            };
            let fee = self.fee_amount.read();
            if fee != 0 {
                assert(IERC20Dispatcher { contract_address: self.fee_token.read() }.transfer_from(
                    get_caller_address(),self.fee_collector.read(),fee.into()), 'FEE_FAILED');
            };
            for nf in spend.nullifiers {
                assert(*nf != 0, 'ZERO_NULLIFIER');
                assert(!self.nullifiers.read(*nf), 'NULLIFIER_USED');
                self.nullifiers.write(*nf,true);
                self.emit(NullifierSpent { nullifier: *nf });
            };
            for output in spend.outputs {
                self.publish(*output.commitment,delivery_digest(*output.ciphertext),0,*output.ciphertext);
            };
            for withdrawal in spend.withdrawals {
                assert((*withdrawal.recipient).into() != 0 && *withdrawal.amount != 0, 'BAD_WITHDRAWAL');
                assert(IERC20Dispatcher { contract_address: spend.token }.transfer(
                    *withdrawal.recipient,(*withdrawal.amount).into()), 'TRANSFER_FAILED');
                self.emit(Withdrawn { token: spend.token,recipient: *withdrawal.recipient,amount: *withdrawal.amount });
            };
        }

        fn assert_owner(self: @ContractState) { assert(get_caller_address() == self.owner.read(), 'NOT_OWNER'); }
        fn start(ref self: ContractState) {
            assert(!self.locked.read(), 'REENTRANCY'); self.locked.write(true);
        }
        fn publish(ref self: ContractState, commitment: felt252, digest: felt252, settled_amount: u128, ciphertext: Span<felt252>) {
            assert(digest != 0, 'ZERO_DELIVERY');
            let index = self.tree.insert_leaf(commitment);
            self.delivery_digests.write(index,digest);
            self.emit(NotePublished { index,commitment,digest,settled_amount,ciphertext });
        }
    }
}
