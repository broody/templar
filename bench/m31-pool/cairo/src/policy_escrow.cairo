//! Reference escrow controller for policy notes (`docs/policy-note-spec.md` §10). Immutable, no
//! admin. The note's `handle` is the arbiter's address; cases are keyed by `(arbiter,
//! policy_id)`, so a note naming the same arbiter under another policy, token, pool or amount has
//! a different key the arbiter never approved.
//!
//! - `approve(policy_id, outcome)`, by the arbiter, once per `policy_id`: the only outcome (`1`
//!   release, `0` cancel) that may settle, stored as `outcome + 1` so that an unset entry never
//!   matches outcome `0`.
//! - `templar_apply_policy`, by the pool only: the approved outcome of a fixed policy, not yet
//!   consumed; marks it consumed.
//!
//! The deadline refund needs nothing from this contract.
use starknet::ContractAddress;

#[starknet::interface]
pub trait IPolicyEscrow<T> {
    fn approve(ref self: T, policy_id: felt252, outcome: u8);
    /// The approved outcome plus one, or zero when none.
    fn approval(self: @T, arbiter: ContractAddress, policy_id: felt252) -> u8;
    fn consumed(self: @T, arbiter: ContractAddress, policy_id: felt252) -> bool;
    fn pool(self: @T) -> ContractAddress;
}

#[starknet::contract]
pub mod PolicyEscrow {
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess, StoragePointerWriteAccess,
    };
    use starknet::{ContractAddress, get_caller_address, get_tx_info};
    use crate::policy::{
        AUTH_CHAIN, AUTH_HANDLE, AUTH_INDEX, AUTH_KIND, AUTH_LEN, AUTH_POLICY_ID, AUTH_POOL, AUTH_TAG, FIXED,
        ITemplarPolicyController, POLICY_OK,
    };

    #[storage]
    struct Storage {
        pool: ContractAddress,
        approvals: Map<(ContractAddress, felt252), u8>,
        consumed: Map<(ContractAddress, felt252), bool>,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        Approved: Approved,
        Settled: Settled,
    }
    #[derive(Drop, starknet::Event)]
    pub struct Approved {
        pub arbiter: ContractAddress,
        pub policy_id: felt252,
        pub outcome: u8,
    }
    #[derive(Drop, starknet::Event)]
    pub struct Settled {
        pub arbiter: ContractAddress,
        pub policy_id: felt252,
        pub outcome: u8,
    }

    #[constructor]
    fn constructor(ref self: ContractState, pool: ContractAddress) {
        assert(pool.into() != 0, 'ZERO_POOL');
        self.pool.write(pool);
    }

    #[abi(embed_v0)]
    impl EscrowImpl of super::IPolicyEscrow<ContractState> {
        fn approve(ref self: ContractState, policy_id: felt252, outcome: u8) {
            assert(outcome <= 1, 'ESCROW_OUTCOME');
            assert(policy_id != 0, 'ESCROW_POLICY');
            let arbiter = get_caller_address();
            assert(self.approvals.read((arbiter, policy_id)) == 0, 'ESCROW_DECIDED');
            self.approvals.write((arbiter, policy_id), outcome + 1);
            self.emit(Approved { arbiter, policy_id, outcome });
        }

        fn approval(self: @ContractState, arbiter: ContractAddress, policy_id: felt252) -> u8 {
            self.approvals.read((arbiter, policy_id))
        }

        fn consumed(self: @ContractState, arbiter: ContractAddress, policy_id: felt252) -> bool {
            self.consumed.read((arbiter, policy_id))
        }

        fn pool(self: @ContractState) -> ContractAddress {
            self.pool.read()
        }
    }

    #[abi(embed_v0)]
    impl ControllerImpl of ITemplarPolicyController<ContractState> {
        fn templar_apply_policy(ref self: ContractState, authorization: Span<felt252>, data: Span<felt252>) -> felt252 {
            let pool = self.pool.read();
            assert(get_caller_address() == pool, 'ESCROW_CALLER');
            assert(authorization.len() == AUTH_LEN, 'ESCROW_AUTH');
            assert(*authorization.at(AUTH_TAG) == 'TEMPLAR_POLICY_V1', 'ESCROW_AUTH');
            assert(*authorization.at(AUTH_CHAIN) == get_tx_info().unbox().chain_id, 'ESCROW_CHAIN');
            assert(*authorization.at(AUTH_POOL) == pool.into(), 'ESCROW_POOL');
            // The token is bound by the policy id; the escrow has no use for `data`.
            let kind: u8 = (*authorization.at(AUTH_KIND)).try_into().unwrap();
            assert(kind == FIXED, 'ESCROW_KIND');
            let arbiter: ContractAddress = (*authorization.at(AUTH_HANDLE)).try_into().expect('ESCROW_ARBITER');
            let policy_id = *authorization.at(AUTH_POLICY_ID);
            let outcome: u8 = (*authorization.at(AUTH_INDEX)).try_into().unwrap();
            let approved = self.approvals.read((arbiter, policy_id));
            assert(approved != 0 && approved == outcome + 1, 'ESCROW_NOT_APPROVED');
            assert(!self.consumed.read((arbiter, policy_id)), 'ESCROW_CONSUMED');
            self.consumed.write((arbiter, policy_id), true);
            self.emit(Settled { arbiter, policy_id, outcome });
            let _ = data;
            POLICY_OK
        }
    }
}
