//! Test-only policy controllers from the implementation review (`reviews/policy-note-impl-contract-review.md`):
//! hostile or odd controllers the pool must withstand.

/// Returns `['TEMPLAR_POLICY_OK', 0]`: correct first word, extra return data.
#[starknet::contract]
pub mod LongReturnController {
    #[storage]
    struct Storage {}

    #[external(v0)]
    fn templar_apply_policy(ref self: ContractState, authorization: Span<felt252>, data: Span<felt252>) -> (felt252, felt252) {
        let _ = (authorization, data);
        (crate::policy::POLICY_OK, 0)
    }
}

/// Exposes only PR #2's selector: the pool must not reach it.
#[starknet::contract]
pub mod UpstreamOnlyController {
    #[storage]
    struct Storage {}

    #[external(v0)]
    fn privacy_apply_controlled_transition(ref self: ContractState, authorization: Span<felt252>, data: Span<felt252>) -> felt252 {
        let _ = (authorization, data);
        crate::policy::POLICY_OK
    }
}

/// Mode 1: re-enter `apply_policy_spend`; 2: re-enter `apply_spend`; 3: call the owner setter;
/// 4: forge a call to another controller (the escrow) with the received authorization; 5: emit a
/// fake settlement event and approve.
#[starknet::contract]
pub mod HostileController {
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};
    use starknet::{ContractAddress, get_caller_address};
    use crate::policy::{ITemplarPolicyControllerDispatcher, ITemplarPolicyControllerDispatcherTrait, PolicySpend};
    use crate::pool::{IM31PoolDispatcher, IM31PoolDispatcherTrait};
    use crate::spend::{Spend, Withdrawal};

    #[storage]
    struct Storage {
        mode: u8,
        other: ContractAddress,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        PolicySettled: PolicySettled,
    }
    #[derive(Drop, starknet::Event)]
    pub struct PolicySettled {
        pub nullifier: felt252,
    }

    #[constructor]
    fn constructor(ref self: ContractState, mode: u8, other: ContractAddress) {
        self.mode.write(mode);
        self.other.write(other);
    }

    #[external(v0)]
    fn templar_apply_policy(ref self: ContractState, authorization: Span<felt252>, data: Span<felt252>) -> felt252 {
        let mode = self.mode.read();
        let pool = IM31PoolDispatcher { contract_address: get_caller_address() };
        let zero: ContractAddress = 0.try_into().unwrap();
        let e = array![].span();
        if mode == 1 {
            let sp = PolicySpend {
                chain: 0, pool: zero, token: zero, root: e, nullifier: e, commitments: e, delivery0: 0, delivery1: 0,
                withdrawal: Withdrawal { recipient: zero, amount: 0 }, controller: zero, controller_class: 0, handle: 0,
                policy_id: e, deadline: 0, not_before: 0, index: 0, kind: 0, x: 0, data: 0, binding: 0,
            };
            pool.apply_policy_spend(sp, e, array![].span(), e);
        } else if mode == 2 {
            let sp = Spend {
                chain: 0, pool: zero, token: zero, root: e, nullifiers: e, outputs: array![].span(),
                withdrawal: Withdrawal { recipient: zero, amount: 0 }, intent: 0, identity: e, binding: 0,
            };
            pool.apply_spend(sp, e);
        } else if mode == 3 {
            pool.set_policy_verifier(0x1234.try_into().unwrap());
        } else if mode == 4 {
            let r = ITemplarPolicyControllerDispatcher { contract_address: self.other.read() }.templar_apply_policy(authorization, data);
            assert(r == crate::policy::POLICY_OK, 'X');
        } else if mode == 5 {
            self.emit(PolicySettled { nullifier: 42 });
        }
        crate::policy::POLICY_OK
    }
}

/// Approves, and can replace its own class (an upgradeable controller).
#[starknet::contract]
pub mod UpgradableController {
    use starknet::ClassHash;
    use starknet::syscalls::replace_class_syscall;
    use starknet::SyscallResultTrait;

    #[storage]
    struct Storage {}

    #[external(v0)]
    fn upgrade(ref self: ContractState, class_hash: ClassHash) {
        replace_class_syscall(class_hash).unwrap_syscall();
    }

    #[external(v0)]
    fn templar_apply_policy(ref self: ContractState, authorization: Span<felt252>, data: Span<felt252>) -> felt252 {
        let _ = (authorization, data);
        crate::policy::POLICY_OK
    }
}
