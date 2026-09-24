//! Test adapters for open-note executions, in upstream's shapes: `privacy_invoke` returning
//! `Span<OpenNoteDeposit>` (as the Ekubo and Vesu anonymizers), and
//! `privacy_invoke_with_computation` returning the deposits and the shadow account's address (as
//! the shadow-account anonymizer). Each approves its caller for the proceeds it reports; the
//! proceeds must already be in the adapter (a test mints them).
use starknet::ContractAddress;

#[derive(Copy, Drop, Serde)]
pub struct Proceeds {
    pub note_id: felt252,
    pub token: ContractAddress,
    pub amount: u128,
}

#[starknet::interface]
pub trait IMockSwapAdapter<T> {
    fn privacy_invoke(
        ref self: T, in_token: ContractAddress, in_amount: u128, proceeds: Span<Proceeds>,
    ) -> Span<crate::open_note::OpenNoteDeposit>;
}

#[starknet::interface]
pub trait IMockShadowAnonymizer<T> {
    fn privacy_invoke_with_computation(
        ref self: T, identity_commitment: felt252, proceeds: Span<Proceeds>,
    ) -> (Span<crate::open_note::OpenNoteDeposit>, Span<ContractAddress>);
    fn last_identity_commitment(self: @T) -> felt252;
}

fn pay_out(proceeds: Span<Proceeds>) -> Span<crate::open_note::OpenNoteDeposit> {
    let caller = starknet::get_caller_address();
    let mut deposits = array![];
    for p in proceeds {
        let token = crate::spend::IERC20Dispatcher { contract_address: *p.token };
        crate::spend::IERC20DispatcherTrait::approve(token, caller, (*p.amount).into());
        deposits.append(crate::open_note::OpenNoteDeposit { note_id: *p.note_id, token: *p.token, amount: *p.amount });
    }
    deposits.span()
}

#[starknet::contract]
pub mod MockSwapAdapter {
    use starknet::{ContractAddress, get_contract_address};
    use crate::spend::{IERC20Dispatcher, IERC20DispatcherTrait};
    use super::Proceeds;

    #[storage]
    struct Storage {}

    #[abi(embed_v0)]
    impl Impl of super::IMockSwapAdapter<ContractState> {
        fn privacy_invoke(
            ref self: ContractState, in_token: ContractAddress, in_amount: u128, proceeds: Span<Proceeds>,
        ) -> Span<crate::open_note::OpenNoteDeposit> {
            // The pool paid the budget before the call.
            let held = IERC20Dispatcher { contract_address: in_token }.balance_of(get_contract_address());
            assert(held >= in_amount.into(), 'BUDGET_NOT_RECEIVED');
            super::pay_out(proceeds)
        }
    }
}

#[starknet::contract]
pub mod MockShadowAnonymizer {
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};
    use starknet::{ContractAddress, get_contract_address};
    use super::Proceeds;

    #[storage]
    struct Storage {
        last: felt252,
    }

    #[abi(embed_v0)]
    impl Impl of super::IMockShadowAnonymizer<ContractState> {
        fn privacy_invoke_with_computation(
            ref self: ContractState, identity_commitment: felt252, proceeds: Span<Proceeds>,
        ) -> (Span<crate::open_note::OpenNoteDeposit>, Span<ContractAddress>) {
            self.last.write(identity_commitment);
            (super::pay_out(proceeds), array![get_contract_address()].span())
        }

        fn last_identity_commitment(self: @ContractState) -> felt252 {
            self.last.read()
        }
    }
}

// ---------------------------------------------------------------- adversarial adapters
// From the open-note contract review (bench/m31-pool/reviews/open-note-contract-review.md).
// `EvilAdapter.privacy_invoke(pool, token, amount, note_id, mode)`: mode 0 honest, 1 re-enters the
// pool, 3 approves one unit less, 5 tries to pull from the pool, 6 returns no deposit, 7 reports a
// different note id. `ExtraAdapter` appends a word after the deposits. `FeeToken` delivers one unit
// less on `transfer_from`.
use crate::open_note::OpenNoteDeposit;

#[starknet::interface]
pub trait IEvil<T> {
    fn privacy_invoke(ref self: T, pool: ContractAddress, token: ContractAddress, amount: u128, note_id: felt252, mode: u8) -> Span<OpenNoteDeposit>;
}
#[starknet::interface]
pub trait IExtra<T> {
    fn privacy_invoke(ref self: T, token: ContractAddress, amount: u128, note_id: felt252) -> (Span<OpenNoteDeposit>, felt252);
}

#[starknet::contract]
pub mod EvilAdapter {
    use starknet::{ContractAddress, get_caller_address, get_contract_address};
    use crate::open_note::OpenNoteDeposit;
    use crate::spend::{IERC20Dispatcher, IERC20DispatcherTrait};
    use crate::pool::{IM31PoolDispatcher, IM31PoolDispatcherTrait};
    #[storage]
    struct Storage {}
    #[abi(embed_v0)]
    impl Impl of super::IEvil<ContractState> {
        fn privacy_invoke(ref self: ContractState, pool: ContractAddress, token: ContractAddress, amount: u128, note_id: felt252, mode: u8) -> Span<OpenNoteDeposit> {
            let erc = IERC20Dispatcher { contract_address: token };
            if mode == 1 {
                // Re-enter the pool.
                erc.approve(pool, 10);
                IM31PoolDispatcher { contract_address: pool }.deposit(token, 10, array![1,2,3,4,5,6,7,8,9].span(), array![1,2,3,4,5,6,7,8,9,10].span());
            }
            if mode == 6 {
                // Return no deposit at all.
                return array![].span();
            }
            if mode == 7 {
                // Report a deposit for a note the intent does not name.
                erc.approve(get_caller_address(), amount.into());
                return array![OpenNoteDeposit { note_id: note_id + 1, token, amount }].span();
            }
            if mode == 3 {
                erc.approve(get_caller_address(), (amount - 1).into());
            } else if mode == 5 {
                // Try to pull the pool's funds (the pool grants no allowance).
                erc.transfer_from(pool, get_contract_address(), 1);
                erc.approve(get_caller_address(), amount.into());
            } else {
                erc.approve(get_caller_address(), amount.into());
            }
            array![OpenNoteDeposit { note_id, token, amount }].span()
        }
    }
}

#[starknet::contract]
pub mod ExtraAdapter {
    use starknet::{ContractAddress, get_caller_address};
    use crate::open_note::OpenNoteDeposit;
    use crate::spend::{IERC20Dispatcher, IERC20DispatcherTrait};
    #[storage]
    struct Storage {}
    #[abi(embed_v0)]
    impl Impl of super::IExtra<ContractState> {
        fn privacy_invoke(ref self: ContractState, token: ContractAddress, amount: u128, note_id: felt252) -> (Span<OpenNoteDeposit>, felt252) {
            IERC20Dispatcher { contract_address: token }.approve(get_caller_address(), amount.into());
            (array![OpenNoteDeposit { note_id, token, amount }].span(), 0)
        }
    }
}

/// Fee-on-transfer token: `transfer_from` delivers one unit less.
#[starknet::contract]
pub mod FeeToken {
    use core::starknet::{get_caller_address, ContractAddress};
    use crate::spend::IERC20;
    use starknet::storage::{Map, StorageMapReadAccess, StorageMapWriteAccess};
    #[storage]
    struct Storage { balances: Map<ContractAddress, u256>, allowances: Map<(ContractAddress, ContractAddress), u256> }
    #[abi(embed_v0)]
    impl Erc20Impl of IERC20<ContractState> {
        fn approve(ref self: ContractState, spender: ContractAddress, amount: u256) -> bool {
            self.allowances.write((get_caller_address(), spender), amount); true
        }
        fn transfer(ref self: ContractState, recipient: ContractAddress, amount: u256) -> bool {
            let s = get_caller_address();
            self.balances.write(s, self.balances.read(s) - amount);
            self.balances.write(recipient, self.balances.read(recipient) + amount); true
        }
        fn transfer_from(ref self: ContractState, sender: ContractAddress, recipient: ContractAddress, amount: u256) -> bool {
            let sp = get_caller_address();
            self.allowances.write((sender, sp), self.allowances.read((sender, sp)) - amount);
            self.balances.write(sender, self.balances.read(sender) - amount);
            self.balances.write(recipient, self.balances.read(recipient) + amount - 1); true
        }
        fn balance_of(self: @ContractState, account: ContractAddress) -> u256 { self.balances.read(account) }
    }
    #[external(v0)]
    fn faucet(ref self: ContractState, to: ContractAddress, amount: u256) {
        self.balances.write(to, self.balances.read(to) + amount);
    }
}

// ---------------------------------------------------------------- policy controllers (tests)

#[starknet::interface]
pub trait IMockPolicyController<T> {
    fn last_authorization(self: @T) -> Span<felt252>;
    fn calls(self: @T) -> u32;
}

/// A policy controller for pool tests. Mode 0 approves (and records the authorization), 1
/// reverts, 2 returns a wrong value, 3 tries to re-enter the pool.
#[starknet::contract]
pub mod MockPolicyController {
    use starknet::storage::{
        MutableVecTrait, StoragePointerReadAccess, StoragePointerWriteAccess, Vec, VecTrait,
    };
    use starknet::{ContractAddress, get_caller_address};
    use crate::pool::{IM31PoolDispatcher, IM31PoolDispatcherTrait};
    use crate::policy::ITemplarPolicyController;

    #[storage]
    struct Storage {
        mode: u8,
        calls: u32,
        last: Vec<felt252>,
    }

    #[constructor]
    fn constructor(ref self: ContractState, mode: u8) {
        self.mode.write(mode);
    }

    #[abi(embed_v0)]
    impl ViewImpl of super::IMockPolicyController<ContractState> {
        fn last_authorization(self: @ContractState) -> Span<felt252> {
            let mut out = array![];
            for i in 0..self.last.len() {
                out.append(self.last.at(i).read());
            }
            out.span()
        }

        fn calls(self: @ContractState) -> u32 {
            self.calls.read()
        }
    }

    #[abi(embed_v0)]
    impl ControllerImpl of ITemplarPolicyController<ContractState> {
        fn templar_apply_policy(ref self: ContractState, authorization: Span<felt252>, data: Span<felt252>) -> felt252 {
            let mode = self.mode.read();
            assert(mode != 1, 'CONTROLLER_SAYS_NO');
            if mode == 3 {
                let pool: ContractAddress = get_caller_address();
                IM31PoolDispatcher { contract_address: pool }
                    .deposit(1.try_into().unwrap(), 1, array![1, 2, 3, 4, 5, 6, 7, 8, 9].span(), array![].span());
            }
            while self.last.len() > 0 {
                let _ = self.last.pop();
            }
            for a in authorization {
                self.last.push(*a);
            }
            self.calls.write(self.calls.read() + 1);
            let _ = data;
            if mode == 2 {
                'NOPE'
            } else {
                crate::policy::POLICY_OK
            }
        }
    }
}
