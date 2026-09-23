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
