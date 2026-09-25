//! Mock bound accounts for the statement-account tests. Each is deployed at the account address
//! the fixture proof names, and answers `is_valid_signature` in one fixed way.

/// `is_valid_signature` as SNIP-6 declares it.
#[starknet::interface]
pub trait ISrc6<T> {
    fn is_valid_signature(self: @T, hash: felt252, signature: Array<felt252>) -> felt252;
}

/// The statement account's entry points.
#[starknet::interface]
pub trait IStatementAccount<T> {
    fn __validate__(self: @T, proof_data: Span<felt252>, salt: felt252, signature: Span<felt252>) -> felt252;
    fn __execute__(ref self: T, proof_data: Span<felt252>, salt: felt252, signature: Span<felt252>);
}

pub const MODE_CHECK: felt252 = 0;
pub const MODE_ZERO: felt252 = 1;
pub const MODE_PANIC: felt252 = 2;
pub const MODE_EMIT: felt252 = 3;
pub const MODE_REENTER: felt252 = 4;
pub const MODE_ANY: felt252 = 5;

/// Returns `'VALID'` in `MODE_CHECK` only for the expected hash and signature (so a test also
/// pins the hash the statement account computes), `0` in `MODE_ZERO`, panics in `MODE_PANIC`,
/// emits an L2→L1 message and returns `'VALID'` in `MODE_EMIT`, calls back into the statement
/// account in `MODE_REENTER`, and returns `'VALID'` for anything in `MODE_ANY`.
#[starknet::contract]
pub mod MockAccount {
    use core::poseidon::poseidon_hash_span;
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};
    use starknet::syscalls::send_message_to_l1_syscall;
    use starknet::{ContractAddress, SyscallResultTrait};
    use super::{IStatementAccountDispatcher, IStatementAccountDispatcherTrait};

    #[storage]
    struct Storage {
        mode: felt252,
        expected_hash: felt252,
        expected_signature: felt252,
        statement_account: ContractAddress,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        mode: felt252,
        expected_hash: felt252,
        expected_signature: felt252,
        statement_account: ContractAddress,
    ) {
        self.mode.write(mode);
        self.expected_hash.write(expected_hash);
        self.expected_signature.write(expected_signature);
        self.statement_account.write(statement_account);
    }

    #[external(v0)]
    fn is_valid_signature(self: @ContractState, hash: felt252, signature: Array<felt252>) -> felt252 {
        let mode = self.mode.read();
        if mode == super::MODE_CHECK {
            let ok = hash == self.expected_hash.read()
                && poseidon_hash_span(signature.span()) == self.expected_signature.read();
            return if ok { 'VALID' } else { 0 };
        }
        if mode == super::MODE_ZERO {
            return 0;
        }
        if mode == super::MODE_PANIC {
            panic!("MOCK_PANIC");
        }
        if mode == super::MODE_EMIT {
            send_message_to_l1_syscall(0, array!['MOCK'].span()).unwrap_syscall();
            return 'VALID';
        }
        if mode == super::MODE_REENTER {
            let target = IStatementAccountDispatcher { contract_address: self.statement_account.read() };
            target.__execute__(array![].span(), 0, array![].span());
            return 'VALID';
        }
        'VALID'
    }
}

/// A deployed contract without `is_valid_signature`: the call returns an error, and the spend fails.
#[starknet::contract]
pub mod MockNoEntryPoint {
    #[storage]
    struct Storage {}

    #[external(v0)]
    fn other(self: @ContractState) -> felt252 {
        0
    }
}

/// Returns two felts, `['VALID', 0]`: the statement account requires exactly one.
#[starknet::contract]
pub mod MockTwoFelts {
    #[storage]
    struct Storage {}

    #[external(v0)]
    fn is_valid_signature(self: @ContractState, hash: felt252, signature: Array<felt252>) -> (felt252, felt252) {
        ('VALID', 0)
    }
}
