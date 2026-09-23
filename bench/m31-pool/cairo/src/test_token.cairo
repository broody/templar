//! Minimal ERC20 for deposit/withdraw tests: balances + allowances,
//! transfer/transfer_from per `pool::spend::IERC20`, plus a test faucet.

#[starknet::contract]
pub mod E2EToken {
    use core::starknet::{get_caller_address, ContractAddress};
    use m31_pool::spend::IERC20;
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };

    #[storage]
    struct Storage {
        balances: Map<ContractAddress, u256>,
        allowances: Map<(ContractAddress, ContractAddress), u256>,
    }

    #[constructor]
    fn constructor(ref self: ContractState, initial_holder: ContractAddress, initial_amount: u256) {
        self.balances.write(initial_holder, initial_amount);
    }

    #[abi(embed_v0)]
    impl Erc20Impl of IERC20<ContractState> {
        fn approve(ref self: ContractState, spender: ContractAddress, amount: u256) -> bool {
            self.allowances.write((get_caller_address(), spender), amount);
            true
        }

        fn transfer(ref self: ContractState, recipient: ContractAddress, amount: u256) -> bool {
            let sender = get_caller_address();
            let balance = self.balances.read(sender);
            assert(balance >= amount, 'INSUFFICIENT_FUNDS');
            self.balances.write(sender, balance - amount);
            self.balances.write(recipient, self.balances.read(recipient) + amount);
            true
        }

        fn transfer_from(
            ref self: ContractState,
            sender: ContractAddress,
            recipient: ContractAddress,
            amount: u256,
        ) -> bool {
            let spender = get_caller_address();
            let allowance = self.allowances.read((sender, spender));
            assert(allowance >= amount, 'INSUFFICIENT_ALLOWANCE');
            self.allowances.write((sender, spender), allowance - amount);
            let balance = self.balances.read(sender);
            assert(balance >= amount, 'INSUFFICIENT_FUNDS');
            self.balances.write(sender, balance - amount);
            self.balances.write(recipient, self.balances.read(recipient) + amount);
            true
        }
    }

    #[external(v0)]
    fn faucet(ref self: ContractState, to: ContractAddress, amount: u256) {
        self.balances.write(to, self.balances.read(to) + amount);
    }

    #[external(v0)]
    fn balance_of(self: @ContractState, account: ContractAddress) -> u256 {
        self.balances.read(account)
    }
}
