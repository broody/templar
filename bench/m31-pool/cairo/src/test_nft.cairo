//! Test-only token and recipient contracts for M31 pool V2: OpenZeppelin ERC721 and ERC1155 with
//! a public mint (no acceptance check, so the test contract can hold tokens), an account-like
//! recipient (SRC5 answers ISRC6), a recipient that re-enters the pool from its ERC1155 hook, and
//! a contract with no SRC5 at all.

#[starknet::interface]
pub trait IMint<T> {
    fn mint(ref self: T, to: starknet::ContractAddress, token_id: u256, value: u256);
}

#[starknet::contract]
pub mod TestERC721 {
    use openzeppelin_introspection::src5::SRC5Component;
    use openzeppelin_token::erc721::{ERC721Component, ERC721HooksEmptyImpl};
    use starknet::ContractAddress;

    component!(path: ERC721Component, storage: erc721, event: ERC721Event);
    component!(path: SRC5Component, storage: src5, event: SRC5Event);

    #[abi(embed_v0)]
    impl ERC721MixinImpl = ERC721Component::ERC721MixinImpl<ContractState>;
    impl ERC721InternalImpl = ERC721Component::InternalImpl<ContractState>;

    #[storage]
    struct Storage {
        #[substorage(v0)]
        erc721: ERC721Component::Storage,
        #[substorage(v0)]
        src5: SRC5Component::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        #[flat]
        ERC721Event: ERC721Component::Event,
        #[flat]
        SRC5Event: SRC5Component::Event,
    }

    #[constructor]
    fn constructor(ref self: ContractState) {
        self.erc721.initializer("Test NFT", "TNFT", "");
    }

    #[abi(embed_v0)]
    impl MintImpl of super::IMint<ContractState> {
        fn mint(ref self: ContractState, to: ContractAddress, token_id: u256, value: u256) {
            self.erc721.mint(to, token_id);
        }
    }
}

#[starknet::contract]
pub mod TestERC1155 {
    use openzeppelin_introspection::src5::SRC5Component;
    use openzeppelin_token::erc1155::{ERC1155Component, ERC1155HooksEmptyImpl};
    use starknet::ContractAddress;

    component!(path: ERC1155Component, storage: erc1155, event: ERC1155Event);
    component!(path: SRC5Component, storage: src5, event: SRC5Event);

    #[abi(embed_v0)]
    impl ERC1155MixinImpl = ERC1155Component::ERC1155MixinImpl<ContractState>;
    impl ERC1155InternalImpl = ERC1155Component::InternalImpl<ContractState>;

    #[storage]
    struct Storage {
        #[substorage(v0)]
        erc1155: ERC1155Component::Storage,
        #[substorage(v0)]
        src5: SRC5Component::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        #[flat]
        ERC1155Event: ERC1155Component::Event,
        #[flat]
        SRC5Event: SRC5Component::Event,
    }

    #[constructor]
    fn constructor(ref self: ContractState) {
        self.erc1155.initializer("");
    }

    #[abi(embed_v0)]
    impl MintImpl of super::IMint<ContractState> {
        /// Credits without an acceptance check (also used to simulate a hook-less mint to the
        /// pool).
        fn mint(ref self: ContractState, to: ContractAddress, token_id: u256, value: u256) {
            self.erc1155.update(0.try_into().unwrap(), to, array![token_id].span(), array![value].span());
        }
    }
}

/// Answers SRC5 for ISRC6, as an account does, so ERC1155 safe transfers to it succeed.
#[starknet::contract]
pub mod AccountLikeRecipient {
    use openzeppelin_introspection::src5::SRC5Component;

    component!(path: SRC5Component, storage: src5, event: SRC5Event);

    #[abi(embed_v0)]
    impl SRC5Impl = SRC5Component::SRC5Impl<ContractState>;
    impl SRC5InternalImpl = SRC5Component::InternalImpl<ContractState>;

    #[storage]
    struct Storage {
        #[substorage(v0)]
        src5: SRC5Component::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        #[flat]
        SRC5Event: SRC5Component::Event,
    }

    #[constructor]
    fn constructor(ref self: ContractState) {
        self.src5.register_interface(crate::assets::ISRC6_ID);
    }
}

/// No SRC5: ERC1155 safe transfers to it revert.
#[starknet::contract]
pub mod PlainRecipient {
    #[storage]
    struct Storage {}
}

/// An ERC1155 receiver whose hook calls back into the pool (an ERC20 deposit); the pool's lock
/// must make the whole payout revert.
#[starknet::contract]
pub mod ReentrantRecipient {
    use starknet::ContractAddress;
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};
    use crate::pool_v2::{IM31PoolV2Dispatcher, IM31PoolV2DispatcherTrait};

    #[storage]
    struct Storage {
        pool: ContractAddress,
        token: ContractAddress,
    }

    #[constructor]
    fn constructor(ref self: ContractState, pool: ContractAddress, token: ContractAddress) {
        self.pool.write(pool);
        self.token.write(token);
    }

    #[external(v0)]
    fn supports_interface(self: @ContractState, interface_id: felt252) -> bool {
        interface_id == crate::assets::IERC1155_RECEIVER_ID || interface_id == crate::assets::ISRC5_ID
    }

    #[external(v0)]
    fn on_erc1155_received(
        ref self: ContractState, operator: ContractAddress, from: ContractAddress, token_id: u256, value: u256,
        data: Span<felt252>,
    ) -> felt252 {
        let inner = array![1, 2, 3, 4, 5, 6, 7, 8, 9].span();
        let ciphertext = array![1, 2, 3, 4, 5, 6, 7, 8, 9, 10].span();
        IM31PoolV2Dispatcher { contract_address: self.pool.read() }.deposit(self.token.read(), 1, inner, ciphertext);
        crate::assets::IERC1155_RECEIVER_ID
    }
}
