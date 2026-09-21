#[starknet::interface]
pub trait ITreeWriter<TState> {
    fn insert_leaf(ref self: TState, leaf: felt252) -> u64;
}

//! Mock contract embedding the tree component for snforge tests.

#[starknet::contract]
pub mod TreeMock {
    use pool::tree::tree_component;
    use pool::tree::tree_component::TreeInternalTrait;

    component!(path: tree_component, storage: tree, event: TreeEvent);

    #[storage]
    struct Storage {
        #[substorage(v0)]
        pub tree: tree_component::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        TreeEvent: tree_component::Event,
    }

    #[constructor]
    fn constructor(ref self: ContractState) {}

    #[abi(embed_v0)]
    impl WriterImpl of super::ITreeWriter<ContractState> {
        fn insert_leaf(ref self: ContractState, leaf: felt252) -> u64 {
            self.tree.insert_leaf(leaf)
        }
    }

    #[abi(embed_v0)]
    impl TreeImpl = tree_component::Tree<ContractState>;
}
