use super::m31_hash::Digest;

#[starknet::interface]
pub trait IM31Tree<TState> {
    fn get_root(self: @TState) -> Digest;
    fn get_leaf_count(self: @TState) -> u64;
    fn root_is_known(self: @TState, root: Digest) -> bool;
    fn get_node(self: @TState, level: u64, index: u64) -> Digest;
}

#[starknet::component]
pub mod tree_component {
    use super::Digest;
    use m31_tree_bench::m31_hash::{DigestTrait, empty_leaf, leaf_hash, node_hash};
    use m31_tree_bench::felt_tree::{node_key,TREE_DEPTH,ROOT_HISTORY_SIZE};
    use starknet::storage::{Map,StorageMapReadAccess,StorageMapWriteAccess,StoragePointerReadAccess,StoragePointerWriteAccess};
    #[storage]
    pub struct Storage {
        pub nodes: Map<felt252, Digest>,
        pub zero_hashes: Map<u64, Digest>,
        pub zeros_initialized: bool,
        pub tree_count: u64,
        pub tree_root: Digest,
        pub root_history: Map<(felt252,felt252), bool>,
        pub ring_slots: Map<u64, Digest>,
        pub root_ring_index: u64,
    }
    #[embeddable_as(Tree)]
    impl TreeImpl<TContractState,+HasComponent<TContractState>> of super::IM31Tree<ComponentState<TContractState>> {
        fn get_root(self: @ComponentState<TContractState>) -> Digest { self.tree_root.read() }
        fn get_leaf_count(self: @ComponentState<TContractState>) -> u64 { self.tree_count.read() }
        fn root_is_known(self: @ComponentState<TContractState>,root: Digest) -> bool { self.root_history.read(root.key()) }
        fn get_node(self: @ComponentState<TContractState>,level: u64,index: u64) -> Digest {
            let value=self.nodes.read(node_key(level,index));
            if value.is_zero() { self.zero_hashes.read(level) } else { value }
        }
    }
    #[generate_trait]
    pub impl TreeInternalImpl<TContractState,+HasComponent<TContractState>> of TreeInternalTrait<TContractState> {
        fn insert_leaf(ref self: ComponentState<TContractState>, leaf: felt252) -> u64 {
            assert(leaf != 0,'ZERO_LEAF');
            if !self.zeros_initialized.read() { self._init_zeros(); }
            let idx=self.tree_count.read();
            assert(idx < 0x100000000,'TREE_FULL');
            let mut cur_value=leaf_hash(leaf);
            self.nodes.write(node_key(0,idx),cur_value);
            let mut level: u64=0;
            let mut cur_index=idx;
            while level < TREE_DEPTH {
                let sib_index=if cur_index%2==0 { cur_index+1 } else { cur_index-1 };
                let sib_stored=self.nodes.read(node_key(level,sib_index));
                let sibling=if sib_stored.is_zero() { self.zero_hashes.read(level) } else { sib_stored };
                cur_value=if cur_index%2==0 { node_hash(level+1,cur_value,sibling) }
                    else { node_hash(level+1,sibling,cur_value) };
                self.nodes.write(node_key(level+1,cur_index/2),cur_value);
                cur_index/=2;
                level+=1;
            }
            let ring_index=self.root_ring_index.read();
            let slot=ring_index%ROOT_HISTORY_SIZE;
            if ring_index>=ROOT_HISTORY_SIZE {
                let old=self.ring_slots.read(slot);
                self.root_history.write(old.key(),false);
            }
            self.ring_slots.write(slot,cur_value);
            self.root_history.write(cur_value.key(),true);
            self.root_ring_index.write(ring_index+1);
            self.tree_root.write(cur_value);
            self.tree_count.write(idx+1);
            idx
        }
        fn _init_zeros(ref self: ComponentState<TContractState>) {
            let mut z=empty_leaf();
            self.zero_hashes.write(0,z);
            let mut l: u64=0;
            while l<TREE_DEPTH {
                l+=1;
                z=node_hash(l,z,z);
                self.zero_hashes.write(l,z);
            }
            self.tree_root.write(z);
            self.root_history.write(z.key(),true);
            self.ring_slots.write(0,z);
            self.root_ring_index.write(1);
            self.zeros_initialized.write(true);
        }
    }
}
