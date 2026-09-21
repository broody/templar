use super::m31_hash::Digest;
#[starknet::interface]
pub trait IFeltBench<TState> {
    fn append_batch(ref self: TState, leaves: Span<felt252>) -> felt252;
    fn seed_prefix(ref self: TState, leaves: Span<felt252>);
    fn seed_counters(ref self: TState, count: u64, ring: u64);
    fn seed_snapshot(ref self: TState, nodes: Span<(felt252, felt252)>, zeros: Span<felt252>, roots: Span<felt252>);
    fn read_raw_state(self: @TState, node_keys: Span<felt252>, history_keys: Span<felt252>) -> Array<felt252>;
}
#[starknet::interface]
pub trait IM31Bench<TState> {
    fn append_batch(ref self: TState, leaves: Span<felt252>) -> Digest;
    fn seed_prefix(ref self: TState, leaves: Span<felt252>);
    fn seed_counters(ref self: TState, count: u64, ring: u64);
    fn seed_snapshot(ref self: TState, nodes: Span<(felt252, Digest)>, zeros: Span<Digest>, roots: Span<Digest>);
    fn read_raw_state(self: @TState, node_keys: Span<felt252>, history_keys: Span<Digest>) -> Array<felt252>;
}
// Both contracts are benchmark fixtures, with deliberately unrestricted writers.
// seed_prefix separates setup costs from the measured append_batch entrypoint.
// seed_counters is only for the capacity/history boundary tests.
#[starknet::contract]
pub mod FeltTreeBench {
    use m31_tree_bench::felt_tree::tree_component;
    use m31_tree_bench::felt_tree::tree_component::TreeInternalTrait;
    use starknet::storage::{StoragePointerWriteAccess,StorageMapWriteAccess,StoragePointerReadAccess,StorageMapReadAccess};
    component!(path: tree_component, storage: tree, event: TreeEvent);
    #[storage]
    struct Storage { #[substorage(v0)] pub tree: tree_component::Storage }
    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event { TreeEvent: tree_component::Event }
    #[abi(embed_v0)]
    impl TreeImpl = tree_component::Tree<ContractState>;
    #[abi(embed_v0)]
    impl BenchImpl of super::IFeltBench<ContractState> {
        fn append_batch(ref self: ContractState, leaves: Span<felt252>) -> felt252 {
            for leaf in leaves { self.tree.insert_leaf(*leaf); };
            TreeImpl::get_root(@self)
        }
        fn seed_prefix(ref self: ContractState, leaves: Span<felt252>) {
            for leaf in leaves { self.tree.insert_leaf(*leaf); };
        }
        fn seed_snapshot(ref self: ContractState, nodes: Span<(felt252, felt252)>, zeros: Span<felt252>, roots: Span<felt252>) {
            assert(zeros.len() == 33 && roots.len() >= 2 && roots.len() <= 9, 'FIXTURE_SHAPE');
            for entry in nodes { let (key,value)=*entry; self.tree.nodes.write(key,value); };
            let mut i: u64=0;
            for zero in zeros { self.tree.zero_hashes.write(i,*zero); i+=1; };
            i=0;
            for root in roots { self.tree.ring_slots.write(i,*root); self.tree.root_history.write(*root,true); i+=1; };
            self.tree.zeros_initialized.write(true);
            self.tree.tree_count.write((roots.len()-1).into());
            self.tree.tree_root.write(*roots.at(roots.len()-1));
            self.tree.root_ring_index.write(roots.len().into());
        }
        // Raw reads deliberately bypass get_node's empty-node fallback. The wire order
        // is nodes, zeros0..33, flag/count/root/ring_index, all256 ring slots, history.
        // This entrypoint is only for fixture correctness tests, never a measured append.
        fn read_raw_state(self: @ContractState, node_keys: Span<felt252>, history_keys: Span<felt252>) -> Array<felt252> {
            let mut result=array![];
            for key in node_keys { result.append(self.tree.nodes.read(*key)); };
            let mut level: u64=0;
            while level < 34 { result.append(self.tree.zero_hashes.read(level)); level+=1; };
            result.append(if self.tree.zeros_initialized.read() { 1 } else { 0 });
            result.append(self.tree.tree_count.read().into());
            result.append(self.tree.tree_root.read());
            result.append(self.tree.root_ring_index.read().into());
            let mut slot: u64=0;
            while slot < 256 { result.append(self.tree.ring_slots.read(slot)); slot+=1; };
            for root in history_keys { result.append(if self.tree.root_history.read(*root) { 1 } else { 0 }); };
            result
        }
        fn seed_counters(ref self: ContractState, count: u64, ring: u64) {
            self.tree.tree_count.write(count);
            self.tree.root_ring_index.write(ring);
        }
    }
}
#[starknet::contract]
pub mod M31TreeBench {
    use m31_tree_bench::m31_tree::tree_component;
    use m31_tree_bench::m31_tree::tree_component::TreeInternalTrait;
    use m31_tree_bench::m31_hash::{Digest,DigestTrait};
    use starknet::storage::{StoragePointerWriteAccess,StorageMapWriteAccess,StoragePointerReadAccess,StorageMapReadAccess};
    component!(path: tree_component, storage: tree, event: TreeEvent);
    #[storage]
    struct Storage { #[substorage(v0)] pub tree: tree_component::Storage }
    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event { TreeEvent: tree_component::Event }
    #[abi(embed_v0)]
    impl TreeImpl = tree_component::Tree<ContractState>;
    #[abi(embed_v0)]
    impl BenchImpl of super::IM31Bench<ContractState> {
        fn append_batch(ref self: ContractState, leaves: Span<felt252>) -> Digest {
            for leaf in leaves { self.tree.insert_leaf(*leaf); };
            TreeImpl::get_root(@self)
        }
        fn seed_prefix(ref self: ContractState, leaves: Span<felt252>) {
            for leaf in leaves { self.tree.insert_leaf(*leaf); };
        }
        fn seed_snapshot(ref self: ContractState, nodes: Span<(felt252, Digest)>, zeros: Span<Digest>, roots: Span<Digest>) {
            assert(zeros.len() == 33 && roots.len() >= 2 && roots.len() <= 9, 'FIXTURE_SHAPE');
            for entry in nodes { let (key,value)=*entry; self.tree.nodes.write(key,value); };
            let mut i: u64=0;
            for zero in zeros { self.tree.zero_hashes.write(i,*zero); i+=1; };
            i=0;
            for root in roots { self.tree.ring_slots.write(i,*root); self.tree.root_history.write(root.key(),true); i+=1; };
            self.tree.zeros_initialized.write(true);
            self.tree.tree_count.write((roots.len()-1).into());
            self.tree.tree_root.write(*roots.at(roots.len()-1));
            self.tree.root_ring_index.write(roots.len().into());
        }
        // Raw reads deliberately bypass get_node's empty-node fallback. The wire order
        // is nodes, zeros0..33, flag/count/root/ring_index, all256 ring slots, history.
        // This entrypoint is only for fixture correctness tests, never a measured append.
        fn read_raw_state(self: @ContractState, node_keys: Span<felt252>, history_keys: Span<Digest>) -> Array<felt252> {
            let mut result=array![];
            for key in node_keys { let value=self.tree.nodes.read(*key); result.append(value.low); result.append(value.high); };
            let mut level: u64=0;
            while level < 34 { let value=self.tree.zero_hashes.read(level); result.append(value.low); result.append(value.high); level+=1; };
            result.append(if self.tree.zeros_initialized.read() { 1 } else { 0 });
            result.append(self.tree.tree_count.read().into());
            let value=self.tree.tree_root.read(); result.append(value.low); result.append(value.high);
            result.append(self.tree.root_ring_index.read().into());
            let mut slot: u64=0;
            while slot < 256 { let value=self.tree.ring_slots.read(slot); result.append(value.low); result.append(value.high); slot+=1; };
            for root in history_keys { result.append(if self.tree.root_history.read(root.key()) { 1 } else { 0 }); };
            result
        }
        fn seed_counters(ref self: ContractState, count: u64, ring: u64) {
            self.tree.tree_count.write(count);
            self.tree.root_ring_index.write(ring);
        }
    }
}
