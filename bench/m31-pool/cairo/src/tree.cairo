//! Depth-32 append-only Poseidon2-M31 note tree with the reference pool's 256-root history
//! (`controlled-push-e2e/cairo/src/tree.cairo`). Two storage modes:
//! - **nodes**: every updated node is stored, as in the reference, so wallets can read paths
//!   from chain storage (`get_node`);
//! - **frontier**: only the rightmost left child per level, the minimum an append needs; paths
//!   then come from events or an indexer.
//! Digests are nine M31 words stored as two felts (`hash::pack`); roots and nullifiers are keyed
//! by `hash::key`. Empty subtrees are the generated constants `zeros::zero`.

pub const TREE_DEPTH: u32 = 32;
pub const ROOT_HISTORY_SIZE: u64 = 256;

#[starknet::interface]
pub trait IM31Tree<TState> {
    fn get_root(self: @TState) -> Span<felt252>;
    fn get_leaf_count(self: @TState) -> u64;
    fn root_is_known(self: @TState, root: Span<felt252>) -> bool;
    /// Stored node, or the empty-subtree digest for its level (nodes mode only).
    fn get_node(self: @TState, level: u32, index: u64) -> Span<felt252>;
}

pub fn node_key(level: u32, index: u64) -> felt252 {
    let level: felt252 = level.into();
    level * 0x10000000000000000 + index.into()
}

#[starknet::component]
pub mod m31_tree_component {
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };
    use crate::hash::{Digest, is_zero, key, node, pack, unpack};
    use crate::zeros::zero;
    use super::{ROOT_HISTORY_SIZE, TREE_DEPTH, node_key};

    #[storage]
    pub struct Storage {
        pub format: u8,
        pub store_nodes: bool,
        /// nodes mode: node digests keyed by `node_key(level, index)`; absent = empty subtree.
        pub nodes: Map<felt252, (felt252, felt252)>,
        /// frontier mode: the rightmost left child at each level.
        pub frontier: Map<u32, (felt252, felt252)>,
        pub tree_count: u64,
        pub tree_root: (felt252, felt252),
        pub root_history: Map<felt252, bool>,
        pub ring_slots: Map<u64, felt252>,
        pub root_ring_index: u64,
    }

    #[embeddable_as(M31Tree)]
    pub impl M31TreeImpl<
        TContractState, +HasComponent<TContractState>,
    > of super::IM31Tree<ComponentState<TContractState>> {
        fn get_root(self: @ComponentState<TContractState>) -> Span<felt252> {
            let (lo, hi) = self.tree_root.read();
            unpack(lo, hi).span()
        }

        fn get_leaf_count(self: @ComponentState<TContractState>) -> u64 {
            self.tree_count.read()
        }

        fn root_is_known(self: @ComponentState<TContractState>, root: Span<felt252>) -> bool {
            self.root_history.read(key(crate::hash::read_digest(root)))
        }

        fn get_node(self: @ComponentState<TContractState>, level: u32, index: u64) -> Span<felt252> {
            assert(self.store_nodes.read(), 'NODES_NOT_STORED');
            let (lo, hi) = self.nodes.read(node_key(level, index));
            if lo == 0 && hi == 0 {
                zero(self.format.read(), level).span()
            } else {
                unpack(lo, hi).span()
            }
        }
    }

    #[generate_trait]
    pub impl M31TreeInternalImpl<
        TContractState, +HasComponent<TContractState>,
    > of M31TreeInternalTrait<TContractState> {
        /// Fixes the node format and storage mode and seeds the history with the empty root.
        fn initializer(ref self: ComponentState<TContractState>, format: u8, store_nodes: bool) {
            assert(format <= 1, 'FORMAT');
            self.format.write(format);
            self.store_nodes.write(store_nodes);
            let empty = zero(format, TREE_DEPTH);
            self.tree_root.write(pack(empty));
            let k = key(empty);
            self.root_history.write(k, true);
            self.ring_slots.write(0, k);
            self.root_ring_index.write(1);
        }

        /// Appends `leaf`; only funded deposits or verified spends may call this.
        fn insert_leaf(ref self: ComponentState<TContractState>, leaf: Digest) -> u64 {
            assert(!is_zero(leaf), 'ZERO_LEAF');
            let format = self.format.read();
            let store_nodes = self.store_nodes.read();
            let idx = self.tree_count.read();
            assert(idx < 0x100000000, 'TREE_FULL');
            if store_nodes {
                self.nodes.write(node_key(0, idx), pack(leaf));
            }
            let mut cur = leaf;
            let mut index = idx;
            let mut level: u32 = 0;
            while level < TREE_DEPTH {
                let left_child = index % 2 == 0;
                let sibling = if store_nodes {
                    let sib_index = if left_child { index + 1 } else { index - 1 };
                    let (lo, hi) = self.nodes.read(node_key(level, sib_index));
                    if lo == 0 && hi == 0 {
                        zero(format, level)
                    } else {
                        unpack(lo, hi)
                    }
                } else if left_child {
                    self.frontier.write(level, pack(cur));
                    zero(format, level)
                } else {
                    let (lo, hi) = self.frontier.read(level);
                    unpack(lo, hi)
                };
                cur = if left_child {
                    node(format, level.into(), cur, sibling)
                } else {
                    node(format, level.into(), sibling, cur)
                };
                index = index / 2;
                level += 1;
                if store_nodes {
                    self.nodes.write(node_key(level, index), pack(cur));
                }
            }
            // Root history ring: evict the oldest root when saturated (as the reference).
            let k = key(cur);
            let ring_index = self.root_ring_index.read();
            let slot = ring_index % ROOT_HISTORY_SIZE;
            if ring_index >= ROOT_HISTORY_SIZE {
                let old = self.ring_slots.read(slot);
                self.root_history.write(old, false);
            }
            self.ring_slots.write(slot, k);
            self.root_history.write(k, true);
            self.root_ring_index.write(ring_index + 1);
            self.tree_root.write(pack(cur));
            self.tree_count.write(idx + 1);
            idx
        }
    }
}
