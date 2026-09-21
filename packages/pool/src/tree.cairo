//! Sparse commitment tree + root history ring — spec §4 (frozen 2026-09-19).
//!
//! Append-only fixed-depth binary tree over Starknet storage maps:
//! - Leaves are note commitments, appended at `tree_count` (no in-place updates,
//!   no deletions — spends are via nullifiers).
//! - Internal nodes are stored keyed by `(level, index)`; absent nodes default to
//!   the zero-hash chain `Z_l` where `Z_0 = EMPTY_LEAF` and `Z_{l+1} = H(Z_l, Z_l)`.
//!   Zero hashes are initialized lazily on the first insert (32 Poseidon steps,
//!   once).
//! - `root_history` is a bounded ring (`ROOT_HISTORY_SIZE`): a spend statement may
//!   reference any root still in the ring, which is what makes concurrent
//!   deposit/spend races benign (spec §7.4). Ring eviction policy: the oldest
//!   root is evicted (decided per spec open item §9.3).

use core::poseidon::poseidon_hash_span;
use starknet::storage::{
    StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
    StoragePointerWriteAccess,
};

pub const TREE_DEPTH: u64 = 32;
pub const ROOT_HISTORY_SIZE: u64 = 256;
pub const EMPTY_LEAF: felt252 = 0;
const TWO_POW_64: felt252 = 0x10000000000000000;

/// Storage key for the node at `level` (0 = leaves, TREE_DEPTH = root) and
/// `index` within that level.
pub fn node_key(level: u64, index: u64) -> felt252 {
    index.into() * TWO_POW_64 + level.into()
}

/// Ordered hash of two children: `H(left, right)`.
pub fn hash_pair(left: felt252, right: felt252) -> felt252 {
    poseidon_hash_span(array![left, right].span())
}

/// Recomputes the tree root from a leaf and its sibling path (as the M2 circuit
/// and the SDK do). `path[i]` is the sibling value at level `i`.
pub fn compute_root_from_path(leaf: felt252, leaf_index: u64, path: Span<felt252>) -> felt252 {
    assert(path.len() == TREE_DEPTH.try_into().unwrap(), 'BAD_PATH_LEN');
    let mut acc = leaf;
    let mut idx = leaf_index;
    let mut i: usize = 0;
    while i < TREE_DEPTH.try_into().unwrap() {
        let sib = *path.at(i);
        if idx % 2 == 0 {
            acc = hash_pair(acc, sib);
        } else {
            acc = hash_pair(sib, acc);
        }
        idx = idx / 2;
        i += 1;
    }
    acc
}

#[starknet::interface]
pub trait ITree<TState> {
    /// Current root.
    fn get_root(self: @TState) -> felt252;
    /// Number of leaves inserted.
    fn get_leaf_count(self: @TState) -> u64;
    /// Whether `root` is in the acceptable ring.
    fn root_is_known(self: @TState, root: felt252) -> bool;
    /// Stored node value at `(level, index)`, or the level's zero-hash default
    /// when absent. Used by SDK/tests to assemble membership paths.
    fn get_node(self: @TState, level: u64, index: u64) -> felt252;
}

#[starknet::component]
pub mod tree_component {
    use super::{hash_pair, node_key, EMPTY_LEAF, ROOT_HISTORY_SIZE, TREE_DEPTH};
    use core::poseidon::poseidon_hash_span;
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };

    #[storage]
    pub struct Storage {
        /// Internal + leaf nodes keyed by `node_key(level, index)`; absent = zero
        /// default for that level.
        pub nodes: Map<felt252, felt252>,
        /// Zero-hash chain `Z_l`; written once at lazy init.
        pub zero_hashes: Map<u64, felt252>,
        pub zeros_initialized: bool,
        /// Next append index (= number of leaves).
        pub tree_count: u64,
        pub tree_root: felt252,
        pub root_history: Map<felt252, bool>,
        /// Ring slot -> root, to find the evicted oldest root.
        pub ring_slots: Map<u64, felt252>,
        pub root_ring_index: u64,
    }

    #[embeddable_as(Tree)]
    pub impl TreeImpl<
        TContractState, +HasComponent<TContractState>,
    > of super::ITree<ComponentState<TContractState>> {
        fn get_root(self: @ComponentState<TContractState>) -> felt252 {
            self.tree_root.read()
        }

        fn get_leaf_count(self: @ComponentState<TContractState>) -> u64 {
            self.tree_count.read()
        }

        fn root_is_known(self: @ComponentState<TContractState>, root: felt252) -> bool {
            self.root_history.read(root)
        }

        fn get_node(self: @ComponentState<TContractState>, level: u64, index: u64) -> felt252 {
            let stored = self.nodes.read(node_key(level, index));
            if stored == 0 { self.zero_hashes.read(level) } else { stored }
        }
    }

    #[generate_trait]
    pub impl TreeInternalImpl<
        TContractState, +HasComponent<TContractState>,
    > of TreeInternalTrait<TContractState> {
        /// Internal mutation: only funded deposits or verified spends may call this.
        fn insert_leaf(
            ref self: ComponentState<TContractState>, leaf: felt252,
        ) -> u64 {
            assert(leaf != EMPTY_LEAF, 'ZERO_LEAF');
            if !self.zeros_initialized.read() {
                self._init_zeros();
            }

            let idx = self.tree_count.read();
            assert(idx < 0x100000000, 'TREE_FULL');
            self.nodes.write(node_key(0, idx), leaf);
            let mut level: u64 = 0;
            let mut cur_index: u64 = idx;
            let mut cur_value: felt252 = leaf;
            while level < TREE_DEPTH {
                let sib_index = if cur_index % 2 == 0 { cur_index + 1 } else { cur_index - 1 };
                let sib_stored = self.nodes.read(node_key(level, sib_index));
                let sib_value = if sib_stored == 0 {
                    self.zero_hashes.read(level)
                } else {
                    sib_stored
                };
                cur_value = if cur_index % 2 == 0 {
                    hash_pair(cur_value, sib_value)
                } else {
                    hash_pair(sib_value, cur_value)
                };
                self.nodes.write(node_key(level + 1, cur_index / 2), cur_value);
                cur_index = cur_index / 2;
                level += 1;
            }

            // Root history ring: evict the oldest root when saturated.
            let ring_index = self.root_ring_index.read();
            let slot = ring_index % ROOT_HISTORY_SIZE;
            if ring_index >= ROOT_HISTORY_SIZE {
                let old = self.ring_slots.read(slot);
                self.root_history.write(old, false);
            }
            self.ring_slots.write(slot, cur_value);
            self.root_history.write(cur_value, true);
            self.root_ring_index.write(ring_index + 1);
            self.tree_root.write(cur_value);
            self.tree_count.write(idx + 1);
            idx
        }

        /// Computes the zero-hash chain `Z_1..Z_TREE_DEPTH` and seeds the ring
        /// with the empty-tree root. Called once, lazily.
        fn _init_zeros(ref self: ComponentState<TContractState>) {
            self.zero_hashes.write(0, EMPTY_LEAF);
            let mut z: felt252 = EMPTY_LEAF;
            let mut l: u64 = 0;
            while l < TREE_DEPTH {
                z = poseidon_hash_span(array![z, z].span());
                l += 1;
                self.zero_hashes.write(l, z);
            }
            self.tree_root.write(z);
            self.root_history.write(z, true);
            self.ring_slots.write(0, z);
            self.root_ring_index.write(1);
            self.zeros_initialized.write(true);
        }
    }
}
