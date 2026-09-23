use pool::tests::mock_tree::{ITreeWriterDispatcher, ITreeWriterDispatcherTrait};
//! Tree tests: pure path verification, an independent naive reference
//! implementation, and stateful snforge tests for insertion + root ring.

use core::poseidon::poseidon_hash_span;
use pool::tree::{
    compute_root_from_path, hash_pair, ITreeDispatcher, ITreeDispatcherTrait, ROOT_HISTORY_SIZE,
    TREE_DEPTH,
};
use snforge_std::{declare, ContractClassTrait, DeclareResultTrait};
use starknet::{ContractAddress, SyscallResultTrait};

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

/// Zero-hash chain `Z_0..Z_TREE_DEPTH` (Z_0 = 0, Z_{l+1} = H(Z_l, Z_l)).
fn build_zeros() -> Array<felt252> {
    let mut zeros = array![];
    let mut z: felt252 = 0;
    let mut l: u64 = 0;
    while l <= TREE_DEPTH {
        zeros.append(z);
        z = poseidon_hash_span(array![z, z].span());
        l += 1;
    }
    zeros
}

/// Path for a leaf whose siblings are all empty above level `filled`:
/// `[sibling, Z_1, ..., Z_31]`.
fn full_path(first_sibling: felt252, zeros: @Array<felt252>) -> Span<felt252> {
    let mut path = array![first_sibling];
    let mut l: u64 = 1;
    while l < TREE_DEPTH {
        path.append(*zeros.at(l.try_into().unwrap()));
        l += 1;
    }
    path.span()
}

/// Independent (recursive, pruned) sparse-tree root over `leaves`, used to
/// cross-check the component's incremental root updates.
fn naive_root(
    depth: u64, lower: u64, coverage: u128, leaves: @Array<(u64, felt252)>, zeros: @Array<felt252>,
) -> felt252 {
    if depth == 0 {
        let mut i: usize = 0;
        let mut v: felt252 = 0;
        while i < leaves.len() {
            let (idx, val) = *leaves.at(i);
            let idx_u: u128 = idx.into();
            if idx_u == lower.into() {
                v = val;
            }
            i += 1;
        }
        v
    } else {
        // Prune: no leaf under this subtree.
        let mut i: usize = 0;
        let mut any = false;
        while i < leaves.len() {
            let (idx, _) = *leaves.at(i);
            let idx_u: u128 = idx.into();
            if idx_u >= lower.into() && idx_u < lower.into() + coverage {
                any = true;
            }
            i += 1;
        }
        if !any {
            return *zeros.at(depth.try_into().unwrap());
        }
        let half = coverage / 2;
        let l = naive_root(depth - 1, lower, half, leaves, zeros);
        let r = naive_root(depth - 1, lower + half.try_into().unwrap(), half, leaves, zeros);
        let child_default = *zeros.at((depth - 1).try_into().unwrap());
        if l == child_default && r == child_default {
            *zeros.at(depth.try_into().unwrap())
        } else {
            hash_pair(l, r)
        }
    }
}

// ---------------------------------------------------------------------------
// Pure tests (no state)
// ---------------------------------------------------------------------------

#[test]
fn path_verification_two_leaves() {
    let a: felt252 = 0xaa;
    let b: felt252 = 0xbb;
    let zeros = build_zeros();
    // Root built bottom-up, then above the 2-leaf subtree the path folds
    // against the zero chain: n_{l+1} = H(n_l, Z_l).
    let mut expected = hash_pair(a, b);
    let mut l: u64 = 1;
    while l < TREE_DEPTH {
        expected = hash_pair(expected, *zeros.at(l.try_into().unwrap()));
        l += 1;
    }
    let path = full_path(b, @zeros);
    assert_eq!(compute_root_from_path(a, 0, path), expected);
    let path1 = full_path(a, @zeros);
    assert_eq!(compute_root_from_path(b, 1, path1), expected);
}

#[test]
fn path_verification_wrong_path_fails() {
    // A path with a wrong sibling must not reconstruct the same root.
    let a: felt252 = 0xa;
    let b: felt252 = 0xbb;
    let zeros = build_zeros();
    let mut expected = hash_pair(a, b);
    let mut l: u64 = 1;
    while l < TREE_DEPTH {
        expected = hash_pair(expected, *zeros.at(l.try_into().unwrap()));
        l += 1;
    }
    let wrong_path = full_path(0xdead, @zeros);
    assert_ne!(compute_root_from_path(a, 0, wrong_path), expected);
    let _ = b;
}

#[test]
fn zero_hash_chain_is_self_consistent() {
    // The empty-subtree default at depth 2 equals H(Z_1, Z_1): a fully empty
    // tree of 4 leaves hashes to the chain value, matching the component's
    // lazy init rule.
    let zeros = build_zeros();
    let empty_root = hash_pair(*zeros.at(1), *zeros.at(1));
    assert_eq!(empty_root, *zeros.at(2));
}

// ---------------------------------------------------------------------------
// Stateful tests (TreeMock)
// ---------------------------------------------------------------------------

fn deploy_tree() -> (ContractAddress, ITreeDispatcher) {
    let contract = declare("TreeMock").unwrap_syscall().contract_class();
    let (address, _) = contract.deploy(constructor_calldata: @array![]).unwrap_syscall();
    (address, ITreeDispatcher { contract_address: address })
}

/// Assembles the sibling path for `leaf_index` from stored nodes, as the SDK
/// would for the circuit witness.
fn assemble_path(tree: @ITreeDispatcher, leaf_index: u64) -> Span<felt252> {
    let mut path = array![];
    let mut level: u64 = 0;
    let mut idx = leaf_index;
    while level < TREE_DEPTH {
        let sib = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
        path.append(tree.get_node(level, sib));
        idx = idx / 2;
        level += 1;
    }
    path.span()
}

#[test]
fn insert_updates_root_count_and_matches_naive_reference() {
    let (_, tree) = deploy_tree();

    let l0: felt252 = 0x1111;
    let l1: felt252 = 0x2222;
    let l2: felt252 = 0x3333;

    assert_eq!(ITreeWriterDispatcher { contract_address: tree.contract_address }.insert_leaf(l0), 0);
    assert_eq!(ITreeWriterDispatcher { contract_address: tree.contract_address }.insert_leaf(l1), 1);
    assert_eq!(ITreeWriterDispatcher { contract_address: tree.contract_address }.insert_leaf(l2), 2);
    assert_eq!(tree.get_leaf_count(), 3);

    let leaves = array![(0, l0), (1, l1), (2, l2)];
    let zeros = build_zeros();
    let expected = naive_root(TREE_DEPTH, 0, 0x100000000, @leaves, @zeros);
    assert_eq!(tree.get_root(), expected);

    // Every inserted leaf's assembled path must reconstruct the current root.
    let path0 = assemble_path(@tree, 0);
    assert_eq!(compute_root_from_path(l0, 0, path0), tree.get_root());
    let path1 = assemble_path(@tree, 1);
    assert_eq!(compute_root_from_path(l1, 1, path1), tree.get_root());
    let path2 = assemble_path(@tree, 2);
    assert_eq!(compute_root_from_path(l2, 2, path2), tree.get_root());
}

#[test]
#[should_panic(expected: ('ZERO_LEAF',))]
fn zero_leaf_is_rejected() {
    let (_, tree) = deploy_tree();
    ITreeWriterDispatcher { contract_address: tree.contract_address }.insert_leaf(0);
}

#[test]
fn root_history_ring_evicts_oldest() {
    let (_, tree) = deploy_tree();

    ITreeWriterDispatcher { contract_address: tree.contract_address }.insert_leaf(1);
    let root_after_first = tree.get_root();
    assert!(tree.root_is_known(root_after_first));

    // Fill the ring past capacity: ROOT_HISTORY_SIZE entries + the seeded
    // empty-tree root + slack.
    let mut i: u64 = 2;
    while i <= ROOT_HISTORY_SIZE + 5 {
        ITreeWriterDispatcher { contract_address: tree.contract_address }.insert_leaf(i.into());
        i += 1;
    }

    assert!(!tree.root_is_known(root_after_first));
    assert!(tree.root_is_known(tree.get_root()));
}

#[test]
fn first_insert_seeds_zero_chain_and_count() {
    let (_, tree) = deploy_tree();
    ITreeWriterDispatcher { contract_address: tree.contract_address }.insert_leaf(42);
    assert_eq!(tree.get_leaf_count(), 1);
    assert!(tree.get_root() != 0);
    assert!(tree.root_is_known(tree.get_root()));
}
