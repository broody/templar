//! Focused regression tests for the isolated empty-preprocessing compatibility case.
use core::box::BoxImpl;
use stwo_verifier_core::fields::m31::M31;
use stwo_verifier_core::vcs::MerkleHasher;
use stwo_verifier_core::vcs::blake2s_hasher::Blake2sHash;
use stwo_verifier_core::vcs::verifier::{MerkleVerifier,MerkleVerifierTrait,MerkleDecommitment};
fn run_empty(root: Blake2sHash,columns: Span<u32>,queries: Span<u32>,values: Span<M31>,witness: Span<Blake2sHash>) {
    let tree=MerkleVerifier::<MerkleHasher> {root,tree_height:0,column_log_deg_bounds:columns};
    tree.verify(queries,values,MerkleDecommitment::<MerkleHasher> {hash_witness:witness});
}
fn empty_root() -> Blake2sHash { MerkleHasher::hash_node(None,[].span()) }
#[test]
fn empty_tree_accepts_exact_shape() { run_empty(empty_root(),[].span(),[].span(),[].span(),[].span()); }
#[test]
#[should_panic]
fn empty_tree_rejects_wrong_root() {
    run_empty(Blake2sHash {hash:BoxImpl::new([0_u32;8])},[].span(),[].span(),[].span(),[].span());
}
#[test]
#[should_panic]
fn empty_tree_rejects_columns() { run_empty(empty_root(),[8].span(),[].span(),[].span(),[].span()); }
#[test]
#[should_panic]
fn empty_tree_rejects_queries() { run_empty(empty_root(),[].span(),[0].span(),[].span(),[].span()); }
#[test]
#[should_panic]
fn empty_tree_rejects_values() { run_empty(empty_root(),[].span(),[].span(),[0_u32.try_into().unwrap()].span(),[].span()); }
#[test]
#[should_panic]
fn empty_tree_rejects_witness() { run_empty(empty_root(),[].span(),[].span(),[].span(),[empty_root()].span()); }

#[test]
fn empty_root_matches_pinned_native_full_blake2s() {
    // Native ordinary Blake2s default().finalize(), independently checked with hashlib.
    assert_eq!(empty_root().hash.unbox(), [813310313, 2491453561, 3491828193, 2085238082, 1219908895, 514171180, 4245497115, 4193177630]);
}
