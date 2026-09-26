//! Option A of the tree strategy, for measurement: the pool appends outputs to an on-chain
//! Poseidon2-M31 note tree (the R0 client's tree) instead of the felt252 tree. The pool mirrors
//! the reference ordinary pool (`controlled-push-e2e/cairo/src/pool.cairo`): same guards, root
//! history, nullifier set, delivery digests and events, with the R0 statement and binding.
pub mod adapter;
pub mod assets;
pub mod hash;
/// Default: the fully unrolled permutation (cheapest to run). Feature `compact_perm`: shared round
/// code, half the pool's declaration cost for about 4.5% more gas per call.
pub mod perm {
    #[cfg(feature: 'compact_perm')]
    pub use super::perm_compact::*;
    #[cfg(not(feature: 'compact_perm'))]
    pub use super::perm_unrolled::*;
}
#[cfg(feature: 'compact_perm')]
mod perm_compact;
#[cfg(not(feature: 'compact_perm'))]
mod perm_unrolled;
pub mod open_note;
pub mod policy;
pub mod policy_escrow;
pub mod pool;
pub mod pool_v2;
pub mod pool_v3;
pub mod spend;
pub mod spend4;
pub mod spend5;
pub mod test_adapters;
pub mod test_nft;
pub mod test_policy_controllers;
pub mod test_token;
pub mod tree;
pub mod tree_v3;
pub mod zeros;
#[cfg(test)]
mod tests;
