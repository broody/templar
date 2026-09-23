//! Option A of the tree strategy, for measurement: the pool appends outputs to an on-chain
//! Poseidon2-M31 note tree (the R0 client's tree) instead of the felt252 tree. The pool mirrors
//! the reference ordinary pool (`controlled-push-e2e/cairo/src/pool.cairo`): same guards, root
//! history, nullifier set, delivery digests and events, with the R0 statement and binding.
pub mod hash;
pub mod perm;
pub mod pool;
pub mod spend;
pub mod test_token;
pub mod tree;
pub mod zeros;
#[cfg(test)]
mod tests;
