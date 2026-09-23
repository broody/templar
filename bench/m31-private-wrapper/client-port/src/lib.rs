//! In-circuit verifier for the frozen TMPZK002 Blake private-membership proof.
/// Native oracle: the complete unchanged client (prover + verifier) on its original stwo pin.
/// Only used to cross-check acceptance; statements cross over as JSON.
pub use templar_private_membership as oracle;
// The client's reviewed AIR, permutation and constants, compiled unchanged against the
// circuit's stwo. `air.rs` refers to `crate::hash` and `crate::constants`.
#[path = "../../../m31-private-blake/client/src/air.rs"]
pub mod air;

/// Native acceptance by the unchanged client verifier; the statement crosses as JSON.
pub fn oracle_verify(public: &air::Public, proof: &[u8]) -> anyhow::Result<()> {
    let public: oracle::air::Public = serde_json::from_value(serde_json::to_value(public)?)?;
    oracle::verify(&public, proof)
}
pub mod ro;
pub mod transcript;
pub mod native;
pub mod merkle;
pub mod domain;
pub mod sym;
pub mod ood;
pub mod verify;
pub mod aligned;
#[allow(dead_code)]
#[path = "../../../m31-private-blake/client/src/constants.rs"]
mod constants;
#[allow(dead_code)]
#[path = "../../../m31-private-blake/client/src/hash.rs"]
pub mod hash;
pub mod membership;
pub mod payment;
