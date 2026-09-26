//! Device-proving spike (`../PLAN.md`), phase 1: a cost-model R0 statement account over the M31
//! pool's hashes. `hash.cairo`, `perm_compact.cairo`, `perm_unrolled.cairo` and `spend5.cairo` are
//! copied verbatim from `bench/m31-pool/cairo/src/`; `spend.cairo` is a verbatim subset of that
//! package's `spend.cairo`; `perm_qm31.cairo` is the QM31-opcode probe
//! (`bench/m31-private-wrapper/qm31-opcode/perm-unrolled-probe`) behind the same interface.
//!
//! The permutation is selected by feature: default the fully unrolled felt252 form, `compact_perm`
//! the shared-round form, `qm31_perm` native M31 arithmetic unrolled, `qm31_compact_perm` native
//! M31 arithmetic with the shared-round structure (both local capture only: U1).
pub mod account;
pub mod hash;
pub mod perm {
    #[cfg(feature: 'compact_perm')]
    pub use super::perm_compact::*;
    #[cfg(feature: 'qm31_perm')]
    pub use super::perm_qm31::*;
    #[cfg(feature: 'qm31_compact_perm')]
    pub use super::perm_qm31_compact::*;
    #[cfg(not(feature: 'compact_perm'))]
    #[cfg(not(feature: 'qm31_perm'))]
    #[cfg(not(feature: 'qm31_compact_perm'))]
    pub use super::perm_unrolled::*;
}
#[cfg(feature: 'compact_perm')]
mod perm_compact;
#[cfg(feature: 'qm31_perm')]
mod perm_qm31;
#[cfg(feature: 'qm31_compact_perm')]
mod perm_qm31_compact;
#[cfg(not(feature: 'compact_perm'))]
#[cfg(not(feature: 'qm31_perm'))]
#[cfg(not(feature: 'qm31_compact_perm'))]
mod perm_unrolled;
pub mod spend;
pub mod spend5;
pub mod statement;
