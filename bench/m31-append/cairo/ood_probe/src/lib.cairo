//! Pure evaluator differential probe, separate from proof acceptance.
use stwo_constraint_framework::LookupElementsImpl;
use stwo_verifier_core::fields::qm31::{QM31,QM31Serde};
use templar_m31_append_bridge::air::{M31Air,evaluate};
#[derive(Drop,Serde)]
pub struct OodInput {
    pub log_size: u32,
    pub claimed_sum: QM31,
    pub z: QM31,
    pub alpha: QM31,
    pub random: QM31,
    pub trace: Span<Span<QM31>>,
    pub interaction: Span<Span<QM31>>,
}
#[executable]
fn main(mut input: Span<felt252>) -> QM31 {
    let values: OodInput=Serde::deserialize(ref input).expect('OOD_ENCODING');
    assert(input.is_empty(),'OOD_TRAILING');
    let air=M31Air {log_size:values.log_size,claimed_sum:values.claimed_sum,lookup:LookupElementsImpl::from_z_alpha(values.z,values.alpha)};
    evaluate(@air,values.trace,values.interaction,values.random)
}
