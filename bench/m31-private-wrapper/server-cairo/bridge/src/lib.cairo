//! Public server hash circuit compatibility probe. No private note or key is accepted by this API.
//!
//! The vendored verifier pins its circuit topology, preprocessed root, full PCS config,
//! and output count. Build-time constants must be generated from a reviewed client manifest.
use stwo_circuit_air::{CircuitProof, VerificationOutput, get_verification_output, verify_circuit};



/// Decode exactly one proof. Successful verification returns a digest binding the compiled
/// preprocessed root and the proof's public output values.
pub fn verify_serialized(mut proof_data: Span<felt252>) -> VerificationOutput {
    let proof: CircuitProof = Serde::deserialize(ref proof_data).expect('INVALID_PROOF_ENCODING');
    assert!(proof_data.is_empty(), "trailing proof data");
    let output = get_verification_output(@proof);
    verify_circuit(proof);
    output
}

#[executable]
fn main(proof_data: Span<felt252>) -> VerificationOutput {
    verify_serialized(proof_data)
}
