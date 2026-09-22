//! Compatibility oracle linked exclusively against preserved original dependencies.
use std::{fs, error::Error};
use privacy_circuit_verify::{PrivacyProofOutput, verify_recursive_circuit};
fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args().collect();
    assert_eq!(args.len(), 3, "stock PROOF PREIMAGE_JSON");
    let proof = fs::read(&args[1])?;
    let output_preimage = serde_json::from_slice(&fs::read(&args[2])?)?;
    let accepts = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        verify_recursive_circuit(&PrivacyProofOutput { proof, output_preimage }).is_ok()
    })).unwrap_or(false);
    println!("{{\"original_verifier_accepts\":{accepts}}}");
    Ok(())
}
