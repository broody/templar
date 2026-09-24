//! Measurement harness: prove a virtual-OS PIE through the PROOF2 large path, verify it with the
//! V2 recursive-circuit verifier, and run three rejection controls. Writes proof.bin,
//! output-preimage.json and summary.json into OUT_DIR.
use std::path::PathBuf;
use std::time::Instant;
use std::{env, fs};

use cairo_vm::vm::runners::cairo_pie::CairoPie;
use privacy_circuit_verify::{
    PrivacyProofOutput, get_large_proofs_circuit_registry, verify_recursive_circuit,
};
use privacy_prove::privacy_recursive_prove_large;
use serde_json::json;
use starknet_types_core::felt::Felt;

fn rejects(proof: Vec<u8>, output_preimage: Vec<Felt>) -> bool {
    verify_recursive_circuit(&PrivacyProofOutput { proof, output_preimage }).is_err()
}

fn main() {
    tracing_subscriber::fmt().with_max_level(tracing::Level::INFO).init();
    let args: Vec<String> = env::args().collect();
    assert_eq!(args.len(), 3, "prove_large PIE OUT_DIR");
    let out = PathBuf::from(&args[2]);
    fs::create_dir_all(&out).unwrap();

    let pie = CairoPie::read_zip_file(&PathBuf::from(&args[1])).unwrap();
    let start = Instant::now();
    let output = privacy_recursive_prove_large(pie).unwrap();
    let prove_seconds = start.elapsed().as_secs_f64();
    fs::write(out.join("proof.bin"), &output.proof).unwrap();
    fs::write(out.join("output-preimage.json"), serde_json::to_vec_pretty(&output.output_preimage).unwrap()).unwrap();

    let start = Instant::now();
    let verified = verify_recursive_circuit(&output).is_ok();
    let verify_seconds = start.elapsed().as_secs_f64();

    // Leaf verifier selected by the header's preprocessed root (bytes 3..35).
    let root: Vec<u32> = output.proof[3..35]
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
        .collect();
    let leaf_log = get_large_proofs_circuit_registry()
        .leaf_verifiers
        .iter()
        .find(|lv| lv.preprocessed_root.0.as_slice() == root.as_slice())
        .map(|lv| lv.trace_log_size);

    let mut changed_output = output.output_preimage.clone();
    *changed_output.last_mut().unwrap() += Felt::ONE;
    let mut flipped = output.proof.clone();
    let mid = 35 + (flipped.len() - 35) / 2;
    flipped[mid] ^= 1;
    let truncated = output.proof[..output.proof.len() - 1].to_vec();

    let summary = json!({
        "prove_seconds": prove_seconds,
        "verify_seconds": verify_seconds,
        "verified": verified,
        "proof_bytes": output.proof.len(),
        "gateway_max_proof_size": 480000,
        "leaf_verifier_trace_log_size": leaf_log,
        "output_preimage_len": output.output_preimage.len(),
        "rejects_changed_output": rejects(output.proof.clone(), changed_output),
        "rejects_flipped_proof_byte": rejects(flipped, output.output_preimage.clone()),
        "rejects_truncated_proof": rejects(truncated, output.output_preimage.clone()),
    });
    fs::write(out.join("summary.json"), serde_json::to_vec_pretty(&summary).unwrap()).unwrap();
    println!("{}", serde_json::to_string_pretty(&summary).unwrap());
}
