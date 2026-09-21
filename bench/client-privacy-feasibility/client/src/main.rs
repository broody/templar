//! Synthetic local-only checkpoint harness. Not a custom membership/privacy construction.
use std::error::Error;
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::Instant;

use bincode::Options;
use cairo_vm::vm::runners::cairo_pie::CairoPie;
use privacy_circuit_verify::{PrivacyProofOutput, verify_recursive_circuit};
use privacy_prove::{
    LowMemoryOptions, SyntheticCairoCheckpoint, prepare_synthetic_cairo_checkpoint,
    privacy_recursive_prove_low_memory, wrap_synthetic_cairo_checkpoint,
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use starknet_types_core::felt::Felt;

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const CHECKPOINT_MAGIC: &[u8] = b"TEMPLAR_SYNTHETIC_LOCAL_CAIRO_CHECKPOINT_V1\0";

fn options() -> LowMemoryOptions {
    LowMemoryOptions {
        cache_cairo_coefficients: true,
        recompute_cairo_commitments: true,
        bounded_cairo_columns: Some(16),
        bounded_circuit_columns: Some(16),
    }
}

fn private_new(path: &Path) -> Result<File> {
    Ok(OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?)
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut file = BufWriter::new(private_new(path)?);
    serde_json::to_writer_pretty(&mut file, value)?;
    file.write_all(b"\n")?;
    file.flush()?;
    Ok(())
}

fn decode_checkpoint<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    let body = bytes.strip_prefix(CHECKPOINT_MAGIC).ok_or("Wrong checkpoint format")?;
    // Fixed-int matches the encoder. Slice decoding rejects trailing bytes as well as truncation.
    Ok(bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .deserialize(body)?)
}

fn write_checkpoint(path: &Path, checkpoint: &SyntheticCairoCheckpoint) -> Result<()> {
    let mut file = BufWriter::new(private_new(path)?);
    file.write_all(CHECKPOINT_MAGIC)?;
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .serialize_into(&mut file, checkpoint)?;
    file.flush()?;
    Ok(())
}

fn read_checkpoint(path: &Path) -> Result<SyntheticCairoCheckpoint> {
    let bytes = fs::read(path)?;
    decode_checkpoint(&bytes)
}

fn write_proof(dir: &Path, output: &PrivacyProofOutput) -> Result<()> {
    let mut file = private_new(&dir.join("proof.bin"))?;
    file.write_all(&output.proof)?;
    write_json(&dir.join("output-preimage.json"), &output.output_preimage)?;
    Ok(())
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn configuration() -> Value {
    use privacy_circuit_verify::consts::*;
    json!({
        "scope": "unchanged fixed Cairo wrapper; synthetic local fixture only",
        "privacy_qualified_by_measurement": false,
        "bounded_cairo_columns": 16,
        "bounded_circuit_columns": 16,
        "cairo_pcs_config": CAIRO_PCS_CONFIG,
        "circuit_pcs_config": CIRCUIT_PCS_CONFIG,
        "cairo_interaction_pow_bits": 24,
        "circuit_interaction_pow_bits": 20,
        "channel": "Blake2sM31",
        "blinding_policy": "unchanged inner witness commitment seed and outer query count",
        "circuit_output_addresses": CIRCUIT_OUTPUT_ADDRESSES,
        "trusted_circuit_preprocessed_root": PRIVACY_RECURSION_CIRCUIT_PREPROCESSED_ROOT,
        "checkpoint": "local typed CairoProof with auxiliary data and matching output preimage; no config authority"
    })
}

fn main() -> Result<()> {
    let process_start = Instant::now();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env()
            .add_directive("info".parse()?))
        .with_ansi(false)
        .with_timer(tracing_subscriber::fmt::time::uptime())
        .init();
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        return Err("Usage: templar-client-privacy-feasibility prepare <synthetic-pie.zip> <fresh-output-dir> | wrap <checkpoint.bin> <fresh-output-dir> | unsplit <synthetic-pie.zip> <fresh-output-dir> | verify <proof.bin> <output-preimage.json>".into());
    }
    let mode = args[1].as_str();
    let input = Path::new(&args[2]);
    if mode == "verify" {
        let proof = fs::read(input)?;
        let output_preimage: Vec<Felt> = serde_json::from_slice(&fs::read(&args[3])?)?;
        let mut output = PrivacyProofOutput { proof, output_preimage };
        verify_recursive_circuit(&output)?;
        let last = output.output_preimage.last_mut().ok_or("Empty output preimage")?;
        *last += Felt::ONE;
        if verify_recursive_circuit(&output).is_ok() {
            return Err("Changed public output was accepted".into());
        }
        println!("{}", json!({"native_verifier_accepted": true, "changed_public_output_rejected": true,
            "full_elapsed_seconds": process_start.elapsed().as_secs_f64()}));
        return Ok(());
    }
    if !matches!(mode, "prepare" | "wrap" | "unsplit") {
        return Err("Unknown mode".into());
    }
    let out = Path::new(&args[3]);
    fs::create_dir(out)?;
    let mut summary = configuration();
    summary["mode"] = json!(mode);
    summary["input_bytes"] = json!(fs::metadata(input)?.len());
    let load_start = Instant::now();
    if mode == "prepare" {
        let pie = CairoPie::read_zip_file(input)?;
        summary["load_seconds"] = json!(load_start.elapsed().as_secs_f64());
        let stage_start = Instant::now();
        let checkpoint = prepare_synthetic_cairo_checkpoint(pie, options())?;
        summary["prepare_seconds"] = json!(stage_start.elapsed().as_secs_f64());
        let write_start = Instant::now();
        write_checkpoint(&out.join("checkpoint.bin"), &checkpoint)?;
        write_json(&out.join("output-preimage.json"), &checkpoint.output_preimage)?;
        summary["checkpoint_bytes"] = json!(fs::metadata(out.join("checkpoint.bin"))?.len());
        summary["write_seconds"] = json!(write_start.elapsed().as_secs_f64());
    } else {
        let output = if mode == "wrap" {
            let checkpoint = read_checkpoint(input)?;
            summary["load_seconds"] = json!(load_start.elapsed().as_secs_f64());
            let stage_start = Instant::now();
            let output = wrap_synthetic_cairo_checkpoint(checkpoint, options())?;
            summary["wrapper_seconds"] = json!(stage_start.elapsed().as_secs_f64());
            output
        } else {
            let pie = CairoPie::read_zip_file(input)?;
            summary["load_seconds"] = json!(load_start.elapsed().as_secs_f64());
            let stage_start = Instant::now();
            let output = privacy_recursive_prove_low_memory(pie, options())?;
            summary["unsplit_seconds"] = json!(stage_start.elapsed().as_secs_f64());
            output
        };
        let write_start = Instant::now();
        write_proof(out, &output)?;
        summary["write_seconds"] = json!(write_start.elapsed().as_secs_f64());
        summary["proof_bytes"] = json!(output.proof.len());
        summary["proof_sha256"] = json!(sha256(&output.proof));
        summary["output_preimage_felts"] = json!(output.output_preimage.len());
        summary["verification"] = json!("separate verify command, excluded from proving measurement");
    }
    // Includes reading input, all stage allocations and writing proof/checkpoint files.
    // External process accounting also includes summary writing and process teardown.
    summary["elapsed_through_artifact_write_seconds"] = json!(process_start.elapsed().as_secs_f64());
    write_json(&out.join("summary.json"), &summary)?;
    println!("{}", summary);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<u8> {
        let mut bytes = CHECKPOINT_MAGIC.to_vec();
        bincode::DefaultOptions::new().with_fixint_encoding()
            .serialize_into(&mut bytes, &vec![3_u64, 7, 11]).unwrap();
        bytes
    }

    #[test]
    fn checkpoint_roundtrip() {
        assert_eq!(decode_checkpoint::<Vec<u64>>(&sample()).unwrap(), vec![3, 7, 11]);
    }

    #[test]
    fn checkpoint_rejects_trailing_and_truncated_data() {
        let mut bytes = sample();
        bytes.push(0);
        assert!(decode_checkpoint::<Vec<u64>>(&bytes).is_err());
        bytes.truncate(bytes.len() - 2);
        assert!(decode_checkpoint::<Vec<u64>>(&bytes).is_err());
    }

    #[test]
    fn checkpoint_rejects_wrong_format() {
        let mut bytes = sample();
        bytes[0] ^= 1;
        assert!(decode_checkpoint::<Vec<u64>>(&bytes).is_err());
    }
}
