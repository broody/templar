//! `templar-prove prove JOB_DIR`: prove `JOB_DIR/os.pie.zip` through the large-proof path with
//! bounded-memory storage, verify the proof with the recursive-circuit verifier, and write
//! `proof.bin`, `output-preimage.json` and `prove-result.json` (prover-server spec §5.5).
//!
//! Bounded-memory settings come from `JOB_DIR/prove-job.json`: `{cairo_fri_columns,
//! circuit_fri_columns, stream_commitments}` (defaults 16, 16, false: whole-tree commitments,
//! ~28 GiB). Runs without network access (the caller puts it in an empty network namespace).
use std::path::Path;
use std::time::Instant;

use anyhow::{bail, Context, Result};
use cairo_vm::vm::runners::cairo_pie::CairoPie;
use leaf_prover::prove_leaf::BoundedMemory;
use privacy_circuit_verify::verify_recursive_circuit;
use privacy_prove::privacy_recursive_prove_large_bounded;
use serde_json::{json, Value};

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("prove") if args.len() == 3 => prove(Path::new(&args[2])),
        Some("version") => {
            println!("{}", json!({"binary": "templar-prove", "version": env!("CARGO_PKG_VERSION"),
                                 "proving": "broody/proving@b54ed94f832e4e3537aec783101582cfcd632659"}));
            Ok(())
        }
        _ => bail!("usage: templar-prove prove JOB_DIR | version"),
    }
}

fn prove(dir: &Path) -> Result<()> {
    let job: Value = std::fs::read(dir.join("prove-job.json"))
        .ok()
        .map(|b| serde_json::from_slice(&b))
        .transpose()
        .context("parsing prove-job.json")?
        .unwrap_or(json!({}));
    let columns = |key: &str| job[key].as_u64().map(|n| n as usize).or(Some(16)).filter(|n| *n > 0);
    let bounded = BoundedMemory {
        cairo_fri_columns: columns("cairo_fri_columns"),
        circuit_fri_columns: columns("circuit_fri_columns"),
        stream_commitments: job["stream_commitments"].as_bool().unwrap_or(false),
    };
    let pie = CairoPie::read_zip_file(&dir.join("os.pie.zip")).context("reading the PIE")?;
    let start = Instant::now();
    let output = privacy_recursive_prove_large_bounded(pie, bounded).map_err(|e| anyhow::anyhow!("proving: {e:?}"))?;
    let prove_seconds = start.elapsed().as_secs_f64();
    let start = Instant::now();
    let verified = verify_recursive_circuit(&output).is_ok();
    let verify_seconds = start.elapsed().as_secs_f64();
    if !verified {
        bail!("the large proof does not verify");
    }
    std::fs::write(dir.join("proof.bin"), &output.proof)?;
    std::fs::write(dir.join("output-preimage.json"), serde_json::to_vec_pretty(&output.output_preimage)?)?;
    let result = json!({
        "prove_seconds": prove_seconds, "verify_seconds": verify_seconds, "verified": verified,
        "proof_bytes": output.proof.len(),
        "bounded": {"cairo_fri_columns": bounded.cairo_fri_columns, "circuit_fri_columns": bounded.circuit_fri_columns,
                    "stream_commitments": bounded.stream_commitments},
    });
    std::fs::write(dir.join("prove-result.json"), serde_json::to_vec_pretty(&result)?)?;
    Ok(())
}
