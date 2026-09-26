//! `templar-prove prove JOB_DIR`: prove `JOB_DIR/os.pie.zip` through the large-proof path with
//! bounded-memory storage, verify the proof with the recursive-circuit verifier, and write
//! `proof.bin`, `output-preimage.json` and `prove-result.json` (prover-server spec §5.5). The
//! result names the proof header's leaf bucket: the Cairo trace log size whose leaf verifier the
//! header's preprocessed root belongs to.
//!
//! `templar-prove bucket JOB_DIR`: the bucket check before proving (docs/pool-v3-spec.md §9.3). It
//! runs the leaf bootloader on the PIE and writes the base trace only, as proving does, and writes
//! `bucket.json`: the enabled components' log sizes and the leaf trace log size,
//! `max(25, largest column log size)`, computed as the Cairo prover computes its trace domain. The header of the PROOF2 proof maps one-to-one to that size, so
//! every job the server proves must land in the pinned bucket. No commitments, FRI or circuit.
//!
//! `templar-prove header PROOF_BIN`: the leaf bucket a proof's header names.
//!
//! Bounded-memory settings come from `JOB_DIR/prove-job.json`: `{cairo_fri_columns,
//! circuit_fri_columns, stream_commitments}` (defaults 16, 16, false: whole-tree commitments,
//! ~28 GiB). Runs without network access (the caller puts it in an empty network namespace).
use std::path::Path;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{bail, Context, Result};
use cairo_program_runner_lib::types::{HashFunc, PrivacySimpleBootloaderInput, SimpleBootloaderInput};
use cairo_program_runner_lib::utils::get_cairo_run_config;
use cairo_program_runner_lib::{cairo_run_program, ProgramInput, Task, TaskSpec};
use cairo_vm::types::layout_name::LayoutName;
use cairo_vm::vm::runners::cairo_pie::CairoPie;
use leaf_prover::prove_leaf::BoundedMemory;
use privacy_circuit_verify::{get_large_proofs_circuit_registry, get_leaf_bootloader_program, verify_recursive_circuit};
use privacy_prove::privacy_recursive_prove_large_bounded;
use serde_json::{json, Value};
use stwo_cairo_adapter::adapter::adapt;
use stwo_cairo_prover::prover::warm_pedersen_pp_trace;
use stwo_cairo_prover::witness::cairo::create_cairo_claim_generator;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("prove") if args.len() == 3 => prove(Path::new(&args[2])),
        Some("bucket") if args.len() == 3 => bucket(Path::new(&args[2])),
        Some("header") if args.len() == 3 => {
            let proof = std::fs::read(&args[2]).context("reading the proof")?;
            println!("{}", json!({"leaf_trace_log_size": header_bucket(&proof)}));
            Ok(())
        }
        Some("version") => {
            println!("{}", json!({"binary": "templar-prove", "version": env!("CARGO_PKG_VERSION"),
                                 "proving": "broody/proving@b54ed94f832e4e3537aec783101582cfcd632659"}));
            Ok(())
        }
        _ => bail!("usage: templar-prove prove JOB_DIR | bucket JOB_DIR | header PROOF_BIN | version"),
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
        "leaf_trace_log_size": header_bucket(&output.proof),
        "bounded": {"cairo_fri_columns": bounded.cairo_fri_columns, "circuit_fri_columns": bounded.circuit_fri_columns,
                    "stream_commitments": bounded.stream_commitments},
    });
    std::fs::write(dir.join("prove-result.json"), serde_json::to_vec_pretty(&result)?)?;
    Ok(())
}

/// The leaf bucket a PROOF2 proof's header names: the trace log size of the registry leaf verifier
/// whose preprocessed root follows the 3-byte version (`None` if no entry matches).
fn header_bucket(proof: &[u8]) -> Option<u32> {
    let root = proof.get(3..35)?;
    get_large_proofs_circuit_registry().leaf_verifiers.iter().find_map(|leaf| {
        let bytes: Vec<u8> = leaf.preprocessed_root.0.iter().flat_map(|w| w.to_le_bytes()).collect();
        (bytes == root).then_some(leaf.trace_log_size)
    })
}

fn bucket(dir: &Path) -> Result<()> {
    let start = Instant::now();
    let pie = CairoPie::read_zip_file(&dir.join("os.pie.zip")).context("reading the PIE")?;
    let registry = get_large_proofs_circuit_registry();
    let params = registry.cairo_prover_params;
    // The leaf bootloader's run, exactly as `privacy_recursive_prove_large_bounded` makes it.
    let program = get_leaf_bootloader_program().map_err(|e| anyhow::anyhow!("the leaf bootloader: {e}"))?;
    let input = PrivacySimpleBootloaderInput {
        simple_bootloader_input: SimpleBootloaderInput {
            fact_topologies_path: None,
            single_page: true,
            tasks: vec![TaskSpec { task: Rc::new(Task::Pie(pie)), program_hash_function: HashFunc::Blake }],
        },
        output_preimage_dump_path: dir.join("bucket-output-preimage.json"),
    };
    let config = get_cairo_run_config(&None, LayoutName::all_cairo_stwo, true, true, true, false)
        .map_err(|e| anyhow::anyhow!("run config: {e:?}"))?;
    let runner = cairo_run_program(&program, Some(ProgramInput::Value(Box::new(input))), config, None)
        .map_err(|e| anyhow::anyhow!("the leaf bootloader run: {e:?}"))?;
    let steps = runner.vm.get_current_step();
    let input = adapt(&runner).map_err(|e| anyhow::anyhow!("adapter: {e:?}"))?;
    drop(runner);
    // The base trace, as the Cairo prover writes it; its claim fixes every component's log size.
    warm_pedersen_pp_trace(params.preprocessed_trace);
    let generator = create_cairo_claim_generator(input, Arc::new(params.preprocessed_trace.to_preprocessed_trace()));
    let (_trace, claim, _interaction) = generator.write_trace(params.opt_n_id_to_big_components);
    // The largest column log size, exactly as `prove_cairo_bounded` computes the trace domain.
    let largest = claim.log_sizes().iter().flatten().copied().max().context("no component")?;
    // The flat claim lists the enabled components only, one bit per possible component.
    let flat = claim.flatten_claim();
    let enabled = flat.component_enable_bits.iter().filter(|b| **b).count();
    if flat.component_log_sizes.len() != enabled {
        bail!("{} component sizes for {enabled} enabled components", flat.component_log_sizes.len());
    }
    if flat.component_log_sizes.iter().copied().max() != Some(largest) {
        bail!("the flat claim's largest size differs from the trace's");
    }
    let trace_log_size = largest.max(params.preprocessed_trace.max_log_trace_size());
    let supported = registry.leaf_verifier(trace_log_size).is_ok();
    let result = json!({
        "trace_log_size": trace_log_size, "largest_component_log_size": largest, "supported": supported,
        "enabled_component_log_sizes": flat.component_log_sizes, "component_enable_bits": flat.component_enable_bits,
        "leaf_bootloader_steps": steps, "seconds": start.elapsed().as_secs_f64(),
    });
    let _ = std::fs::remove_file(dir.join("bucket-output-preimage.json"));
    std::fs::write(dir.join("bucket.json"), serde_json::to_vec_pretty(&result)?)?;
    Ok(())
}
