//! Device-proving spike, V2 small (log20) privacy path. No network, no chain.
//!
//! - `prove-small trace PIE OUT`: privacy bootloader + adapter + claim generation, no proof.
//!   Writes `boot.json` (steps, opcode counts, builtin instances, Blake/QM31 opcode counts),
//!   `claim.json` (every component's claim, including `memory_id_to_big`) and `small-path.json`
//!   (the fixed small-path component list and trace log size, for the acceptance check).
//! - `prove-small cairo-only PIE OUT`: the Cairo stage alone, as `privacy_prove` does it (the
//!   privacy bootloader, `prove_cairo` with `CAIRO_PROVER_PARAMS`, the circuit-verifier
//!   serialization), kind `cairo`. After proving it also verifies the proof natively with the
//!   generic Rust verifier (`verify_cairo_ex`) and checks a one-byte change of the interaction PoW is
//!   rejected: this works for any component set, including the QM31 opcode's.
//! - `prove-small recursive PIE OUT`: the full small recursive proof (`privacy_recursive_prove`
//!   with its precomputes), kind `recursive`.
//! - `prove-small recursion CAIRO_DIR OUT`: the recursion stage alone in a fresh process, from a
//!   `cairo-only` output: deserialize with the fixed small-path config (as `verify_cairo` does),
//!   build and check the Cairo-verifier circuit, prove it with circuit-only precomputes, as
//!   `privacy_recursive_prove` does. Kind `recursive`; the proof must equal `recursive`'s.
//! - `prove-small verify OUT`: verifies `OUT/proof.bin` with the matching V2 verifier and checks
//!   that a changed output, a flipped proof byte and a truncated proof are rejected.
use std::error::Error;
use std::fs;
use std::path::Path;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Instant;

use cairo_air::CairoProofForRustVerifier;
use cairo_air::flat_claims::FlatClaim;
use cairo_air::verifier::verify_cairo_ex;
use cairo_program_runner_lib::types::{HashFunc, PrivacySimpleBootloaderInput, SimpleBootloaderInput};
use circuit_cairo_verifier::statement::AUX_DATA_FIXED_LEN;
use circuit_cairo_verifier::verify::{build_and_fill_cairo_verifier_circuit, prepare_cairo_proof_for_circuit_verifier};
use circuit_common::finalize::pad_context;
use circuit_prover::prover::{prepare_circuit_proof_for_circuit_verifier, prove_circuit_with_precompute};
use circuit_serialize::deserialize::deserialize_proof_with_config;
use circuit_serialize::serialize::CircuitSerialize;
use circuits::utils::bytes_from_le_u32s;
use cairo_program_runner_lib::{ProgramInput, Task, TaskSpec, cairo_run_program};
use cairo_vm::vm::runners::cairo_pie::CairoPie;
use privacy_circuit_verify::consts::{
    CAIRO_TRACE_LOG_SIZE, CIRCUIT_FRI_CONFIG, CIRCUIT_PCS_CONFIG, MAX_CAIRO_PROOF_UNCOMPRESSED_BYTES,
    PRIVACY_RECURSION_CIRCUIT_PREPROCESSED_ROOT, PRIVACY_TRANSACTION_COMPONENTS,
};
use privacy_circuit_verify::utils::ProofHeader;
use privacy_circuit_verify::{
    PrivacyProofOutput, Version, compute_privacy_bootloader_output_hash, get_cairo_preprocessed_circuit,
    get_cairo_verifier_config, get_privacy_bootloader_program, get_recursive_circuit_config, verify_cairo,
    verify_recursive_circuit,
};
use privacy_prove::consts::{CAIRO_PROVER_PARAMS, CAIRO_RUN_CONFIG, CIRCUIT_STORE_POLYNOMIALS_COEFFICIENTS};
use privacy_prove::{prepare_recursive_prover_precomputes, privacy_recursive_prove};
use serde_json::{Value, json};
use starknet_types_core::felt::Felt;
use stwo::core::fields::m31::M31;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::utils::MaybeOwned;
use stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleChannel;
use stwo::prover::CommitmentTreeProver;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::mempool::BaseColumnPool;
use stwo::prover::poly::circle::PolyOps;
use stwo_cairo_adapter::ProverInput;
use stwo_cairo_adapter::adapter::adapt;
use stwo_cairo_prover::prover::prove_cairo;
use stwo_cairo_prover::witness::cairo::create_cairo_claim_generator;
use tracing::info;
use tempfile::NamedTempFile;
use tracing_subscriber::fmt::format::FmtSpan;

type Res<T> = Result<T, Box<dyn Error>>;

fn save(path: &Path, value: &Value) -> Res<()> {
    fs::write(path, serde_json::to_vec_pretty(value)?)?;
    Ok(())
}

fn read_pie(path: &str) -> Res<CairoPie> {
    Ok(CairoPie::read_zip_file(Path::new(path))?)
}

/// The privacy bootloader over the PIE, as `privacy_prove` runs it: the prover input, the output
/// preimage, and the run's step and builtin counts.
fn boot(pie: CairoPie) -> Res<(ProverInput, Vec<Felt>, Value, f64)> {
    let start = Instant::now();
    info!("Run privacy bootloader and get the prover input and output preimage");
    let temp = NamedTempFile::new()?;
    let input = PrivacySimpleBootloaderInput {
        simple_bootloader_input: SimpleBootloaderInput {
            fact_topologies_path: None,
            single_page: true,
            tasks: vec![TaskSpec { task: Rc::new(Task::Pie(pie)), program_hash_function: HashFunc::Blake }],
        },
        output_preimage_dump_path: temp.path().to_path_buf(),
    };
    let runner = cairo_run_program(
        &get_privacy_bootloader_program()?,
        Some(ProgramInput::Value(Box::new(input))),
        CAIRO_RUN_CONFIG,
        None,
    )?;
    let resources = runner.get_execution_resources()?;
    let preimage: Vec<Felt> = serde_json::from_slice(&fs::read(temp.path())?)?;
    let input = adapt(&runner)?;
    drop(runner);
    let res = json!({
        "n_steps": resources.n_steps,
        "n_memory_holes": resources.n_memory_holes,
        "builtin_instance_counter": resources.builtin_instance_counter.iter()
            .map(|(k, v)| (k.to_string(), json!(v))).collect::<serde_json::Map<_, _>>(),
    });
    Ok((input, preimage, res, start.elapsed().as_secs_f64()))
}

fn trace(pie: CairoPie, out: &Path) -> Res<()> {
    let (input, preimage, resources, run_seconds) = boot(pie)?;
    let s = &input.state_transitions.casm_states_by_opcode;
    let opcodes = json!({
        "generic_opcode": s.generic_opcode.len(), "add_ap_opcode": s.add_ap_opcode.len(),
        "add_opcode": s.add_opcode.len(), "add_opcode_small": s.add_opcode_small.len(),
        "assert_eq_opcode": s.assert_eq_opcode.len(),
        "assert_eq_opcode_double_deref": s.assert_eq_opcode_double_deref.len(),
        "assert_eq_opcode_imm": s.assert_eq_opcode_imm.len(), "call_opcode_abs": s.call_opcode_abs.len(),
        "call_opcode_rel_imm": s.call_opcode_rel_imm.len(), "jnz_opcode_non_taken": s.jnz_opcode_non_taken.len(),
        "jnz_opcode_taken": s.jnz_opcode_taken.len(), "jump_opcode_rel_imm": s.jump_opcode_rel_imm.len(),
        "jump_opcode_rel": s.jump_opcode_rel.len(), "jump_opcode_double_deref": s.jump_opcode_double_deref.len(),
        "jump_opcode_abs": s.jump_opcode_abs.len(), "mul_opcode_small": s.mul_opcode_small.len(),
        "mul_opcode": s.mul_opcode.len(), "ret_opcode": s.ret_opcode.len(),
        "blake_compress_opcode": s.blake_compress_opcode.len(),
        "qm_31_add_mul_opcode": s.qm_31_add_mul_opcode.len(),
    });
    let builtins: serde_json::Map<String, Value> = input
        .builtin_segments
        .get_counts()
        .into_iter()
        .map(|(name, count)| (format!("{name:?}"), json!(count)))
        .collect();
    save(&out.join("boot.json"), &json!({
        "scope": "privacy bootloader over the PIE (V2 small path, proving@2b495a3 + bounded patches)",
        "bootloader_run_seconds": run_seconds,
        "n_steps": resources["n_steps"],
        "n_memory_holes": resources["n_memory_holes"],
        "builtin_instance_counter": resources["builtin_instance_counter"],
        "adapter_builtin_instances": builtins,
        "opcode_rows": opcodes,
        "pc_count": input.pc_count,
        // Actual rows behind the memory components' padded log sizes.
        "memory": {"addresses": input.memory.address_to_id.len(),
                   "small_values": input.memory.small_values.len(),
                   "f252_values": input.memory.f252_values.len()},
        "output_preimage_len": preimage.len(),
    }))?;
    let start = Instant::now();
    let generator = create_cairo_claim_generator(
        input,
        Arc::new(CAIRO_PROVER_PARAMS.preprocessed_trace.to_preprocessed_trace()),
    );
    let (base, claim, interaction) = generator.write_trace(CAIRO_PROVER_PARAMS.opt_n_id_to_big_components);
    let columns = base.len();
    // Base trace cells: every committed base column's rows (its domain size).
    let mut by_log: std::collections::BTreeMap<u32, usize> = Default::default();
    for column in &base {
        *by_log.entry(column.domain.log_size()).or_default() += 1;
    }
    let base_cells: u64 = by_log.iter().map(|(log, n)| (*n as u64) << log).sum();
    drop((base, interaction));
    save(&out.join("claim.json"), &serde_json::to_value(&claim)?)?;
    save(&out.join("small-path.json"), &json!({
        "cairo_trace_log_size": CAIRO_TRACE_LOG_SIZE,
        "privacy_transaction_components": PRIVACY_TRANSACTION_COMPONENTS.to_vec(),
        "base_trace_columns": columns,
        "base_trace_cells": base_cells,
        "base_columns_by_log_size": by_log.iter().map(|(k, v)| (k.to_string(), json!(v))).collect::<serde_json::Map<_, _>>(),
        "write_trace_seconds": start.elapsed().as_secs_f64(),
    }))?;
    Ok(())
}

fn write_output(out: &Path, output: &PrivacyProofOutput, kind: &str, extra: Value) -> Res<()> {
    fs::write(out.join("proof.bin"), &output.proof)?;
    save(&out.join("output-preimage.json"), &serde_json::to_value(&output.output_preimage)?)?;
    let mut summary = json!({"kind": kind, "proof_bytes": output.proof.len()});
    summary.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
    save(&out.join("summary.json"), &summary)
}

fn verify(out: &Path) -> Res<()> {
    let summary: Value = serde_json::from_slice(&fs::read(out.join("summary.json"))?)?;
    let kind = summary["kind"].as_str().ok_or("summary.kind")?.to_string();
    let proof = fs::read(out.join("proof.bin"))?;
    let output_preimage: Vec<Felt> = serde_json::from_slice(&fs::read(out.join("output-preimage.json"))?)?;
    let check = |proof: Vec<u8>, output_preimage: Vec<Felt>| -> Result<(), String> {
        let output = PrivacyProofOutput { proof, output_preimage };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if kind == "cairo" { verify_cairo(&output).map_err(|e| e.to_string()) }
            else { verify_recursive_circuit(&output).map_err(|e| e.to_string()) }
        }));
        result.unwrap_or_else(|_| Err("verifier panicked".to_string()))
    };
    let start = Instant::now();
    let valid = check(proof.clone(), output_preimage.clone());
    let verify_seconds = start.elapsed().as_secs_f64();
    let mut changed = output_preimage.clone();
    *changed.last_mut().ok_or("empty output")? += Felt::ONE;
    let mut flipped = proof.clone();
    let mid = 35 + (flipped.len() - 35) / 2;
    flipped[mid] ^= 1;
    let truncated = proof[..proof.len() - 1].to_vec();
    let controls = json!({
        "changed_output_rejected": check(proof.clone(), changed).is_err(),
        "flipped_byte_rejected": check(flipped, output_preimage.clone()).is_err(),
        "truncated_rejected": check(truncated, output_preimage).is_err(),
    });
    let passed = valid.is_ok() && controls.as_object().unwrap().values().all(|v| v == &json!(true));
    save(&out.join("verify.json"), &json!({
        "kind": kind, "valid": valid.is_ok(), "error": valid.err(), "verify_seconds": verify_seconds,
        "controls": controls, "passed": passed,
    }))?;
    if !passed {
        return Err("verification or a rejection control failed".into());
    }
    Ok(())
}

fn with_header(uncompressed: &[u8]) -> Res<Vec<u8>> {
    let header = ProofHeader {
        version: Version::current(),
        preprocessed_root: bytes_from_le_u32s(PRIVACY_RECURSION_CIRCUIT_PREPROCESSED_ROOT),
    };
    Ok(header.serialize().into_iter().chain(zstd::encode_all(uncompressed, 3)?).collect())
}

/// `privacy_prove` step by step, then a native verification of the Cairo proof.
fn cairo_only(pie: CairoPie, out: &Path) -> Res<()> {
    let (input, output_preimage, resources, boot_seconds) = boot(pie)?;
    info!("Generate the cairo proof");
    let start = Instant::now();
    let cairo_proof = prove_cairo::<Blake2sM31MerkleChannel>(input, CAIRO_PROVER_PARAMS)?;
    let prove_seconds = start.elapsed().as_secs_f64();
    let FlatClaim { component_enable_bits, component_log_sizes: _, public_data: _ } = cairo_proof.claim.flatten_claim();
    info!("Prepare the proof for the circuit verifier");
    let (proof, serialized_aux_data) = prepare_cairo_proof_for_circuit_verifier(&cairo_proof, &component_enable_bits);
    info!("Serialize and compress the proof and public data");
    let mut proof_bytes: Vec<u8> = vec![];
    proof.serialize(&mut proof_bytes);
    let combined: Vec<u8> =
        serialized_aux_data.iter().flat_map(|x| x.0.to_le_bytes()).chain(proof_bytes).collect();
    let output = PrivacyProofOutput { proof: with_header(&combined)?, output_preimage };
    let serialize_seconds = start.elapsed().as_secs_f64() - prove_seconds;
    info!("Cairo stage done");
    // Native verification with the generic Rust verifier (any component set), outside the timing.
    let rust_proof: CairoProofForRustVerifier<_> = cairo_proof.into();
    let mut mutated = rust_proof.clone();
    mutated.interaction_pow ^= 1;
    let start = Instant::now();
    let include_all = CAIRO_PROVER_PARAMS.include_all_preprocessed_columns;
    let native = verify_cairo_ex::<Blake2sM31MerkleChannel>(rust_proof, include_all).map_err(|e| format!("{e:?}"));
    let native_seconds = start.elapsed().as_secs_f64();
    let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        verify_cairo_ex::<Blake2sM31MerkleChannel>(mutated, include_all).is_err()
    }))
    .unwrap_or(true);
    write_output(out, &output, "cairo", json!({
        "boot_seconds": boot_seconds, "prove_seconds": prove_seconds, "serialize_seconds": serialize_seconds,
        "bootloader": resources, "native_verify": native.is_ok(), "native_verify_error": native.err(),
        "native_verify_seconds": native_seconds, "native_pow_byte_mutation_rejected": rejected,
    }))
}

/// The recursion stage alone, from a `cairo-only` output, as `privacy_recursive_prove` runs it.
fn recursion(cairo_dir: &Path, out: &Path) -> Res<()> {
    let bytes = fs::read(cairo_dir.join("proof.bin"))?;
    let output_preimage: Vec<Felt> = serde_json::from_slice(&fs::read(cairo_dir.join("output-preimage.json"))?)?;
    let start = Instant::now();
    info!("Prepare the cairo proof for the cairo-circuit verifier");
    let raw = zstd::bulk::decompress(&bytes[ProofHeader::SIZE..], MAX_CAIRO_PROOF_UNCOMPRESSED_BYTES)?;
    let config = get_cairo_verifier_config()?;
    let program_len = get_privacy_bootloader_program()?.data_len();
    let aux_len = (AUX_DATA_FIXED_LEN + program_len + config.proof_config.n_components()) * 4;
    if raw.len() < aux_len {
        return Err("cairo proof shorter than the fixed small-path layout".into());
    }
    let (aux_bytes, proof_bytes) = raw.split_at(aux_len);
    let aux: Vec<M31> = aux_bytes.chunks_exact(4).map(|c| M31::from(u32::from_le_bytes(c.try_into().unwrap()))).collect();
    let mut rest: &[u8] = proof_bytes;
    let proof = deserialize_proof_with_config(&mut rest, &config.proof_config)
        .map_err(|e| format!("fixed small-path deserialization failed: {e:?}"))?;
    if !rest.is_empty() {
        return Err(format!("{} trailing bytes: the proof's component set is not the fixed small-path list", rest.len()).into());
    }
    info!("Build the cairo-circuit verifier context");
    let output_hash = compute_privacy_bootloader_output_hash(&output_preimage);
    let mut context = build_and_fill_cairo_verifier_circuit(&config, proof, aux, output_hash);
    if !context.is_circuit_valid() {
        return Err("Circuit is not valid".into());
    }
    pad_context(&mut context);
    info!("Prepare the circuit precomputes");
    let preprocessed_circuit = get_cairo_preprocessed_circuit(&config);
    let circuit_config = get_recursive_circuit_config(&PRIVACY_RECURSION_CIRCUIT_PREPROCESSED_ROOT)?;
    let lifting = CIRCUIT_PCS_CONFIG.trace_lifting_log_size.max(circuit_config.config.preprocessed_lifting_log_size);
    let twiddles = SimdBackend::precompute_twiddles(CanonicCoset::new(lifting).circle_domain().half_coset);
    let pool = BaseColumnPool::<SimdBackend>::new();
    let polys = SimdBackend::interpolate_columns(preprocessed_circuit.preprocessed_trace.get_trace::<SimdBackend>(), &twiddles);
    let tree = CommitmentTreeProver::<SimdBackend, Blake2sM31MerkleChannel>::new(
        polys, CIRCUIT_FRI_CONFIG.log_blowup_factor, &twiddles, CIRCUIT_STORE_POLYNOMIALS_COEFFICIENTS,
        circuit_config.config.preprocessed_lifting_log_size, &pool);
    info!("Prove the cairo-circuit verifier");
    let circuit_proof = prove_circuit_with_precompute(
        &pool, &twiddles, &preprocessed_circuit, MaybeOwned::Owned(tree), context.values(), circuit_config.config)?;
    info!("Prepare the circuit proof for the circuit verifier");
    let (proof_qm31s, _public_data) = prepare_circuit_proof_for_circuit_verifier(circuit_proof);
    info!("Serialize and compress the proof");
    let mut proof_bytes: Vec<u8> = vec![];
    proof_qm31s.serialize(&mut proof_bytes);
    let output = PrivacyProofOutput { proof: with_header(&proof_bytes)?, output_preimage };
    info!("Recursion stage done");
    write_output(out, &output, "recursive", json!({"prove_seconds": start.elapsed().as_secs_f64(), "from": cairo_dir}))
}

fn main() -> Res<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with_span_events(FmtSpan::CLOSE)
        .with_ansi(false)
        .init();
    let a: Vec<String> = std::env::args().collect();
    let usage = "prove-small trace|cairo-only|recursive PIE OUT | recursion CAIRO_DIR OUT | verify OUT";
    match (a.get(1).map(String::as_str), a.len()) {
        (Some("trace"), 4) => {
            let out = Path::new(&a[3]);
            fs::create_dir_all(out)?;
            trace(read_pie(&a[2])?, out)
        }
        (Some("cairo-only"), 4) => {
            let out = Path::new(&a[3]);
            fs::create_dir_all(out)?;
            cairo_only(read_pie(&a[2])?, out)
        }
        (Some("recursion"), 4) => {
            let out = Path::new(&a[3]);
            fs::create_dir_all(out)?;
            recursion(Path::new(&a[2]), out)
        }
        (Some("recursive"), 4) => {
            let out = Path::new(&a[3]);
            fs::create_dir_all(out)?;
            let pie = read_pie(&a[2])?;
            let start = Instant::now();
            let precomputes = prepare_recursive_prover_precomputes()?;
            let precompute_seconds = start.elapsed().as_secs_f64();
            let start = Instant::now();
            let output = privacy_recursive_prove(pie, precomputes)?;
            write_output(out, &output, "recursive", json!({
                "precompute_seconds": precompute_seconds, "prove_seconds": start.elapsed().as_secs_f64()}))
        }
        (Some("verify"), 3) => verify(Path::new(&a[2])),
        _ => Err(usage.into()),
    }
}
