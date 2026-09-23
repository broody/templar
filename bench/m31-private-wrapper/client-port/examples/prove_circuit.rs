//! Proves circuit A for one TMPZK002 proof on `starkware-libs/proving` and verifies it natively
//! with the stark verifier, following upstream's own `stwo_verify` test flow. Writes the trusted
//! manifest (including the circuit hash the consumer must pin) and the Cairo verifier input.
use std::{fs, path::Path, time::Instant};
use blake2::{Blake2s256, Digest};
use circuit_cairo_serialize::prepare_circuit_proof_for_cairo_verifier;
use circuit_common::N_RESERVED;
use circuit_common::finalize::{ComponentSizes, pad_to_targets};
use circuit_common::preprocessed::PreprocessedCircuit;
use circuit_prover::circuit_air::circuit_components::CircuitComponents;
use circuit_prover::circuit_hash::compute_circuit_hash;
use circuit_prover::prover::{BaseColumnPool, CircuitProof, SimdBackend, prove_circuit_assignment_with_channel};
use circuit_verifier::circuit_claim::{CircuitInteractionElements, column_log_sizes_per_tree, lookup_sum};
use circuit_verifier::statement::{INTERACTION_POW_BITS, all_circuit_components, circuit_component_log_sizes};
use circuits::context::{Context, FinalizedContext};
use circuits::ivalue::{IValue, NoValue};
use num_traits::{One, Zero};
use serde_json::json;
use stwo::core::channel::{Channel, MerkleChannel};
use stwo::core::fields::m31::M31;
use stwo::core::fields::qm31::QM31;
use stwo::core::fri::FriConfig;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
use stwo::core::vcs::blake2_hash::Blake2sHash;
use stwo::core::vcs_lifted::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher};
use templar_client_verifier_circuit::air::Public;
use templar_client_verifier_circuit::native;
use templar_client_verifier_circuit::verify::{N_OUTPUTS, build, statement_outputs};

type MC = Blake2sMerkleChannel;

const PROVING: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../target/proving-main");

/// Bridge FRI config: PoW 26, blowup 2, 35 queries, fold 4 (26 + 2*35 = 96 bits, as upstream's
/// production 26 + 1*70). Production's 70 queries exceed one virtual block's 1.1B L2 gas when
/// verified in Cairo, so `build_bridge_proving.py` sets exactly these two values in the vendored
/// `circuit_fri_config()`; the component shape stays upstream's production target.
fn production_fri() -> FriConfig {
    let path = format!("{PROVING}/circuit_registry_definitions/production/circuit_fri_config.json");
    let production: FriConfig = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    assert_eq!((production.pow_bits, production.log_blowup_factor, production.n_queries), (26, 1, 70));
    FriConfig { log_blowup_factor: 2, n_queries: 35, ..production }
}

/// Component row targets read from the Cairo verifier's `COMPONENT_LOG_SIZES`, so circuit A is
/// padded to exactly the shape the unmodified verifier expects.
fn production_targets() -> ComponentSizes {
    let path = format!("{PROVING}/stwo_cairo_verifier/crates/circuit_air/src/multiverifier_consts.cairo");
    let text = fs::read_to_string(path).unwrap();
    let block = &text[text.find("pub const COMPONENT_LOG_SIZES").unwrap()..];
    let log = |name: &str| -> usize {
        let at = block.find(&format!("    {name}: ")).unwrap_or_else(|| panic!("{name}"));
        let rest = &block[at + name.len() + 6..];
        1usize << rest[..rest.find(',').unwrap()].trim().parse::<u32>().unwrap()
    };
    ComponentSizes { eq: log("eq"), qm31_ops: log("qm31_ops"), m31_to_u32: log("m_31_to_u_32"), triple_xor: log("triple_xor"), blake_g_gate: log("blake_g_gate") }
}

fn config(trace_log_size: u32) -> PcsConfig {
    PcsConfig::from_fri_and_trace_size(production_fri(), trace_log_size)
}

fn circuit<V: IValue>(p: &native::Parsed, public: &Public) -> FinalizedContext<V> {
    assert_eq!(N_OUTPUTS, N_RESERVED);
    let mut c = Context::<V>::new(N_RESERVED);
    let s = build(&mut c, p, &public.root);
    let out = statement_outputs(&mut c, &s);
    c.set_outputs(&out);
    let mut c = c.finalize(true);
    let raw = circuit_common::finalize::compute_padded_sizes(&c);
    let target = production_targets();
    assert!(raw.zip(&target, |r, t| (r <= t) as usize) == raw.map(|_| 1), "circuit A exceeds the production shape: {raw:?} vs {target:?}");
    pad_to_targets(&mut c, &target);
    c
}

/// `Blake2s(x || root LE u32)`, computed without the circuit.
fn expected(p: &native::Parsed, public: &Public) -> Vec<QM31> {
    let mut m = p.x.clone();
    for r in public.root {
        m.extend(r.to_le_bytes());
    }
    Blake2s256::digest(&m).chunks_exact(4).map(|c| *QM31::pack_u32(u32::from_le_bytes(c.try_into().unwrap())).get()).collect()
}

/// Upstream's `stwo_verify` flow (circuit_prover/src/prover_test.rs), with trusted inputs:
/// the preprocessed root and circuit hash come from the topology, never from the proof.
fn native_verify(proof: &CircuitProof<Blake2sMerkleHasher>, pp: &PreprocessedCircuit, trusted_root: Blake2sHash, expected: &[QM31]) {
    assert_eq!(proof.stark_proof.proof.commitments[0], trusted_root, "preprocessed root");
    assert_eq!(proof.pcs_config, config(pp.trace_log_size()), "pcs config");
    assert_eq!(proof.claim.output_values, expected, "statement digest");
    let log_sizes = circuit_component_log_sizes(&all_circuit_components::<NoValue>(), &pp.preprocessed_trace.log_sizes());
    let circuit_hash = compute_circuit_hash::<Blake2sMerkleHasher>(&log_sizes, proof.pcs_config.fri_config.log_blowup_factor, trusted_root);
    assert_eq!(proof.circuit_hash, circuit_hash, "circuit hash");
    let channel = &mut <MC as MerkleChannel>::C::default();
    channel.mix_felts(&[proof.channel_salt.into()]);
    proof.pcs_config.fri_config.mix_into(channel);
    let scheme = &mut CommitmentSchemeVerifier::<MC>::new(proof.pcs_config);
    let [trace_sizes, interaction_sizes] = column_log_sizes_per_tree(&log_sizes);
    let pp_sizes: Vec<u32> = pp.preprocessed_trace.log_sizes().values().copied().collect();
    let stark = proof.stark_proof.proof.clone();
    scheme.commit(stark.commitments[0], &pp_sizes, channel);
    MC::mix_hash(channel, circuit_hash);
    proof.claim.mix_into(channel);
    scheme.commit(stark.commitments[1], &trace_sizes, channel);
    assert!(channel.verify_pow_nonce(INTERACTION_POW_BITS, proof.interaction_pow_nonce), "interaction pow");
    channel.mix_u64(proof.interaction_pow_nonce);
    let elements = CircuitInteractionElements::draw(channel);
    proof.interaction_claim.mix_into(channel);
    scheme.commit(stark.commitments[2], &interaction_sizes, channel);
    let components = CircuitComponents::new(&elements, &proof.interaction_claim, &log_sizes, &pp.preprocessed_trace.ids());
    stwo::core::verifier::verify_ex(&components.components(), channel, scheme, stark, true).expect("stark verification");
    assert_eq!(lookup_sum(&proof.claim, &proof.interaction_claim, &elements), QM31::zero(), "lookup sum");
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    assert_eq!(a.len(), 4, "prove_circuit PUBLIC PROOF OUT");
    let public: Public = serde_json::from_slice(&fs::read(&a[1]).unwrap()).unwrap();
    let bytes = fs::read(&a[2]).unwrap();
    let out = Path::new(&a[3]);
    fs::create_dir_all(out).unwrap();
    let started = Instant::now();
    let p = native::parse(&public, &bytes).unwrap();
    let topology = circuit::<NoValue>(&p, &public);
    let context = circuit::<QM31>(&p, &public);
    assert!(topology.circuit() == context.circuit());
    context.validate_circuit();
    let build_seconds = started.elapsed().as_secs_f64();
    let pp = PreprocessedCircuit::from_finalized_circuit(topology.circuit());
    drop(topology);
    let cfg = config(pp.trace_log_size());
    let trusted_root = pp.preprocessed_root(cfg.fri_config.log_blowup_factor);
    let log_sizes = circuit_component_log_sizes(&all_circuit_components::<NoValue>(), &pp.preprocessed_trace.log_sizes());
    let circuit_hash = compute_circuit_hash::<Blake2sMerkleHasher>(&log_sizes, cfg.fri_config.log_blowup_factor, trusted_root);
    let wanted = expected(&p, &public);
    let prove_start = Instant::now();
    let proof = prove_circuit_assignment_with_channel::<MC>(context.values(), &pp, &BaseColumnPool::<SimdBackend>::new(), cfg).unwrap();
    let proving_seconds = prove_start.elapsed().as_secs_f64();
    drop(context);
    let verify_start = Instant::now();
    native_verify(&proof, &pp, trusted_root, &wanted);
    let verify_seconds = verify_start.elapsed().as_secs_f64();
    // Each control mutates one field in place, checks rejection, then restores it.
    let mut proof = proof;
    let mut negatives = vec![];
    let mut reject = |name: &str, proof: &CircuitProof<Blake2sMerkleHasher>| {
        let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| native_verify(proof, &pp, trusted_root, &wanted))).is_err();
        assert!(rejected, "{name} accepted");
        negatives.push(name.to_string());
    };
    proof.claim.output_values[0] += QM31::one();
    reject("output", &proof);
    proof.claim.output_values[0] -= QM31::one();
    let saved = proof.stark_proof.proof.commitments[1];
    proof.stark_proof.proof.0.commitments[1] = Default::default();
    reject("trace", &proof);
    proof.stark_proof.proof.0.commitments[1] = saved;
    let saved = proof.stark_proof.proof.commitments[0];
    proof.stark_proof.proof.0.commitments[0] = Default::default();
    reject("topology", &proof);
    proof.stark_proof.proof.0.commitments[0] = saved;
    let saved = proof.circuit_hash;
    proof.circuit_hash = Default::default();
    reject("circuit-hash", &proof);
    proof.circuit_hash = saved;
    proof.pcs_config.fri_config.pow_bits = 0;
    reject("config", &proof);
    proof.pcs_config.fri_config.pow_bits = 26;
    native_verify(&proof, &pp, trusted_root, &wanted);
    let felts = prepare_circuit_proof_for_cairo_verifier(proof, &log_sizes);
    let columns: Vec<_> = pp.preprocessed_trace.log_sizes().into_iter().map(|(id, l)| json!({"id": id.id, "log_size": l})).collect();
    let words = |h: Blake2sHash| -> Vec<u32> { h.0.chunks_exact(4).map(|c| u32::from_le_bytes(c.try_into().unwrap())).collect() };
    fs::write(out.join("trusted-config.json"), serde_json::to_vec_pretty(&json!({
        "purpose": "tmpzk002-client-verifier-circuit",
        "stack": "starkware-libs/proving@5a7c5ed, padded to the production multiverifier shape, bridge FRI (blowup 2, 35 queries)",
        "channel": "Blake2sMerkleChannel",
        "fri_config": cfg.fri_config,
        "trace_log_size": pp.trace_log_size(),
        "preprocessed_columns": columns,
        "component_log_sizes": log_sizes.into_array().to_vec(),
        "n_outputs": N_OUTPUTS,
        "preprocessed_root_u32_le": words(trusted_root),
        "circuit_hash_u32_le": words(circuit_hash),
    })).unwrap()).unwrap();
    let mut arguments = vec![format!("0x{:x}", felts.len())];
    arguments.extend(felts.iter().map(|f| format!("{f:#x}")));
    fs::write(out.join("cairo-arguments.json"), serde_json::to_vec(&arguments).unwrap()).unwrap();
    let report = json!({
        "scope": "complete TMPZK002 private-membership verifier as one server circuit (proving@5a7c5ed)",
        "trace_log_size": pp.trace_log_size(),
        "component_log_sizes": log_sizes.into_array().to_vec(),
        "build_seconds": build_seconds,
        "proving_seconds": proving_seconds,
        "native_verify_seconds": verify_seconds,
        "total_seconds": started.elapsed().as_secs_f64(),
        "proof_felts": felts.len(),
        "native_negatives": negatives,
        "statement_digest": wanted.iter().map(|v| v.to_m31_array().map(|x| x.0)).collect::<Vec<_>>(),
    });
    fs::write(out.join("report.json"), serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    println!("{report}");
    let _ = M31::from(0);
}
