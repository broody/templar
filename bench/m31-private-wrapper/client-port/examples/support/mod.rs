//! Shared by the circuit-A and client-circuit provers: bridge FRI config, production shape,
//! native verification following upstream's `stwo_verify` flow, and manifest output.
#![allow(dead_code)]
use std::fs;
use circuit_common::finalize::ComponentSizes;
use circuit_common::preprocessed::PreprocessedCircuit;
use circuit_prover::circuit_air::circuit_components::CircuitComponents;
use circuit_prover::circuit_hash::compute_circuit_hash;
use circuit_prover::prover::CircuitProof;
use circuit_verifier::circuit_claim::{CircuitInteractionElements, column_log_sizes_per_tree, lookup_sum};
use circuit_verifier::statement::{INTERACTION_POW_BITS, all_circuit_components, circuit_component_log_sizes};
use circuits::ivalue::NoValue;
use num_traits::{One, Zero};
use serde_json::json;
use stwo::core::channel::{Channel, MerkleChannel};
use stwo::core::fields::qm31::QM31;
use stwo::core::fri::FriConfig;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
use stwo::core::vcs::blake2_hash::Blake2sHash;
use stwo::core::vcs_lifted::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher};

pub type MC = Blake2sMerkleChannel;

const PROVING: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../target/proving-arith");

/// Bridge FRI config: PoW 26, blowup 2, 35 queries, fold 4 (26 + 2*35 = 96 bits, as upstream's
/// production 26 + 1*70). Production's 70 queries exceed one virtual block's 1.1B L2 gas when
/// verified in Cairo, so `build_bridge_proving.py` sets exactly these two values in the vendored
/// `circuit_fri_config()`; the component shape stays upstream's production target.
pub fn bridge_fri() -> FriConfig {
    let path = format!("{PROVING}/circuit_registry_definitions/production/circuit_fri_config.json");
    let production: FriConfig = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    assert_eq!((production.pow_bits, production.log_blowup_factor, production.n_queries), (26, 1, 70));
    FriConfig { log_blowup_factor: 2, n_queries: 35, ..production }
}

/// Component row targets read from the Cairo verifier's `COMPONENT_LOG_SIZES`, so circuit A is
/// padded to exactly the shape the unmodified verifier expects.
pub fn production_targets() -> ComponentSizes {
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

pub fn config(trace_log_size: u32) -> PcsConfig {
    PcsConfig::from_fri_and_trace_size(bridge_fri(), trace_log_size)
}

/// Upstream's `stwo_verify` flow (circuit_prover/src/prover_test.rs), with trusted inputs:
/// the preprocessed root and circuit hash come from the topology, never from the proof.
pub fn native_verify(proof: &CircuitProof<Blake2sMerkleHasher>, pp: &PreprocessedCircuit, trusted_root: Blake2sHash, expected: &[QM31]) {
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
    assert!(proof.interaction_claim.absent_components_claim_zero(&log_sizes), "absent component claimed sum");
}


/// Runs the five tamper controls in place (each field restored), then the honest check.
pub fn negatives(proof: &mut CircuitProof<Blake2sMerkleHasher>, pp: &PreprocessedCircuit, root: Blake2sHash, wanted: &[QM31]) -> Vec<String> {
    let mut out = vec![];
    let mut reject = |name: &str, proof: &CircuitProof<Blake2sMerkleHasher>| {
        let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| native_verify(proof, pp, root, wanted))).is_err();
        assert!(rejected, "{name} accepted");
        out.push(name.to_string());
    };
    proof.claim.output_values[0] += QM31::one();
    reject("output", proof);
    proof.claim.output_values[0] -= QM31::one();
    let saved = proof.stark_proof.proof.commitments[1];
    proof.stark_proof.proof.0.commitments[1] = Default::default();
    reject("trace", proof);
    proof.stark_proof.proof.0.commitments[1] = saved;
    let saved = proof.stark_proof.proof.commitments[0];
    proof.stark_proof.proof.0.commitments[0] = Default::default();
    reject("topology", proof);
    proof.stark_proof.proof.0.commitments[0] = saved;
    let saved = proof.circuit_hash;
    proof.circuit_hash = Default::default();
    reject("circuit-hash", proof);
    proof.circuit_hash = saved;
    // Move part of eq's claimed sum onto triple_xor: the LogUp total is unchanged. Under the
    // arithmetic profile triple_xor is absent, so only the absent-sum check catches this.
    proof.interaction_claim.claimed_sums.eq -= QM31::one();
    proof.interaction_claim.claimed_sums.triple_xor += QM31::one();
    reject("claimed-sum-shift", proof);
    proof.interaction_claim.claimed_sums.eq += QM31::one();
    proof.interaction_claim.claimed_sums.triple_xor -= QM31::one();
    let saved = proof.pcs_config.fri_config.pow_bits;
    proof.pcs_config.fri_config.pow_bits = 0;
    reject("config", proof);
    proof.pcs_config.fri_config.pow_bits = saved;
    native_verify(proof, pp, root, wanted);
    out
}

pub fn words(h: Blake2sHash) -> Vec<u32> {
    h.0.chunks_exact(4).map(|c| u32::from_le_bytes(c.try_into().unwrap())).collect()
}

/// Trusted manifest consumed by the bridge builders.
pub fn manifest(purpose: &str, pp: &PreprocessedCircuit, cfg: &PcsConfig, root: Blake2sHash, circuit_hash: Blake2sHash, extra: serde_json::Value) -> serde_json::Value {
    let log_sizes = circuit_component_log_sizes(&all_circuit_components::<NoValue>(), &pp.preprocessed_trace.log_sizes());
    let columns: Vec<_> = pp.preprocessed_trace.log_sizes().into_iter().map(|(id, l)| json!({"id": id.id, "log_size": l})).collect();
    let mut m = json!({
        "purpose": purpose,
        "channel": "Blake2sMerkleChannel",
        "fri_config": cfg.fri_config,
        "trace_log_size": pp.trace_log_size(),
        "preprocessed_columns": columns,
        "component_log_sizes": log_sizes.into_array().to_vec(),
        "n_outputs": pp.n_outputs,
        "preprocessed_root_u32_le": words(root),
        "circuit_hash_u32_le": words(circuit_hash),
    });
    if let (Some(m), Some(e)) = (m.as_object_mut(), extra.as_object()) {
        m.extend(e.clone());
    }
    m
}

pub fn circuit_hash_of(pp: &PreprocessedCircuit, cfg: &PcsConfig, root: Blake2sHash) -> Blake2sHash {
    let log_sizes = circuit_component_log_sizes(&all_circuit_components::<NoValue>(), &pp.preprocessed_trace.log_sizes());
    compute_circuit_hash::<Blake2sMerkleHasher>(&log_sizes, cfg.fri_config.log_blowup_factor, root)
}

pub fn write(path: &std::path::Path, v: &serde_json::Value) {
    fs::write(path, serde_json::to_vec_pretty(v).unwrap()).unwrap();
}

/// Upstream's allowance for non-query openings: two OOD points × 4 coordinates + 2
/// (`cairo_verifier/src/verify.rs`, `NON_QUERY_INFO_LEAK`).
pub const NON_QUERY_INFO_LEAK: usize = 10;

/// FRI fold steps for a trace of `trace_log_size` under the bridge FRI config: the first layer
/// and each inner layer fold `fold_step` at a time until the last layer
/// (`log_last_layer_degree_bound + log_blowup_factor`).
pub fn fri_fold_schedule(trace_log_size: u32) -> Vec<u32> {
    let fri = bridge_fri();
    let mut remaining = (trace_log_size + fri.log_blowup_factor) - (fri.log_last_layer_degree_bound + fri.log_blowup_factor);
    let mut steps = vec![];
    while remaining > 0 {
        let s = remaining.min(fri.fold_step);
        steps.push(s);
        remaining -= s;
    }
    steps
}

/// Blinding iterations sized for everything a proof opens (math review H1): every FRI layer's
/// full coset per query, not only the queried point, plus the out-of-domain samples. Each
/// iteration adds one random row per witness component, so every committed column gets at least
/// this many random rows.
pub fn blinding_budget(trace_log_size: u32) -> usize {
    let per_query: usize = fri_fold_schedule(trace_log_size).iter().map(|s| 1usize << s).sum();
    bridge_fri().n_queries * per_query + NON_QUERY_INFO_LEAK
}

/// Field values a proof reveals through FRI beyond the trace openings: every layer's witness and
/// the last-layer polynomial.
pub fn revealed_fri_values(proof: &CircuitProof<Blake2sMerkleHasher>) -> usize {
    let fri = &proof.stark_proof.proof.fri_proof;
    std::iter::once(&fri.first_layer).chain(&fri.inner_layers).map(|l| l.fri_witness.len()).sum::<usize>()
        + fri.last_layer_poly.len()
}
