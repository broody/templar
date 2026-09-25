//! Shared by the circuit-A and client-circuit provers: bridge FRI config, production shape,
//! native verification following upstream's `stwo_verify` flow, and manifest output.
#![allow(dead_code)]
use std::fs;
use circuit_common::finalize::ComponentSizes;
use circuit_common::preprocessed::PreprocessedCircuit;
use circuit_prover::circuit_air::circuit_components::CircuitComponents;
use circuit_prover::circuit_hash::compute_circuit_hash;
use circuit_prover::prover::CircuitProof;
use circuit_prover::verify::verify_circuit_proof;
use circuit_verifier::circuit_claim::{CircuitInteractionElements, lookup_sum};
use circuit_verifier::statement::{INTERACTION_POW_BITS, all_circuit_components, circuit_component_log_sizes};
use circuits::ivalue::NoValue;
use num_traits::One;
use serde_json::json;
use stwo::core::channel::{Channel, MerkleChannel};
use stwo::core::fields::qm31::QM31;
use stwo::core::fri::FriConfig;
use stwo::core::pcs::PcsConfig;
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
    // `TEMPLAR_FRI=log_blowup,n_queries[,pow_bits]` selects another point on the same security
    // line (server log20 study); the default is the frozen 2/35/26.
    let (log_blowup_factor, n_queries, pow_bits) = match std::env::var("TEMPLAR_FRI") {
        Ok(v) => {
            let x: Vec<u32> = v.split(',').map(|t| t.trim().parse().expect("TEMPLAR_FRI")).collect();
            (x[0], x[1] as usize, *x.get(2).unwrap_or(&26))
        }
        Err(_) => (2, 35, 26),
    };
    assert!(pow_bits as usize + log_blowup_factor as usize * n_queries >= 96, "FRI security below 96 bits");
    FriConfig { log_blowup_factor, n_queries, pow_bits, ..production }
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
    // Circuit hash, transcript, STARK, LogUp sum and absent-component sums (fork `verify_circuit_proof`).
    if let Err(e) = verify_circuit_proof::<MC>(proof, pp) {
        panic!("{e}");
    }
}

/// A proof of `values` whose output `output` is shifted by one and whose LogUp imbalance is put
/// on the absent `triple_xor` claimed sum (math review M2). It passes everything but the
/// absent-component check. Returns the forged proof; its outputs are the forged statement.
pub fn forge_absent_sum(values: &[QM31], pp: &PreprocessedCircuit, output: usize) -> CircuitProof<Blake2sMerkleHasher> {
    use circuit_common::Qm31OpsTraceGenerator;
    use circuit_prover::witness::trace::{TraceGenerator, write_interaction_trace, write_trace};
    use stwo::core::poly::circle::CanonicCoset;
    use stwo::core::proof_of_work::GrindOps;
    use stwo::core::utils::MaybeOwned;
    use stwo::prover::backend::simd::SimdBackend;
    use stwo::prover::mempool::BaseColumnPool;
    use stwo::prover::poly::circle::PolyOps;
    use stwo::prover::{CommitmentSchemeProver, CommitmentTreeProver, prove_ex};
    let pcs = config(pp.trace_log_size());
    let pool = BaseColumnPool::<SimdBackend>::new();
    let twiddles = SimdBackend::precompute_twiddles(
        CanonicCoset::new(pp.trace_log_size() + pcs.fri_config.log_blowup_factor.max(1)).circle_domain().half_coset,
    );
    let polys = SimdBackend::interpolate_columns(pp.preprocessed_trace.get_trace::<SimdBackend>(), &twiddles);
    let pp_tree = CommitmentTreeProver::<SimdBackend, MC>::new(
        polys, pcs.fri_config.log_blowup_factor, &twiddles, true, pcs.preprocessed_lifting_log_size, &pool,
    );
    let generator = TraceGenerator { qm31_ops_trace_generator: Qm31OpsTraceGenerator { first_permutation_row: pp.first_permutation_row } };
    let channel = &mut <MC as MerkleChannel>::C::default();
    channel.mix_felts(&[0_u32.into()]);
    pcs.fri_config.mix_into(channel);
    let mut scheme = CommitmentSchemeProver::<SimdBackend, MC>::with_memory_pool(pcs, &twiddles, &pool);
    scheme.set_store_polynomials_coefficients();
    let root = pp_tree.commitment.root();
    scheme.commit_tree(MaybeOwned::Owned(pp_tree), channel);
    let mut builder = scheme.tree_builder();
    let (mut claim, log_sizes, igen) = write_trace(values, pp.preprocessed_trace.clone(), pp.n_outputs, &mut builder, &generator, &twiddles);
    claim.output_values[output] += QM31::one();
    let circuit_hash = compute_circuit_hash::<Blake2sMerkleHasher>(&log_sizes, pcs.fri_config.log_blowup_factor, root);
    MC::mix_hash(channel, circuit_hash);
    claim.mix_into(channel);
    builder.commit(channel);
    let nonce = SimdBackend::grind(channel, INTERACTION_POW_BITS);
    channel.mix_u64(nonce);
    let elements = CircuitInteractionElements::draw(channel);
    let mut builder = scheme.tree_builder();
    let mut ic = write_interaction_trace(&log_sizes, igen, &mut builder, &elements, &twiddles);
    let imbalance = lookup_sum(&claim, &ic, &elements);
    ic.claimed_sums.triple_xor -= imbalance;
    ic.mix_into(channel);
    builder.commit(channel);
    let components = CircuitComponents::new(&elements, &ic, &log_sizes, &pp.preprocessed_trace.ids());
    let stark_proof = prove_ex::<SimdBackend, _>(&components.component_provers(), channel, scheme, true).unwrap();
    CircuitProof { pcs_config: pcs, claim, interaction_pow_nonce: nonce, interaction_claim: ic, stark_proof, channel_salt: 0, circuit_hash }
}

/// The forgery negative: a forged proof checked against its own (forged) statement must be
/// rejected, and only by the absent-component check.
pub fn forgery_negative(values: &[QM31], pp: &PreprocessedCircuit, root: Blake2sHash) -> String {
    let forged = forge_absent_sum(values, pp, 0);
    let statement = forged.claim.output_values.clone();
    let err = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| native_verify(&forged, pp, root, &statement)))
        .expect_err("absent-sum forgery accepted");
    let msg = err.downcast_ref::<String>().cloned().unwrap_or_default();
    assert_eq!(msg, "absent component claimed sum", "forgery rejected for another reason");
    "absent-sum-forgery".to_string()
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

/// The relation a hiding audit runs on (F27): `--relation r0` (default, the committed V3
/// baselines), `r5` or `r5-bound`, and for R0 V5 `--shape S`. Removes the flags from `args`.
pub enum Witness {
    R0(templar_client_verifier_circuit::payment::Public, templar_client_verifier_circuit::payment::Private),
    R5(templar_client_verifier_circuit::payment5::Public, templar_client_verifier_circuit::payment5::Private),
}

impl Witness {
    pub fn from_args(args: &mut Vec<String>, seed: u64) -> (Self, String) {
        use rand::SeedableRng;
        use templar_client_verifier_circuit::{payment, payment5};
        let mut take = |name: &str| {
            args.iter().position(|x| x == name).map(|k| {
                let v = args.remove(k + 1);
                args.remove(k);
                v
            })
        };
        let relation = take("--relation").unwrap_or_else(|| "r0".into());
        let shape = take("--shape").unwrap_or_else(|| "transfer".into());
        let rng = &mut rand::rngs::StdRng::seed_from_u64(seed);
        let tree = payment::Tree::Compress;
        let witness = match relation.as_str() {
            "r0" => {
                assert_eq!(shape, "transfer", "R0 V3 audits use the transfer shape");
                let (p, w) = payment::fresh_shape(tree, payment::Shape::Transfer, rng);
                Witness::R0(p, w)
            }
            "r5" | "r5-bound" => {
                let mode = if relation == "r5" { payment5::Mode::Ordinary } else { payment5::Mode::Bound };
                let shape = match shape.as_str() {
                    "transfer" => payment5::Shape::Transfer,
                    "single" => payment5::Shape::Single,
                    "one-out" => payment5::Shape::OneOut,
                    "partial" => payment5::Shape::Partial,
                    "full" => payment5::Shape::Full,
                    "invoke" => payment5::Shape::Invoke,
                    "shadow" => payment5::Shape::Shadow,
                    "nft" => payment5::Shape::Nft,
                    other => panic!("unknown shape {other}"),
                };
                let (p, w) = payment5::fresh_shape(tree, shape, mode, rng);
                Witness::R5(p, w)
            }
            other => panic!("unknown relation {other}"),
        };
        (witness, format!("{relation} {shape}"))
    }

    pub fn n_outputs(&self) -> usize {
        match self {
            Witness::R0(..) => templar_client_verifier_circuit::payment::N_OUTPUTS,
            Witness::R5(..) => templar_client_verifier_circuit::payment5::N_OUTPUTS,
        }
    }

    pub fn build<V: templar_client_verifier_circuit::membership::Lanes>(&self, c: &mut circuits::context::Context<V>) -> Vec<circuits::context::Var> {
        use templar_client_verifier_circuit::{payment, payment5};
        match self {
            Witness::R0(p, w) => payment::build(c, payment::Tree::Compress, p, w),
            Witness::R5(p, w) => payment5::build(c, payment::Tree::Compress, p, w),
        }
    }

    /// The finalized, blinded circuit (arithmetic profile), as the provers build it.
    pub fn circuit<V: templar_client_verifier_circuit::membership::Lanes>(&self, seed: [u8; 32], blinding: usize) -> circuits::context::FinalizedContext<V> {
        use circuit_common::finalize::{Profile, add_zk_blinding_for, pad_context_for};
        let mut c = circuits::context::Context::<V>::new(self.n_outputs());
        let outputs = self.build(&mut c);
        c.set_outputs(&outputs);
        let mut c = c.finalize(true);
        add_zk_blinding_for(&mut c, seed, blinding, Profile::Arithmetic);
        pad_context_for(&mut c, Profile::Arithmetic);
        c
    }
}
