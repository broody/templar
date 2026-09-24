//! Hiding audit, first check: does the verifier see blinding-free functions of the witness?
//!
//! The arithmetic profile blinds `qm31_ops` with add gates only (`x + 0 = x`, `0 + y = y`,
//! `z + 0 = z`; `circuit_common::finalize::qm31_zk_blinding`), so `dst - op0 - op1` is zero,
//! limb by limb, on every blinding row. The verifier opens all twelve `qm31_ops` columns at
//! each query, so it can form that combination, whose low-degree extension depends only on the
//! witness's non-add gates.
//!
//! Test: prove an R0 transfer with blinding seed A. Rebuild the committed base trace with seed
//! B, form `D = dst - op0 - op1` on its low-degree extension, and look up each query's opened
//! combination from proof A in it. Controls: the opened `op0` limbs must match seed A's
//! extension and must not match seed B's.
use std::collections::HashSet;
#[path = "support/mod.rs"]
mod support;
use circuit_common::Qm31OpsTraceGenerator;
use circuit_common::finalize::{Profile, add_zk_blinding_for, pad_context_for};
use circuit_common::preprocessed::PreprocessedCircuit;
use circuit_prover::prover::{BaseColumnPool, SimdBackend, prove_circuit_assignment_bounded};
use circuit_prover::witness::trace::{TraceGenerator, write_trace};
use circuits::context::{Context, FinalizedContext};
use circuits::ivalue::NoValue;
use rand::{SeedableRng, rngs::StdRng};
use serde_json::json;
use stwo::core::channel::{Channel, MerkleChannel};
use stwo::core::fields::m31::M31;
use stwo::core::fields::qm31::QM31;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::utils::MaybeOwned;
use stwo::prover::backend::Column;
use stwo::prover::poly::circle::PolyOps;
use stwo::prover::{CommitmentSchemeProver, CommitmentTreeProver};
use templar_client_verifier_circuit::membership::Lanes;
use templar_client_verifier_circuit::payment::{self, N_OUTPUTS, Private, Public, Shape, Tree};

const TREE: Tree = Tree::Compress;

fn circuit<V: Lanes>(public: &Public, private: &Private, seed: [u8; 32], blinding: usize) -> FinalizedContext<V> {
    let mut c = Context::<V>::new(N_OUTPUTS);
    let outputs = payment::build(&mut c, TREE, public, private);
    c.set_outputs(&outputs);
    let mut c = c.finalize(true);
    add_zk_blinding_for(&mut c, seed, blinding, Profile::Arithmetic);
    pad_context_for(&mut c, Profile::Arithmetic);
    c
}

/// The committed base-trace columns (low-degree extensions, bit-reversed, as opened), with each
/// column's committed log size.
fn committed_base_trace(values: &[QM31], pp: &PreprocessedCircuit) -> Vec<(u32, Vec<M31>)> {
    let pcs = support::config(pp.trace_log_size());
    let pool = BaseColumnPool::<SimdBackend>::new();
    let twiddles = SimdBackend::precompute_twiddles(
        CanonicCoset::new(pp.trace_log_size() + pcs.fri_config.log_blowup_factor.max(1)).circle_domain().half_coset,
    );
    let polys = SimdBackend::interpolate_columns(pp.preprocessed_trace.get_trace::<SimdBackend>(), &twiddles);
    let pp_tree = CommitmentTreeProver::<SimdBackend, support::MC>::new(
        polys, pcs.fri_config.log_blowup_factor, &twiddles, true, pcs.preprocessed_lifting_log_size, &pool,
    );
    let generator = TraceGenerator { qm31_ops_trace_generator: Qm31OpsTraceGenerator { first_permutation_row: pp.first_permutation_row } };
    let channel = &mut <support::MC as MerkleChannel>::C::default();
    channel.mix_felts(&[0_u32.into()]);
    let mut scheme = CommitmentSchemeProver::<SimdBackend, support::MC>::with_memory_pool(pcs, &twiddles, &pool);
    scheme.commit_tree(MaybeOwned::Owned(pp_tree), channel);
    let mut builder = scheme.tree_builder();
    let _ = write_trace(values, pp.preprocessed_trace.clone(), pp.n_outputs, &mut builder, &generator, &twiddles);
    builder.commit(channel);
    scheme.trees[1]
        .polynomials
        .iter()
        .map(|p| {
            let e = p.evals.as_ref().unwrap();
            (e.domain.log_size(), e.values.to_cpu())
        })
        .collect()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let out = std::path::Path::new(args.get(1).map(String::as_str).unwrap_or("target/hiding-leak"));
    std::fs::create_dir_all(out).unwrap();
    let (public, private) = payment::fresh_shape(TREE, Shape::Transfer, &mut StdRng::seed_from_u64(11));
    let (seed_a, seed_b) = ([0xa1; 32], [0xb2; 32]);
    let mut blinding = 0;
    let pp = loop {
        let topology = circuit::<NoValue>(&public, &private, [0; 32], blinding);
        let pp = PreprocessedCircuit::from_finalized_circuit(topology.circuit());
        let need = support::blinding_budget(pp.trace_log_size());
        if blinding >= need {
            break pp;
        }
        blinding = need;
    };
    let a = circuit::<QM31>(&public, &private, seed_a, blinding);
    let b = circuit::<QM31>(&public, &private, seed_b, blinding);
    assert!(a.circuit() == b.circuit(), "the seed changed the topology");
    let cfg = support::config(pp.trace_log_size());
    let proof = prove_circuit_assignment_bounded::<support::MC>(a.values(), &pp, &BaseColumnPool::<SimdBackend>::new(), cfg, Some(16)).unwrap();
    let trace_a = committed_base_trace(a.values(), &pp);
    let trace_b = committed_base_trace(b.values(), &pp);
    let queried = &proof.stark_proof.proof.queried_values[1];
    assert_eq!(queried.len(), trace_a.len(), "base-trace column count");
    // qm31_ops is the only component at the full trace size: its twelve columns are the ones
    // committed at trace_log_size + blowup.
    let full = pp.trace_log_size() + cfg.fri_config.log_blowup_factor;
    let cols: Vec<usize> = (0..trace_a.len()).filter(|&j| trace_a[j].0 == full).collect();
    assert_eq!(cols.len(), 12, "qm31_ops columns: {:?}", trace_a.iter().map(|c| c.0).collect::<Vec<_>>());
    let (op0, op1, dst) = (&cols[0..4], &cols[4..8], &cols[8..12]);
    let n_queries = queried[cols[0]].len();
    let lde_len = trace_a[cols[0]].1.len();

    // Every low-degree-extension point, as a 4-limb tuple: D = dst - op0 - op1, and op0 alone.
    let d_tuple = |t: &Vec<(u32, Vec<M31>)>, i: usize| -> [u32; 4] {
        std::array::from_fn(|k| (t[dst[k]].1[i] - t[op0[k]].1[i] - t[op1[k]].1[i]).0)
    };
    let op0_tuple = |t: &Vec<(u32, Vec<M31>)>, i: usize| -> [u32; 4] { std::array::from_fn(|k| t[op0[k]].1[i].0) };
    let set = |f: &dyn Fn(usize) -> [u32; 4]| -> HashSet<[u32; 4]> { (0..lde_len).map(f).collect() };
    let d_b = set(&|i| d_tuple(&trace_b, i));
    let d_a = set(&|i| d_tuple(&trace_a, i));
    let op0_a = set(&|i| op0_tuple(&trace_a, i));
    let op0_b = set(&|i| op0_tuple(&trace_b, i));
    // Blinding-row sanity: D is identical for both seeds at every point.
    let d_equal = (0..lde_len).all(|i| d_tuple(&trace_a, i) == d_tuple(&trace_b, i));
    let op0_equal = (0..lde_len).filter(|&i| op0_tuple(&trace_a, i) == op0_tuple(&trace_b, i)).count();

    let mut hits = json!({"d_in_seed_b": 0, "d_in_seed_a": 0, "op0_in_seed_a": 0, "op0_in_seed_b": 0});
    let mut bump = |k: &str| *hits.get_mut(k).unwrap() = json!(hits[k].as_u64().unwrap() + 1);
    for q in 0..n_queries {
        let d: [u32; 4] = std::array::from_fn(|k| (queried[dst[k]][q] - queried[op0[k]][q] - queried[op1[k]][q]).0);
        let o: [u32; 4] = std::array::from_fn(|k| queried[op0[k]][q].0);
        if d_b.contains(&d) {
            bump("d_in_seed_b");
        }
        if d_a.contains(&d) {
            bump("d_in_seed_a");
        }
        if op0_a.contains(&o) {
            bump("op0_in_seed_a");
        }
        if op0_b.contains(&o) {
            bump("op0_in_seed_b");
        }
    }
    let report = json!({
        "scope": "R0 V2 transfer, arithmetic profile, compressed nodes; proof with seed A, lookups in seed B's committed trace",
        "trace_log_size": pp.trace_log_size(),
        "blinding_iterations": blinding,
        "fri": format!("{:?}", cfg.fri_config),
        "base_trace_columns": trace_a.len(),
        "lde_points": lde_len,
        "opened_queries": n_queries,
        "hits": hits,
        "d_extension_identical_across_seeds": d_equal,
        "op0_extension_points_equal_across_seeds": op0_equal,
        "blinding_free_leak_confirmed": d_equal && hits["d_in_seed_b"] == json!(n_queries) && hits["op0_in_seed_b"] == json!(0)
            && hits["op0_in_seed_a"] == json!(n_queries),
    });
    std::fs::write(out.join("report.json"), serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    println!("{}", serde_json::to_string_pretty(&report).unwrap());
}
