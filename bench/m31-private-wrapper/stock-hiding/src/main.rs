//! H2 check against unmodified upstream `proving@5a7c5ed` (`target/proving-main`), with the
//! full component profile, upstream's `add_zk_blinding`, its production FRI config (blowup 2¹,
//! 70 queries) and its padding count (`n_queries + NON_QUERY_INFO_LEAK` = 80), as
//! `privacy_circuit_verify` uses them.
//!
//! 1. **Rank audit.** Trace one witness with two blinding seeds (fixed lookup challenges). Per
//!    tree and log size, the kernel of the seed difference is the set of public column
//!    combinations that the blinding never reaches. Each kernel vector is classified as a
//!    constraint identity (zero on every row, harmless) or witness-dependent (a leak).
//! 2. **End to end.** Prove with seed A (upstream `prove_circuit_assignment`). For every
//!    witness-dependent base-tree combination, evaluate it on each query's opened values and
//!    look it up in the combination's low-degree extension built with seed B.
use std::collections::{BTreeMap, HashSet};

use circuit_common::Qm31OpsTraceGenerator;
use circuit_common::finalize::{add_zk_blinding, pad_context};
use circuit_common::preprocessed::PreprocessedCircuit;
use circuit_prover::prover::{BaseColumnPool, SimdBackend, prove_circuit_assignment};
use circuit_prover::witness::trace::{TraceGenerator, write_interaction_trace, write_trace};
use circuit_verifier::circuit_claim::CircuitInteractionElements;
use circuits::context::{Context, FinalizedContext};
use circuits::ivalue::{IValue, qm31_from_u32s};
use circuits::blake::{blake_g_gate, m31_to_u32, triple_xor};
use circuits::ops::{add, add_into, mul};
use circuits::wrappers::U32Wrapper;
use rand::{Rng, SeedableRng, rngs::StdRng};
use serde_json::json;
use stwo::core::channel::{Channel, MerkleChannel};
use stwo::core::fields::m31::{M31, P};
use stwo::core::fields::qm31::QM31;
use stwo::core::fri::FriConfig;
use stwo::core::pcs::PcsConfig;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::utils::MaybeOwned;
use stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleChannel;
use stwo::prover::backend::Column;
use stwo::prover::poly::circle::PolyOps;
use stwo::prover::{CommitmentSchemeProver, CommitmentTreeProver};

type MC = Blake2sM31MerkleChannel;
const PP: u64 = P as u64;
const N_PADDING: usize = 70 + 10;

/// A small relation with private data in every witness component: 16 private QM31 values
/// through 400 mul/add gates, plus Blake G (40), triple XOR (30) and M31→u32 (20) over private u32s.
fn circuit(seed: [u8; 32]) -> FinalizedContext<QM31> {
    let mut c = Context::<QM31>::new(1);
    let mut rng = StdRng::seed_from_u64(5);
    let zero = c.zero();
    let privs: Vec<_> = (0..16)
        .map(|_| {
            let v = c.new_var(QM31::from_qm31(qm31_from_u32s(rng.r#gen(), rng.r#gen(), rng.r#gen(), rng.r#gen())));
            add_into(&mut c, v, zero, v);
            v
        })
        .collect();
    let mut acc = privs[0];
    for g in 0..400 {
        let other = privs[(g * 7 + 3) % 16];
        acc = if g % 2 == 0 { mul(&mut c, acc, other) } else { add(&mut c, acc, other) };
    }
    for &p in &privs[1..] {
        acc = add(&mut c, acc, p);
    }
    let u32v = |c: &mut Context<QM31>, rng: &mut StdRng| -> U32Wrapper<circuits::context::Var> {
        let x = c.new_var(*QM31::pack_u32(rng.r#gen()).get());
        add_into(c, x, zero, x);
        U32Wrapper::new_unsafe(x)
    };
    // Distinct instance counts (Blake G 40, triple XOR 30, M31→u32 20) identify components.
    for i in 0..40 {
        let (a, b, cc, d, f0, f1) = (u32v(&mut c, &mut rng), u32v(&mut c, &mut rng), u32v(&mut c, &mut rng), u32v(&mut c, &mut rng), u32v(&mut c, &mut rng), u32v(&mut c, &mut rng));
        for o in blake_g_gate(&mut c, a, b, cc, d, f0, f1) {
            acc = add(&mut c, acc, *o.get());
        }
        if i >= 30 {
            continue;
        }
        let (x, y, z) = (u32v(&mut c, &mut rng), u32v(&mut c, &mut rng), u32v(&mut c, &mut rng));
        let t = triple_xor(&mut c, x, y, z);
        acc = add(&mut c, acc, *t.get());
        if i >= 20 {
            continue;
        }
        let m = c.new_var(QM31::from_qm31(qm31_from_u32s(rng.gen_range(0..P), 0, 0, 0)));
        add_into(&mut c, m, zero, m);
        let mu = m31_to_u32(&mut c, m);
        acc = add(&mut c, acc, *mu.get());
    }
    c.set_outputs(&[acc]);
    let mut c = c.finalize(true);
    add_zk_blinding(&mut c, seed, N_PADDING);
    pad_context(&mut c);
    c
}

fn pcs(log: u32) -> PcsConfig {
    let fri = FriConfig { pow_bits: 26, log_blowup_factor: 1, log_last_layer_degree_bound: 0, n_queries: 70, fold_step: 4 };
    PcsConfig::from_fri_and_trace_size(fri, log)
}

struct Col {
    log: u32,
    trace: Vec<M31>,
    lde: Vec<M31>,
}

/// Base (tree 1) and interaction (tree 2) columns: trace-domain values and committed LDE.
fn traces(values: &[QM31], pp: &PreprocessedCircuit, elements: &CircuitInteractionElements) -> (Vec<Col>, Vec<Col>) {
    let cfg = pcs(pp.trace_log_size());
    let pool = BaseColumnPool::<SimdBackend>::new();
    let twiddles = SimdBackend::precompute_twiddles(
        CanonicCoset::new(pp.trace_log_size() + cfg.fri_config.log_blowup_factor.max(1)).circle_domain().half_coset,
    );
    let polys = SimdBackend::interpolate_columns(pp.preprocessed_trace.get_trace::<SimdBackend>(), &twiddles);
    let pp_tree = CommitmentTreeProver::<SimdBackend, MC>::new(
        polys, cfg.fri_config.log_blowup_factor, &twiddles, true, cfg.preprocessed_lifting_log_size, &pool,
    );
    let generator = TraceGenerator { qm31_ops_trace_generator: Qm31OpsTraceGenerator { first_permutation_row: pp.first_permutation_row } };
    let channel = &mut <MC as MerkleChannel>::C::default();
    channel.mix_felts(&[0_u32.into()]);
    let mut scheme = CommitmentSchemeProver::<SimdBackend, MC>::with_memory_pool(cfg, &twiddles, &pool);
    scheme.set_store_polynomials_coefficients();
    scheme.commit_tree(MaybeOwned::Owned(pp_tree), channel);
    let mut builder = scheme.tree_builder();
    let (_, log_sizes, igen) = write_trace(values, pp.preprocessed_trace.clone(), pp.n_outputs, &mut builder, &generator, &twiddles);
    builder.commit(channel);
    let mut builder = scheme.tree_builder();
    let _ = write_interaction_trace(&log_sizes, igen, &mut builder, elements, &twiddles);
    builder.commit(channel);
    let cols = |tree: usize| -> Vec<Col> {
        scheme.trees[tree]
            .polynomials
            .iter()
            .map(|p| {
                let c = p.coeffs.as_ref().unwrap();
                let log = c.log_size();
                Col { log, trace: c.evaluate(CanonicCoset::new(log).circle_domain()).values.to_cpu(), lde: p.evals.values.to_cpu() }
            })
            .collect()
    };
    (cols(1), cols(2))
}

fn inv(a: u64) -> u64 {
    let (mut r, mut b, mut e) = (1u64, a % PP, PP - 2);
    while e > 0 {
        if e & 1 == 1 {
            r = r * b % PP;
        }
        b = b * b % PP;
        e >>= 1;
    }
    r
}

/// Kernel basis of `{c : row · c = 0 for every row}`.
fn kernel(rows: impl Iterator<Item = Vec<u64>>, n: usize) -> Vec<Vec<u64>> {
    let mut basis: Vec<(usize, Vec<u64>)> = vec![];
    for mut row in rows {
        for (piv, b) in &basis {
            let f = row[*piv];
            if f != 0 {
                for j in 0..n {
                    row[j] = (row[j] + PP - f * b[j] % PP) % PP;
                }
            }
        }
        if let Some(piv) = (0..n).find(|&j| row[j] != 0) {
            let s = inv(row[piv]);
            row.iter_mut().for_each(|x| *x = *x * s % PP);
            for (_, b) in basis.iter_mut() {
                let f = b[piv];
                if f != 0 {
                    for j in 0..n {
                        b[j] = (b[j] + PP - f * row[j] % PP) % PP;
                    }
                }
            }
            basis.push((piv, row));
            if basis.len() == n {
                break;
            }
        }
    }
    let pivots: Vec<usize> = basis.iter().map(|(p, _)| *p).collect();
    (0..n)
        .filter(|j| !pivots.contains(j))
        .map(|free| {
            let mut c = vec![0u64; n];
            c[free] = 1;
            for (piv, b) in &basis {
                c[*piv] = (PP - b[free]) % PP;
            }
            c
        })
        .collect()
}

fn signed(x: u64) -> i64 {
    if x > PP / 2 { x as i64 - PP as i64 } else { x as i64 }
}

fn main() {
    let out = std::path::Path::new(std::env::args().nth(1).as_deref().unwrap_or("target/stock-hiding")).to_path_buf();
    std::fs::create_dir_all(&out).unwrap();
    let (a, b) = (circuit([0xa1; 32]), circuit([0xb2; 32]));
    assert!(a.circuit() == b.circuit(), "seed changed the topology");
    let pp = PreprocessedCircuit::from_finalized_circuit(a.circuit());
    let channel = &mut <MC as MerkleChannel>::C::default();
    channel.mix_felts(&[7_u32.into()]);
    let elements = CircuitInteractionElements::draw(channel);
    let (base_a, inter_a) = traces(a.values(), &pp, &elements);
    let (base_b, inter_b) = traces(b.values(), &pp, &elements);
    println!("{}", json!({"trace_log_size": pp.trace_log_size(), "base_columns": base_a.iter().map(|c| c.log).collect::<Vec<_>>(),
                          "interaction_columns": inter_a.iter().map(|c| c.log).collect::<Vec<_>>()}));

    // 1. Rank audit per tree and log size.
    let mut findings = vec![];
    let mut leaks: Vec<(Vec<usize>, Vec<u64>)> = vec![];
    for (tree, ta, tb) in [("base", &base_a, &base_b), ("interaction", &inter_a, &inter_b)] {
        let mut groups = BTreeMap::<u32, Vec<usize>>::new();
        for (j, c) in ta.iter().enumerate() {
            groups.entry(c.log).or_default().push(j);
        }
        for (log, cols) in groups {
            let len = ta[cols[0]].trace.len();
            let rows = (0..len).map(|i| cols.iter().map(|&j| (ta[j].trace[i] - tb[j].trace[i]).0 as u64).collect::<Vec<u64>>());
            let changed = (0..len).filter(|&i| cols.iter().any(|&j| ta[j].trace[i] != tb[j].trace[i])).count();
            let ker = kernel(rows, cols.len());
            let mut classified = vec![];
            for c in &ker {
                // Zero on every row (witness included) means a constraint identity.
                let nonzero_rows = (0..len)
                    .filter(|&i| cols.iter().enumerate().fold(0u64, |acc, (k, &j)| (acc + c[k] * ta[j].trace[i].0 as u64) % PP) != 0)
                    .count();
                let support: Vec<(usize, i64)> = cols.iter().enumerate().filter(|(k, _)| c[*k] != 0).map(|(k, &j)| (j, signed(c[k]))).collect();
                if nonzero_rows > 0 && tree == "base" {
                    leaks.push((cols.clone(), c.clone()));
                }
                classified.push(json!({"support": support, "nonzero_rows": nonzero_rows,
                                       "kind": if nonzero_rows == 0 { "constraint identity" } else { "witness-dependent" }}));
            }
            let r = json!({"tree": tree, "log_size": log, "columns": cols, "rows_changed_by_seed": changed,
                           "rank": cols.len() - ker.len(), "unblinded": ker.len(), "kernel": classified});
            println!("{} log{} cols {} rank {} unblinded {} witness-dependent {}", tree, log, cols.len(), cols.len() - ker.len(), ker.len(),
                     r["kernel"].as_array().unwrap().iter().filter(|k| k["kind"] == "witness-dependent").count());
            findings.push(r);
        }
    }

    // 2. End to end on a real proof (seed A), looked up in seed B's committed extension.
    let proof = prove_circuit_assignment(a.values(), &pp, &BaseColumnPool::<SimdBackend>::new(), pcs(pp.trace_log_size())).unwrap();
    let queried = &proof.stark_proof.proof.queried_values[1];
    let mut e2e = vec![];
    for (cols, c) in &leaks {
        let comb = |t: &Vec<Col>, i: usize| -> u64 { cols.iter().enumerate().fold(0u64, |acc, (k, &j)| (acc + c[k] * t[j].lde[i].0 as u64) % PP) };
        let lde_len = base_b[cols[0]].lde.len();
        let set_b: HashSet<u64> = (0..lde_len).map(|i| comb(&base_b, i)).collect();
        let n_q = queried[cols[0]].len();
        let hits = (0..n_q)
            .filter(|&q| set_b.contains(&cols.iter().enumerate().fold(0u64, |acc, (k, &j)| (acc + c[k] * queried[j][q].0 as u64) % PP)))
            .count();
        // Control: the same lookup for a single column (should miss).
        let single: HashSet<u64> = (0..lde_len).map(|i| base_b[cols[0]].lde[i].0 as u64).collect();
        let control = (0..n_q).filter(|&q| single.contains(&(queried[cols[0]][q].0 as u64))).count();
        e2e.push(json!({"columns": cols, "queries": n_q, "combination_found_in_seed_b": hits, "control_single_column_found": control,
                        "lde_points": lde_len}));
    }
    println!("{}", json!({"end_to_end": e2e}));
    let report = json!({
        "scope": "unmodified upstream proving@5a7c5ed, full profile, add_zk_blinding x80, production FRI (blowup 2^1, 70 queries); synthetic circuit with private data in qm31_ops, eq, blake_g_gate, triple_xor and m31_to_u32",
        "trace_log_size": pp.trace_log_size(), "rank_audit": findings, "end_to_end": e2e,
    });
    std::fs::write(out.join("report.json"), serde_json::to_vec_pretty(&report).unwrap()).unwrap();
}
