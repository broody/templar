//! Hiding audit, empirical invariant search over every committed column (base and interaction
//! trees, `qm31_ops` and `eq`): is any linear combination of revealed values independent of
//! the blinding seed?
//!
//! One R0 transfer witness is traced under many seeds, with the lookup challenges fixed. Every
//! column is evaluated at fixed random points: 4 points of its LDE domain, the OODS point `z`,
//! and `z` shifted back one trace step (the previous-row mask), with 4 M31 coordinates each off
//! the base field. `v_s` is the vector of all those values for seed `s`. A combination `c` with
//! `c · v_s` the same for every seed is a seed-independent (witness-only) functional; the rank
//! of `{v_s − v_0}` falls short of the functional count by exactly the number of such
//! combinations. This samples the real distribution instead of linearizing it, so it reaches
//! the interaction (LogUp) columns, which are nonlinear in the blinding. It is H2's check,
//! generalized, at a few points.
#[path = "support/mod.rs"]
mod support;
use circuit_common::Qm31OpsTraceGenerator;
use circuit_common::finalize::{Profile, add_zk_blinding_for, pad_context_for};
use circuit_common::preprocessed::PreprocessedCircuit;
use circuit_prover::prover::{BaseColumnPool, SimdBackend};
use circuit_prover::witness::trace::{TraceGenerator, write_interaction_trace, write_trace};
use circuit_verifier::circuit_claim::CircuitInteractionElements;
use circuits::context::{Context, FinalizedContext};
use circuits::ivalue::NoValue;
use rand::{Rng, SeedableRng, rngs::StdRng};
use serde_json::json;
use stwo::core::channel::{Channel, MerkleChannel};
use stwo::core::circle::CirclePoint;
use stwo::core::fields::m31::P;
use stwo::core::fields::qm31::{QM31, SecureField};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::utils::MaybeOwned;
use stwo::prover::poly::circle::PolyOps;
use stwo::prover::{CommitmentSchemeProver, CommitmentTreeProver};
use templar_client_verifier_circuit::membership::Lanes;
use templar_client_verifier_circuit::payment::{self, N_OUTPUTS, Private, Public, Shape, Tree};

const TREE: Tree = Tree::Compress;
const PP: u64 = P as u64;

fn circuit<V: Lanes>(public: &Public, private: &Private, seed: [u8; 32], blinding: usize) -> FinalizedContext<V> {
    let mut c = Context::<V>::new(N_OUTPUTS);
    let outputs = payment::build(&mut c, TREE, public, private);
    c.set_outputs(&outputs);
    let mut c = c.finalize(true);
    add_zk_blinding_for(&mut c, seed, blinding, Profile::Arithmetic);
    pad_context_for(&mut c, Profile::Arithmetic);
    c
}

/// Per column of trees 1 and 2: (tree, log size, values at the column's points).
fn evaluate(values: &[QM31], pp: &PreprocessedCircuit, elements: &CircuitInteractionElements,
            points: &dyn Fn(u32) -> Vec<CirclePoint<SecureField>>) -> Vec<(usize, u32, Vec<SecureField>)> {
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
    scheme.set_store_polynomials_coefficients();
    scheme.commit_tree(MaybeOwned::Owned(pp_tree), channel);
    let mut builder = scheme.tree_builder();
    let (_, log_sizes, igen) = write_trace(values, pp.preprocessed_trace.clone(), pp.n_outputs, &mut builder, &generator, &twiddles);
    builder.commit(channel);
    let mut builder = scheme.tree_builder();
    let _ = write_interaction_trace(&log_sizes, igen, &mut builder, elements, &twiddles);
    builder.commit(channel);
    let mut out = vec![];
    for tree in [1, 2] {
        for p in scheme.trees[tree].polynomials.iter() {
            let c = p.coeffs.as_ref().unwrap();
            out.push((tree, c.log_size(), points(c.log_size()).into_iter().map(|pt| c.eval_at_point(pt)).collect()));
        }
    }
    out
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let out = std::path::Path::new(args.get(1).map(String::as_str).unwrap_or("target/hiding-invariants"));
    let n_lde: usize = args.get(2).map(|s| s.parse().unwrap()).unwrap_or(4);
    let extra_seeds: usize = args.get(3).map(|s| s.parse().unwrap()).unwrap_or(30);
    std::fs::create_dir_all(out).unwrap();
    let (public, private) = payment::fresh_shape(TREE, Shape::Transfer, &mut StdRng::seed_from_u64(11));
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
    let channel = &mut <support::MC as MerkleChannel>::C::default();
    channel.mix_felts(&[7_u32.into()]);
    let elements = CircuitInteractionElements::draw(channel);
    let z: CirclePoint<SecureField> = CirclePoint::get_random_point(channel);
    let blowup = support::config(pp.trace_log_size()).fri_config.log_blowup_factor;
    // Fixed points per log size: LDE points, then z and z minus one trace step.
    let points = |log: u32| -> Vec<CirclePoint<SecureField>> {
        let mut rng = StdRng::seed_from_u64(1000 + log as u64);
        let lde = CanonicCoset::new(log + blowup).circle_domain();
        let mut v: Vec<CirclePoint<SecureField>> = (0..n_lde).map(|_| lde.at(rng.gen_range(0..lde.size())).into_ef()).collect();
        v.push(z);
        v.push(z - CanonicCoset::new(log).step().into_ef());
        v
    };
    // Functional layout: per column, per point: 1 coordinate at LDE points, 4 at z and z−step.
    let coords_per_column = n_lde + 8;
    let flatten = |cols: &Vec<(usize, u32, Vec<SecureField>)>| -> Vec<u64> {
        let mut v = vec![];
        for (_, _, vals) in cols {
            for (k, x) in vals.iter().enumerate() {
                let a = x.to_m31_array();
                if k < n_lde {
                    assert!(a[1..].iter().all(|m| m.0 == 0));
                    v.push(a[0].0 as u64);
                } else {
                    v.extend(a.iter().map(|m| m.0 as u64));
                }
            }
        }
        v
    };
    let base_values = circuit::<QM31>(&public, &private, [0; 32], blinding);
    let v0_cols = evaluate(base_values.values(), &pp, &elements, &points);
    let layout: Vec<(usize, u32)> = v0_cols.iter().map(|(t, l, _)| (*t, *l)).collect();
    let v0 = flatten(&v0_cols);
    let n = v0.len();
    assert_eq!(n, layout.len() * coords_per_column);
    println!("{}", json!({"columns": layout, "functionals": n}));
    // Incremental echelon basis of differences.
    let inv = |a: u64| -> u64 {
        let (mut r, mut b, mut e) = (1u64, a % PP, PP - 2);
        while e > 0 {
            if e & 1 == 1 {
                r = r * b % PP;
            }
            b = b * b % PP;
            e >>= 1;
        }
        r
    };
    let mut basis: Vec<(usize, Vec<u64>)> = vec![];
    let started = std::time::Instant::now();
    let mut seeds = 0;
    while seeds < n + extra_seeds {
        seeds += 1;
        let mut seed = [0u8; 32];
        seed[..8].copy_from_slice(&(seeds as u64).to_le_bytes());
        seed[8] = 0x5e;
        let c = circuit::<QM31>(&public, &private, seed, blinding);
        let v = flatten(&evaluate(c.values(), &pp, &elements, &points));
        let mut row: Vec<u64> = (0..n).map(|j| (v[j] + PP - v0[j]) % PP).collect();
        for (piv, b) in &basis {
            let f = row[*piv];
            if f != 0 {
                for j in *piv..n {
                    row[j] = (row[j] + PP - f * b[j] % PP) % PP;
                }
            }
        }
        if let Some(piv) = (0..n).find(|&j| row[j] != 0) {
            let s = inv(row[piv]);
            for x in row.iter_mut().skip(piv) {
                *x = *x * s % PP;
            }
            let at = basis.partition_point(|(p, _)| *p < piv);
            basis.insert(at, (piv, row));
        }
        if seeds % 25 == 0 {
            println!("{}", json!({"seeds": seeds, "rank": basis.len(), "seconds": started.elapsed().as_secs_f64()}));
        }
        if basis.len() == n && seeds >= n {
            break;
        }
    }
    // Which functionals are never reached: columns without a pivot, grouped by column.
    let pivots: std::collections::HashSet<usize> = basis.iter().map(|(p, _)| *p).collect();
    let missing: Vec<serde_json::Value> = (0..n).filter(|j| !pivots.contains(j))
        .map(|j| json!({"column": j / coords_per_column, "tree_log": layout[j / coords_per_column], "coord": j % coords_per_column})).collect();
    let report = json!({
        "scope": "seed-invariant linear combinations of revealed values, base + interaction trees, qm31_ops + eq; R0 V2 transfer; fork 4de7408a6",
        "lde_points_per_column": n_lde, "oods_points": ["z", "z - step"], "columns": layout.len(), "functionals": n,
        "seeds": seeds, "rank": basis.len(), "seed_invariant_combinations": n - basis.len(),
        "pivotless_functionals": missing, "seconds": started.elapsed().as_secs_f64(),
    });
    std::fs::write(out.join("report.json"), serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    println!("{}", json!({"functionals": n, "seeds": seeds, "rank": basis.len(), "seed_invariant_combinations": n - basis.len()}));
}
