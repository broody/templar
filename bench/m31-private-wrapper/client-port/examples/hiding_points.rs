//! Hiding audit, per-point rank test for the `qm31_ops` base columns.
//!
//! Every value the verifier sees of a committed column at a point `P` off the trace domain is
//! a linear functional of the trace rows: `p(P) = Σ_i w_P(i) · t[i]` (barycentric weights). The
//! blinding rows of one iteration are (fork `4de7408a6`):
//! `x + 0 = x`, `0 + y = y`, `z + 0 = z`, `x · y`, and the eq yield `e + 0 = e`.
//! We condition on `x` and `e`, a conservative choice. Every revealed functional is then affine
//! in the `y` and `z` limbs (the mul row is linear in `y` for fixed `x`). If the functional
//! matrix restricted to those variables has full row rank, the revealed values are uniform for
//! every witness: exact, for these openings.
//!
//! Points: `K` random LDE points (queries), plus one random out-of-domain point (a QM31
//! evaluation, 4 coordinates). `K = 35` is what a proof opens per column. `K = 560` (35 × 16)
//! pretends every FRI layer-0 coset value were revealed per column, which is conservative.
//! The FRI values themselves are combinations over all trees, and are the next test.
use std::collections::HashMap;
#[path = "support/mod.rs"]
mod support;
use circuit_common::Qm31OpsTraceGenerator;
use circuit_common::preprocessed::PreprocessedCircuit;
use circuit_prover::prover::{BaseColumnPool, SimdBackend};
use circuit_prover::witness::trace::{TraceGenerator, write_trace};
use circuits::context::FinalizedContext;
use circuits::ivalue::NoValue;
use rand::{Rng, SeedableRng, rngs::StdRng};
use serde_json::json;
use stwo::core::channel::{Channel, MerkleChannel};
use stwo::core::circle::CirclePoint;
use stwo::core::fields::m31::{M31, P};
use stwo::core::fields::qm31::{QM31, SecureField};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::utils::MaybeOwned;
use stwo::prover::backend::Column;
use stwo::prover::poly::circle::PolyOps;
use stwo::prover::{CommitmentSchemeProver, CommitmentTreeProver};
use templar_client_verifier_circuit::membership::Lanes;

const PP: u64 = P as u64;

fn circuit<V: Lanes>(w: &support::Witness, seed: [u8; 32], blinding: usize) -> FinalizedContext<V> {
    w.circuit(seed, blinding)
}

/// Base-trace columns on the trace domain (bit-reversed), with log sizes.
fn base_trace(values: &[QM31], pp: &PreprocessedCircuit) -> Vec<(u32, Vec<M31>)> {
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
    let _ = write_trace(values, pp.preprocessed_trace.clone(), pp.n_outputs, &mut builder, &generator, &twiddles);
    builder.commit(channel);
    scheme.trees[1]
        .polynomials
        .iter()
        .map(|p| {
            let c = p.coeffs.as_ref().unwrap();
            (c.log_size(), c.evaluate(CanonicCoset::new(c.log_size()).circle_domain()).values.to_cpu())
        })
        .collect()
}

fn q(t: &[Vec<M31>], cols: &[usize], i: usize) -> QM31 {
    QM31::from_m31_array(std::array::from_fn(|k| t[cols[k]][i]))
}

/// Incremental row-echelon rank over M31 (rows normalized at their pivot).
struct Echelon {
    n: usize,
    rows: Vec<(usize, Vec<u64>)>,
}
impl Echelon {
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
    /// Adds `row`; returns whether it was independent.
    fn push(&mut self, mut row: Vec<u64>) -> bool {
        for (piv, b) in &self.rows {
            let f = row[*piv];
            if f != 0 {
                for j in *piv..self.n {
                    if b[j] != 0 {
                        row[j] = (row[j] + PP - f * b[j] % PP) % PP;
                    }
                }
            }
        }
        match (0..self.n).find(|&j| row[j] != 0) {
            Some(piv) => {
                let s = Self::inv(row[piv]);
                for x in row.iter_mut().skip(piv) {
                    *x = *x * s % PP;
                }
                // Keep pivots sorted so the reduction loop above sees them in order.
                let at = self.rows.partition_point(|(p, _)| *p < piv);
                self.rows.insert(at, (piv, row));
                true
            }
            None => false,
        }
    }
}

fn main() {
    let mut args: Vec<String> = std::env::args().collect();
    let (w, relation) = support::Witness::from_args(&mut args, 11);
    let out = std::path::Path::new(args.get(1).map(String::as_str).unwrap_or("target/hiding-points"));
    let ks: Vec<usize> = args.get(2).map(|s| s.split(',').map(|x| x.parse().unwrap()).collect()).unwrap_or(vec![35, 560]);
    std::fs::create_dir_all(out).unwrap();
    let mut blinding = 0;
    let pp = loop {
        let topology = circuit::<NoValue>(&w, [0; 32], blinding);
        let pp = PreprocessedCircuit::from_finalized_circuit(topology.circuit());
        let need = support::blinding_budget(pp.trace_log_size());
        if blinding >= need {
            break pp;
        }
        blinding = need;
    };
    let a = circuit::<QM31>(&w, [0xa1; 32], blinding);
    let b = circuit::<QM31>(&w, [0xb2; 32], blinding);
    let ta = base_trace(a.values(), &pp);
    let tb = base_trace(b.values(), &pp);
    let log = pp.trace_log_size();
    let cols: Vec<usize> = (0..ta.len()).filter(|&j| ta[j].0 == log).collect();
    assert_eq!(cols.len(), 12);
    let (op0, op1, dst) = (&cols[0..4], &cols[4..8], &cols[8..12]);
    let va: Vec<Vec<M31>> = ta.iter().map(|c| c.1.clone()).collect();
    let vb: Vec<Vec<M31>> = tb.iter().map(|c| c.1.clone()).collect();
    let n = 1usize << log;

    // Classify the blinding rows (rows that change with the seed) by their gate pattern.
    let zero = QM31::from_m31_array([M31::from(0); 4]);
    let changed: Vec<usize> = (0..n).filter(|&i| cols.iter().any(|&j| va[j][i] != vb[j][i])).collect();
    let (mut r_y, mut r_mul, mut r_v) = (vec![], vec![], vec![]);
    for &i in &changed {
        let (x0, x1, d) = (q(&va, op0, i), q(&va, op1, i), q(&va, dst, i));
        if x0 == zero && d == x1 {
            r_y.push(i);
        } else if x1 == zero && d == x0 {
            r_v.push(i);
        } else if d == x0 * x1 {
            r_mul.push(i);
        } else {
            panic!("unclassified blinding row {i}");
        }
    }
    // `x` values are the mul rows' op0; a `v` row whose value is some `x` is an `x + 0` row. The
    // rest are `z + 0` rows or eq yields; we keep as variables only `z` rows (values not seen
    // in the eq component's changed rows), and condition on the eq yields.
    let xs: std::collections::HashSet<QM31> = r_mul.iter().map(|&i| q(&va, op0, i)).collect();
    let eq_cols: Vec<usize> = (0..ta.len()).filter(|&j| ta[j].0 != log).collect();
    let eq_len = va[eq_cols[0]].len();
    let eq_vals: std::collections::HashSet<QM31> = (0..eq_len)
        .filter(|&i| eq_cols.iter().any(|&j| va[j][i] != vb[j][i]))
        .map(|i| QM31::from_m31_array(std::array::from_fn(|k| va[eq_cols[k]][i])))
        .collect();
    let r_z: Vec<usize> = r_v.iter().copied().filter(|&i| !xs.contains(&q(&va, op0, i)) && !eq_vals.contains(&q(&va, op0, i))).collect();
    let n_x_rows = r_v.iter().filter(|&&i| xs.contains(&q(&va, op0, i))).count();
    let n_e_rows = r_v.iter().filter(|&&i| eq_vals.contains(&q(&va, op0, i))).count();
    // Variables: y per iteration (shared by its `0 + y` and mul rows), z per `z + 0` row.
    let mut y_index: HashMap<QM31, usize> = HashMap::new();
    for &i in r_y.iter().chain(&r_mul) {
        let y = q(&va, op1, i);
        let next = y_index.len();
        y_index.entry(y).or_insert(next);
    }
    let n_y = y_index.len();
    let n_vars = 4 * (n_y + r_z.len());
    let yv = |i: usize, l: usize| 4 * y_index[&q(&va, op1, i)] + l;
    let zpos: HashMap<usize, usize> = r_z.iter().enumerate().map(|(k, &i)| (i, k)).collect();
    let zv = |i: usize, l: usize| 4 * (n_y + zpos[&i]) + l;
    let classes = json!({"rows_changed": changed.len(), "zero_plus_y": r_y.len(), "mul": r_mul.len(), "x_plus_zero": n_x_rows,
                         "eq_yield": n_e_rows, "z_plus_zero": r_z.len(), "y_vars": n_y, "m31_variables": n_vars});
    println!("{classes}");

    let coset = CanonicCoset::new(log);
    let lde = CanonicCoset::new(log + support::config(log).fri_config.log_blowup_factor).circle_domain();
    let mut rng = StdRng::seed_from_u64(99);
    let channel = &mut <support::MC as MerkleChannel>::C::default();
    channel.mix_felts(&[123_u32.into()]);
    let oods: CirclePoint<SecureField> = CirclePoint::get_random_point(channel);
    let mut results = vec![];
    for &k in &ks {
        let mut points: Vec<CirclePoint<SecureField>> = (0..k).map(|_| lde.at(rng.gen_range(0..lde.size())).into_ef()).collect();
        points.push(oods);
        let mut ech = Echelon { n: n_vars, rows: vec![] };
        let (mut total, mut independent) = (0usize, 0usize);
        let started = std::time::Instant::now();
        for p in &points {
            let w = SimdBackend::barycentric_weights(coset, *p).to_cpu();
            let wm: [Vec<M31>; 4] = std::array::from_fn(|m| w.columns[m].clone());
            let coords: Vec<usize> = (0..4).filter(|&m| wm[m].iter().any(|v| v.0 != 0)).collect();
            for &m in &coords {
                for kk in 0..4 {
                    // op0 limb kk: z rows.
                    let mut r0 = vec![0u64; n_vars];
                    for &i in &r_z {
                        r0[zv(i, kk)] = wm[m][i].0 as u64;
                    }
                    // op1 limb kk: y rows and mul rows.
                    let mut r1 = vec![0u64; n_vars];
                    for &i in r_y.iter().chain(&r_mul) {
                        r1[yv(i, kk)] = (r1[yv(i, kk)] + wm[m][i].0 as u64) % PP;
                    }
                    // dst limb kk: y rows, z rows, and (x · y)[kk] on mul rows.
                    let mut r2 = vec![0u64; n_vars];
                    for &i in &r_y {
                        r2[yv(i, kk)] = (r2[yv(i, kk)] + wm[m][i].0 as u64) % PP;
                    }
                    for &i in &r_z {
                        r2[zv(i, kk)] = (r2[zv(i, kk)] + wm[m][i].0 as u64) % PP;
                    }
                    for &i in &r_mul {
                        let x = q(&va, op0, i);
                        for l in 0..4 {
                            let mut e = [M31::from(0); 4];
                            e[l] = M31::from(1);
                            let coef = (x * QM31::from_m31_array(e)).to_m31_array()[kk].0 as u64;
                            let v = &mut r2[yv(i, l)];
                            *v = (*v + coef * wm[m][i].0 as u64) % PP;
                        }
                    }
                    for r in [r0, r1, r2] {
                        total += 1;
                        independent += ech.push(r) as usize;
                    }
                }
            }
        }
        let r = json!({"lde_points": k, "oods_points": 1, "functionals": total, "rank": independent,
                       "full_rank": independent == total, "seconds": started.elapsed().as_secs_f64()});
        println!("{r}");
        results.push(r);
    }
    let report = json!({
        "relation": relation,
        "scope": "per-point rank test, qm31_ops base columns, R0 V2 transfer, fork 4de7408a6 blinding; conditioned on x and eq yields",
        "trace_log_size": log, "blinding_iterations": blinding, "classes": classes, "results": results,
    });
    std::fs::write(out.join("report.json"), serde_json::to_vec_pretty(&report).unwrap()).unwrap();
}
