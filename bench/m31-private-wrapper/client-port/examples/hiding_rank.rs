//! Hiding audit, structural check (generalizes `hiding_leak`): is every public linear
//! combination of a component's committed columns reached by the blinding?
//!
//! The same R0 transfer is traced with two blinding seeds, with the lookup challenges fixed
//! across both. For each tree (base trace, interaction trace) and each component (columns of
//! one log size), take the difference of the two traces on the trace domain. A column
//! combination `c` whose value is the same under both seeds on every row satisfies
//! `Δ · c = 0`. Such combinations are unblinded, so the kernel dimension `columns − rank(Δ)`
//! must be 0. Ranks are over M31, so each QM31 interaction column counts as four.
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
use rand::{SeedableRng, rngs::StdRng};
use serde_json::json;
use stwo::core::channel::{Channel, MerkleChannel};
use stwo::core::fields::m31::{M31, P};
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

type Columns = Vec<(u32, Vec<M31>)>;

/// Trace-domain values of the base (tree 1) and interaction (tree 2) columns, with the given
/// interaction challenges.
fn traces(values: &[QM31], pp: &PreprocessedCircuit, elements: &CircuitInteractionElements) -> (Columns, Columns) {
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
    let on_trace_domain = |tree: usize| -> Columns {
        scheme.trees[tree]
            .polynomials
            .iter()
            .map(|p| {
                let coeffs = p.coeffs.as_ref().expect("stored coefficients");
                let log = coeffs.log_size();
                (log, coeffs.evaluate(CanonicCoset::new(log).circle_domain()).values.to_cpu())
            })
            .collect()
    };
    (on_trace_domain(1), on_trace_domain(2))
}

/// Rank over M31 of the rows of `rows` (each of length `n`), and a basis of the combinations
/// `c` with `row · c = 0` for every row.
fn rank_and_kernel(rows: impl Iterator<Item = Vec<u64>>, n: usize) -> (usize, Vec<Vec<u64>>) {
    let p = P as u64;
    let inv = |a: u64| -> u64 {
        let (mut r, mut b, mut e) = (1u64, a % p, p - 2);
        while e > 0 {
            if e & 1 == 1 {
                r = r * b % p;
            }
            b = b * b % p;
            e >>= 1;
        }
        r
    };
    // Reduced row echelon basis, keyed by pivot column.
    let mut basis: Vec<(usize, Vec<u64>)> = vec![];
    for mut row in rows {
        for (piv, b) in &basis {
            let f = row[*piv];
            if f != 0 {
                for j in 0..n {
                    row[j] = (row[j] + p - f * b[j] % p) % p;
                }
            }
        }
        if let Some(piv) = (0..n).find(|&j| row[j] != 0) {
            let s = inv(row[piv]);
            for x in row.iter_mut() {
                *x = *x * s % p;
            }
            for (_, b) in basis.iter_mut() {
                let f = b[piv];
                if f != 0 {
                    for j in 0..n {
                        b[j] = (b[j] + p - f * row[j] % p) % p;
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
    let kernel = (0..n)
        .filter(|j| !pivots.contains(j))
        .map(|free| {
            let mut c = vec![0u64; n];
            c[free] = 1;
            for (piv, b) in &basis {
                c[*piv] = (p - b[free]) % p;
            }
            c
        })
        .collect();
    (basis.len(), kernel)
}

fn audit(name: &str, a: &Columns, b: &Columns) -> serde_json::Value {
    let mut groups = std::collections::BTreeMap::<u32, Vec<usize>>::new();
    for (j, (log, _)) in a.iter().enumerate() {
        groups.entry(*log).or_default().push(j);
    }
    let mut out = vec![];
    for (log, cols) in groups {
        let len = a[cols[0]].1.len();
        let rows = (0..len).map(|i| cols.iter().map(|&j| (a[j].1[i] - b[j].1[i]).0 as u64).collect::<Vec<u64>>());
        let changed = (0..len).filter(|&i| cols.iter().any(|&j| a[j].1[i] != b[j].1[i])).count();
        let (rank, kernel) = rank_and_kernel(rows, cols.len());
        out.push(json!({
            "tree": name, "log_size": log, "columns": cols, "rows_changed_by_seed": changed, "rank": rank,
            "unblinded_combinations": kernel.len(),
            "kernel_basis": kernel.iter().map(|c| c.iter().map(|&x| if x > (P as u64) / 2 { x as i64 - P as i64 } else { x as i64 }).collect::<Vec<_>>()).collect::<Vec<_>>(),
        }));
    }
    json!(out)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let out = std::path::Path::new(args.get(1).map(String::as_str).unwrap_or("target/hiding-rank"));
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
    let a = circuit::<QM31>(&public, &private, [0xa1; 32], blinding);
    let b = circuit::<QM31>(&public, &private, [0xb2; 32], blinding);
    assert!(a.circuit() == b.circuit(), "the seed changed the topology");
    // Challenges from a fixed channel, the same for both traces.
    let channel = &mut <support::MC as MerkleChannel>::C::default();
    channel.mix_felts(&[7_u32.into()]);
    let elements = CircuitInteractionElements::draw(channel);
    let (base_a, inter_a) = traces(a.values(), &pp, &elements);
    let (base_b, inter_b) = traces(b.values(), &pp, &elements);
    let base = audit("base", &base_a, &base_b);
    let inter = audit("interaction", &inter_a, &inter_b);
    let total: u64 = base.as_array().unwrap().iter().chain(inter.as_array().unwrap()).map(|g| g["unblinded_combinations"].as_u64().unwrap()).sum();
    let report = json!({
        "scope": "R0 V2 transfer, arithmetic profile; two blinding seeds, same interaction elements; per component and tree",
        "trace_log_size": pp.trace_log_size(), "blinding_iterations": blinding,
        "base": base, "interaction": inter, "unblinded_combinations_total": total,
    });
    std::fs::write(out.join("report.json"), serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    for g in report["base"].as_array().unwrap().iter().chain(report["interaction"].as_array().unwrap()) {
        println!("{} log{} cols {} changed_rows {} rank {} unblinded {} {:?}", g["tree"], g["log_size"], g["columns"].as_array().unwrap().len(),
                 g["rows_changed_by_seed"], g["rank"], g["unblinded_combinations"], g["kernel_basis"]);
    }
    println!("unblinded_combinations_total {total}");
}
