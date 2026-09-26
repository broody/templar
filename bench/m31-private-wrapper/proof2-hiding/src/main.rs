//! H2/H4 on PROOF2's leaf-verifier circuit, as the prover server pins it
//! (broody/proving@b54ed94f, `target/proving-server`). Private: the findings are undisclosed.
//!
//! `templar-proof2-hiding JOB_DIR OUT_DIR` takes a prover-server job (`os.pie.zip`, `proof.bin`):
//!
//! 1. **The real PROOF2.** Runs the Cairo stage as `prove_leaf_bounded` does, builds the leaf
//!    verifier circuit, blinds it with the seed the leaf prover derives (the Cairo trace root),
//!    pads it to the registry's targets and proves it (bounded, 16 columns). The uncompressed
//!    circuit proof must equal the job's `proof.bin` payload, so what follows is about the proof
//!    that was actually produced.
//! 2. **Rank audit.** The same circuit blinded with a second seed, traced with proof A's own
//!    lookup challenges (replayed from its transcript, checked against its roots). Per tree and
//!    log size, the kernel of the seed difference is the set of public column combinations the
//!    blinding never reaches. Each kernel vector is classified as a constraint identity (zero on
//!    every row) or witness-dependent (a leak).
//! 3. **End to end.** For each tree with witness-dependent combinations, evaluate them all on
//!    each query's opened values in proof A and look the tuple up in seed B's committed
//!    extension. A control does the same lookup with as many single columns.
//! 4. **Three seeds.** The audit again with a third seed: combinations two seeds agree on only by
//!    counting (more independent columns than blinding rows) drop out; seed-invariant ones stay.
use std::collections::{BTreeMap, HashSet};
use std::path::Path;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Instant;

use cairo_program_runner_lib::types::{HashFunc, PrivacySimpleBootloaderInput, SimpleBootloaderInput};
use cairo_program_runner_lib::utils::get_cairo_run_config;
use cairo_program_runner_lib::{ProgramInput, Task, TaskSpec, cairo_run_program};
use cairo_vm::types::layout_name::LayoutName;
use cairo_vm::types::program::Program;
use cairo_vm::vm::runners::cairo_pie::CairoPie;
use circuit_cairo_verifier::statement::{MEMORY_VALUES_LIMBS, N_OUTPUTS, N_WORDS_PER_OUTPUT_CELL};
use circuit_cairo_verifier::verify::{NON_QUERY_INFO_LEAK, build_and_fill_cairo_verifier_circuit, prepare_cairo_proof_for_circuit_verifier};
use circuit_common::Qm31OpsTraceGenerator;
use circuit_common::finalize::{add_zk_blinding, pad_to_targets};
use circuit_common::preprocessed::PreprocessedCircuit;
use circuit_prover::circuit_hash::compute_circuit_hash;
use circuit_prover::prover::{BaseColumnPool, SimdBackend, prepare_circuit_proof_for_circuit_verifier, prove_circuit_assignment_bounded_with};
use circuit_prover::witness::trace::{TraceGenerator, write_interaction_trace, write_trace};
use circuit_serialize::serialize::CircuitSerialize;
use circuit_verifier::circuit_claim::{CircuitInteractionElements, mix_circuit_hash};
use circuits::context::FinalizedContext;
use circuits::ivalue::IValue;
use circuits::utils::bytes_from_le_u32s;
use leaf_prover::prove_leaf::leaf_verifier_config;
use privacy_circuit_verify::utils::ProofHeader;
use privacy_circuit_verify::{get_large_proofs_circuit_registry, get_leaf_bootloader_program};
use rayon::prelude::*;
use serde_json::json;
use stwo::core::channel::{Channel, MerkleChannel};
use stwo::core::fields::m31::{M31, P};
use stwo::core::fields::qm31::QM31;
use stwo::core::pcs::PcsConfig;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::utils::MaybeOwned;
use stwo::core::vcs::blake2_hash::Blake2sHash;
use stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleChannel;
use stwo::core::verifier::PREPROCESSED_TRACE_IDX;
use stwo::prover::backend::Column;
use stwo::prover::poly::circle::PolyOps;
use stwo::prover::{CommitmentSchemeProver, CommitmentTreeProver};
use stwo_cairo_adapter::adapter::adapt;
use stwo_cairo_prover::prover::prove_cairo_bounded;
use stwo_cairo_prover::witness::prelude::Felt252;

type MC = Blake2sM31MerkleChannel;
type Ch = <MC as MerkleChannel>::C;
const PP: u64 = P as u64;

fn program_felts(program: &Program) -> Vec<[M31; MEMORY_VALUES_LIMBS]> {
    program.iter_data().map(|v| Felt252::from(v.get_int().unwrap()).get_limbs()).collect()
}

struct Col {
    log: u32,
    trace: Vec<M31>,
    lde: Vec<M31>,
}

struct Traces {
    base: Vec<Col>,
    inter: Vec<Col>,
    roots: Vec<String>,
    /// The channel right before the interaction elements are drawn.
    draw_channel: Ch,
}

enum Challenges {
    /// Replay the prover's transcript with this interaction PoW nonce.
    Replay(u64),
    /// Draw from this channel state (another trace's).
    From(Ch),
}

/// The circuit prover's first three commitments, as `prove_circuit_with_precompute_bounded`
/// makes them, keeping each committed column's trace-domain values (and its committed extension
/// if `keep_lde`).
fn traces(values: &[QM31], pp: &PreprocessedCircuit, pcs: PcsConfig, challenges: Challenges, keep_lde: bool) -> Traces {
    let pool = BaseColumnPool::<SimdBackend>::new();
    let twiddles = SimdBackend::precompute_twiddles(
        CanonicCoset::new(pp.trace_log_size + pcs.fri_config.log_blowup_factor.max(1)).circle_domain().half_coset,
    );
    let polys = SimdBackend::interpolate_columns(pp.preprocessed_trace.get_trace::<SimdBackend>(), &twiddles);
    let pp_tree = CommitmentTreeProver::<SimdBackend, MC>::new(
        polys, pcs.fri_config.log_blowup_factor, &twiddles, true, pcs.preprocessed_lifting_log_size, &pool,
    );
    let generator = TraceGenerator { qm31_ops_trace_generator: Qm31OpsTraceGenerator { first_permutation_row: pp.first_permutation_row } };
    let channel = &mut Ch::default();
    channel.mix_felts(&[0_u32.into()]);
    pcs.mix_into(channel);
    let mut scheme = CommitmentSchemeProver::<SimdBackend, MC>::with_memory_pool(pcs, &twiddles, &pool);
    scheme.set_store_polynomials_coefficients();
    let pp_root: Blake2sHash = pp_tree.commitment.root().into();
    scheme.commit_tree(MaybeOwned::Owned(pp_tree), channel);
    let mut builder = scheme.tree_builder();
    let (claim, log_sizes, igen) = write_trace(values, pp.preprocessed_trace.clone(), pp.n_outputs, &mut builder, &generator, &twiddles);
    let circuit_hash = compute_circuit_hash(&log_sizes, pcs.fri_config.log_blowup_factor, pp_root);
    mix_circuit_hash(channel, &circuit_hash);
    claim.mix_into(channel);
    builder.commit(channel);
    let draw_channel = match challenges {
        Challenges::Replay(nonce) => {
            channel.mix_u64(nonce);
            channel.clone()
        }
        Challenges::From(c) => c,
    };
    let elements = CircuitInteractionElements::draw(&mut draw_channel.clone());
    let mut builder = scheme.tree_builder();
    let _ = write_interaction_trace(&log_sizes, igen, &mut builder, &elements, &twiddles);
    builder.commit(channel);
    let roots = (0..3).map(|t| format!("{:?}", scheme.trees[t].commitment.root())).collect();
    let cols = |tree: usize| -> Vec<Col> {
        scheme.trees[tree]
            .polynomials
            .iter()
            .map(|p| {
                let c = p.coeffs.as_ref().expect("stored coefficients");
                let log = c.log_size();
                Col {
                    log,
                    trace: c.evaluate(CanonicCoset::new(log).circle_domain()).values.to_cpu(),
                    lde: if keep_lde { p.evals.as_ref().expect("evaluations").values.to_cpu() } else { vec![] },
                }
            })
            .collect()
    };
    let (base, inter) = (cols(1), cols(2));
    Traces { base, inter, roots, draw_channel }
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

fn dot(c: &[u64], cols: &[usize], t: &[Col], i: usize, lde: bool) -> u64 {
    cols.iter().enumerate().fold(0u64, |acc, (k, &j)| {
        let v = if lde { t[j].lde[i].0 } else { t[j].trace[i].0 };
        (acc + c[k] * v as u64) % PP
    })
}

fn diff_row(cols: &[usize], a: &[Col], b: &[Col], i: usize) -> Vec<u64> {
    cols.iter().map(|&j| (a[j].trace[i] - b[j].trace[i]).0 as u64).collect()
}

/// Bits needed for the largest value of column `j` over `rows`.
fn bits(t: &[Col], j: usize, rows: &[usize]) -> u32 {
    rows.par_iter().map(|&i| t[j].trace[i].0).max().map_or(0, |m| 32 - m.leading_zeros())
}

/// A tree's witness-dependent kernel vectors: (columns of the group, vector).
type Leaks = Vec<(Vec<usize>, Vec<u64>)>;

/// Per log size: the kernel of the seed differences (seed A against each of `others`), computed
/// on a sample of the changed rows and then checked on every row (rows that break a candidate join
/// the sample until none do).
fn audit(tree: &str, a: &[Col], others: &[&[Col]]) -> (Vec<serde_json::Value>, Leaks) {
    let mut groups = BTreeMap::<u32, Vec<usize>>::new();
    for (j, c) in a.iter().enumerate() {
        groups.entry(c.log).or_default().push(j);
    }
    let (mut out, mut leaks) = (vec![], vec![]);
    for (log, cols) in groups {
        let start = Instant::now();
        let len = a[cols[0]].trace.len();
        let changed: Vec<usize> =
            (0..len).into_par_iter().filter(|&i| others.iter().any(|b| cols.iter().any(|&j| a[j].trace[i] != b[j].trace[i]))).collect();
        let step = (changed.len() / 50_000).max(1);
        let mut sample: Vec<usize> = changed.iter().take(50_000).chain(changed.iter().step_by(step)).copied().collect();
        let (ker, rounds) = {
            let mut rounds = 0;
            loop {
                rounds += 1;
                let cols_ref = &cols;
                let ker = kernel(sample.iter().flat_map(|&i| others.iter().map(move |b| diff_row(cols_ref, a, b, i))), cols.len());
                let broken: Vec<usize> = changed
                    .par_iter()
                    .copied()
                    .filter(|&i| {
                        others.iter().any(|b| {
                            let d = diff_row(&cols, a, b, i);
                            ker.iter().any(|c| c.iter().zip(&d).fold(0u64, |acc, (x, y)| (acc + x * y) % PP) != 0)
                        })
                    })
                    .collect();
                if broken.is_empty() {
                    break (ker, rounds);
                }
                sample.extend(broken.iter().take(1000));
            }
        };
        // Value widths: on the rows the seeds change (blinding, for the base tree) and on all rows.
        let all: Vec<usize> = (0..len).collect();
        let widths: Vec<(usize, u32, u32)> =
            if tree == "base" { cols.iter().map(|&j| (j, bits(a, j, &changed), bits(a, j, &all))).collect() } else { vec![] };
        let mut classified = vec![];
        for c in &ker {
            let nonzero_rows = (0..len).into_par_iter().filter(|&i| dot(c, &cols, a, i, false) != 0).count();
            let support: Vec<(usize, i64)> = cols.iter().enumerate().filter(|(k, _)| c[*k] != 0).map(|(k, &j)| (j, signed(c[k]))).collect();
            if nonzero_rows > 0 {
                leaks.push((cols.clone(), c.clone()));
            }
            classified.push(json!({"support": support, "nonzero_rows": nonzero_rows,
                                   "kind": if nonzero_rows == 0 { "constraint identity" } else { "witness-dependent" }}));
        }
        let wd = classified.iter().filter(|k| k["kind"] == "witness-dependent").count();
        println!("{tree} log{log} seeds {} cols {} changed_rows {} rank {} unblinded {} witness-dependent {wd} ({:.1}s, {rounds} rounds)",
                 others.len() + 1, cols.len(), changed.len(), cols.len() - ker.len(), ker.len(), start.elapsed().as_secs_f64());
        out.push(json!({"tree": tree, "log_size": log, "columns": [cols[0], cols[cols.len() - 1]], "n_columns": cols.len(),
                        "rows": len, "rows_changed_by_seed": changed.len(), "rank": cols.len() - ker.len(), "unblinded": ker.len(),
                        "witness_dependent": wd, "seeds": others.len() + 1, "kernel": classified,
                        "value_bits_changed_rows_and_all_rows": widths}));
    }
    (out, leaks)
}

/// Looks up, for each query of proof A, the tuple of all of a group's witness-dependent
/// combinations in seed B's committed extension; the control looks up as many single columns.
fn end_to_end(tree: &str, leaks: &Leaks, queried: &[Vec<M31>], b: &[Col]) -> Vec<serde_json::Value> {
    let mut by_group = BTreeMap::<Vec<usize>, Vec<Vec<u64>>>::new();
    for (cols, c) in leaks {
        by_group.entry(cols.clone()).or_default().push(c.clone());
    }
    let mut out = vec![];
    for (cols, vecs) in by_group {
        let lde_len = b[cols[0]].lde.len();
        let n_q = queried[cols[0]].len();
        let opened = |q: usize, c: &[u64]| cols.iter().enumerate().fold(0u64, |acc, (k, &j)| (acc + c[k] * queried[j][q].0 as u64) % PP);
        let set_b: HashSet<Vec<u64>> = (0..lde_len).into_par_iter().map(|i| vecs.iter().map(|c| dot(c, &cols, b, i, true)).collect()).collect();
        let hits = (0..n_q).filter(|&q| set_b.contains(&vecs.iter().map(|c| opened(q, c)).collect::<Vec<u64>>())).count();
        drop(set_b);
        // Control: the first columns of the combinations' support, one per combination.
        let mut control_cols: Vec<usize> = vec![];
        for c in &vecs {
            if let Some(k) = (0..cols.len()).find(|&k| c[k] != 0 && !control_cols.contains(&cols[k])) {
                control_cols.push(cols[k]);
            }
        }
        let set_c: HashSet<Vec<u32>> = (0..lde_len).into_par_iter().map(|i| control_cols.iter().map(|&j| b[j].lde[i].0).collect()).collect();
        let control = (0..n_q).filter(|&q| set_c.contains(&control_cols.iter().map(|&j| queried[j][q].0).collect::<Vec<u32>>())).count();
        println!("{tree} end to end: {} combinations over {} columns: {hits}/{n_q} queries found in seed B's extension ({lde_len} points); control {control}/{n_q}",
                 vecs.len(), cols.len());
        out.push(json!({"tree": tree, "columns": [cols[0], cols[cols.len() - 1]], "combinations": vecs.len(), "queries": n_q,
                        "tuple_found_in_seed_b": hits, "control_columns": control_cols, "control_found": control, "lde_points": lde_len}));
    }
    out
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let job = Path::new(args.get(1).expect("usage: templar-proof2-hiding JOB_DIR OUT_DIR"));
    let out = Path::new(args.get(2).expect("usage: templar-proof2-hiding JOB_DIR OUT_DIR")).to_path_buf();
    std::fs::create_dir_all(&out).unwrap();
    let t0 = Instant::now();
    let lap = |what: &str| println!("[{:.0}s] {what}", t0.elapsed().as_secs_f64());

    // 1. The Cairo stage, as `prove_leaf_bounded` runs it.
    let pie = CairoPie::read_zip_file(&job.join("os.pie.zip")).unwrap();
    let program = get_leaf_bootloader_program().unwrap();
    let registry = get_large_proofs_circuit_registry();
    let preimage = tempfile::NamedTempFile::new_in(&out).unwrap();
    let input = PrivacySimpleBootloaderInput {
        simple_bootloader_input: SimpleBootloaderInput {
            fact_topologies_path: None,
            single_page: true,
            tasks: vec![TaskSpec { task: Rc::new(Task::Pie(pie)), program_hash_function: HashFunc::Blake }],
        },
        output_preimage_dump_path: preimage.path().to_path_buf(),
    };
    let run_config = get_cairo_run_config(&None, LayoutName::all_cairo_stwo, true, true, true, false).unwrap();
    let runner = cairo_run_program(&program, Some(ProgramInput::Value(Box::new(input))), run_config, None).unwrap();
    let prover_input = adapt(&runner).unwrap();
    drop(runner);
    let output = prover_input.builtin_segments.output.unwrap();
    let cells: Vec<[u32; 8]> = (output.begin_addr..output.stop_ptr).map(|a| prover_input.memory.get(a.try_into().unwrap()).as_u256()).collect();
    assert_eq!(cells.len(), N_OUTPUTS);
    let mut words = [0u32; N_OUTPUTS * N_WORDS_PER_OUTPUT_CELL];
    for (chunk, cell) in words.chunks_exact_mut(N_WORDS_PER_OUTPUT_CELL).zip(&cells) {
        chunk.copy_from_slice(&cell[..N_WORDS_PER_OUTPUT_CELL]);
    }
    let output_hash = Blake2sHash::from(words);
    let params = registry.cairo_prover_params;
    let cairo_proof = prove_cairo_bounded::<MC>(prover_input, params, Some(16), false).unwrap();
    lap("Cairo proof");
    let cairo_pp_root = cairo_proof.extended_stark_proof.proof.commitments[PREPROCESSED_TRACE_IDX];
    let cairo_pcs = cairo_proof.extended_stark_proof.proof.config;
    let trace_log_size = cairo_pcs.trace_lifting_log_size - cairo_pcs.fri_config.log_blowup_factor;
    let entry = registry.leaf_verifier(trace_log_size).unwrap();
    let circuit_cfg = registry.config(&entry.config).unwrap();
    assert!(entry.zk_blinding);
    let n_blinding = circuit_cfg.fri_config.n_queries + NON_QUERY_INFO_LEAK;
    // Blinding is added by hand below, with the leaf prover's seed or another one.
    let verifier_config = leaf_verifier_config(params.preprocessed_trace, &cairo_pcs, Arc::from(program_felts(&program)), cairo_pp_root.into(), None);
    let (proof_for_circuit, aux) = prepare_cairo_proof_for_circuit_verifier(&cairo_proof, &verifier_config.enabled_bits);
    drop(cairo_proof);
    // The leaf prover's seed: the Cairo proof's trace root (`build_and_fill_cairo_verifier_circuit`).
    let seed_a = bytes_from_le_u32s(proof_for_circuit.trace_root.0.map(|w| w.get().unpack_u32()));
    let seed_b = seed_a.map(|x| x ^ 0x5a);
    let build = |seed: [u8; 32]| -> (FinalizedContext<QM31>, PreprocessedCircuit) {
        let mut ctx = build_and_fill_cairo_verifier_circuit(&verifier_config, proof_for_circuit.clone(), aux.clone(), output_hash);
        add_zk_blinding(&mut ctx, seed, n_blinding);
        pad_to_targets(&mut ctx, &circuit_cfg.target_sizes());
        assert!(ctx.is_circuit_valid(), "the verifier circuit rejected the proof");
        let pp = PreprocessedCircuit::preprocess_circuit(&mut ctx);
        (ctx, pp)
    };
    let (ctx_a, pp) = build(seed_a);
    lap("leaf circuit, seed A (the leaf prover's)");

    // The real PROOF2, bounded as the server proves it.
    let pcs = PcsConfig::from_fri_and_trace_size(circuit_cfg.fri_config, pp.trace_log_size);
    let proof_a = prove_circuit_assignment_bounded_with::<MC>(ctx_a.values(), &pp, &BaseColumnPool::new(), pcs, Some(16), false).unwrap();
    lap("circuit proof A");
    let commitments: Vec<String> = proof_a.stark_proof.proof.commitments.iter().map(|c| format!("{c:?}")).collect();
    let queried = proof_a.stark_proof.proof.queried_values.clone();
    let nonce = proof_a.interaction_pow_nonce;
    let circuit_hash = format!("{:?}", proof_a.circuit_hash);
    let (qm31s, _) = prepare_circuit_proof_for_circuit_verifier(proof_a);
    let mut uncompressed = vec![];
    qm31s.serialize(&mut uncompressed);
    let job_proof = std::fs::read(job.join("proof.bin")).unwrap();
    let job_payload = zstd::decode_all(&job_proof[ProofHeader::SIZE..]).unwrap();
    let reproduced = uncompressed == job_payload;
    println!("reproduces the job's PROOF2: {reproduced} ({} bytes uncompressed)", uncompressed.len());
    assert!(reproduced, "the harness does not reproduce the job's proof");

    // 2. Rank audit: seed A (replaying proof A's transcript) and seed B with the same challenges.
    let ta = traces(ctx_a.values(), &pp, pcs, Challenges::Replay(nonce), false);
    drop(ctx_a);
    assert_eq!(ta.roots, commitments[..3].to_vec(), "the replayed transcript differs from proof A");
    lap("traces A (roots match proof A)");
    let (ctx_b, pp_b) = build(seed_b);
    assert!(pp_b.preprocessed_trace.ids() == pp.preprocessed_trace.ids() && pp_b.trace_log_size == pp.trace_log_size);
    let tb = traces(ctx_b.values(), &pp_b, pcs, Challenges::From(ta.draw_channel.clone()), true);
    drop(ctx_b);
    assert_eq!(ta.roots[0], tb.roots[0], "the seed changed the preprocessed trace");
    lap("traces B");
    println!("{}", json!({"trace_log_size": pp.trace_log_size, "n_blinding": n_blinding,
                          "base_column_logs": ta.base.iter().map(|c| c.log).collect::<Vec<_>>(),
                          "interaction_column_logs": ta.inter.iter().map(|c| c.log).collect::<Vec<_>>()}));
    let (base, base_leaks) = audit("base", &ta.base, &[&tb.base]);
    let (inter, inter_leaks) = audit("interaction", &ta.inter, &[&tb.inter]);
    lap("rank audit, two seeds");

    // 3. End to end against proof A's opened values.
    let mut e2e = end_to_end("base", &base_leaks, &queried[1], &tb.base);
    e2e.extend(end_to_end("interaction", &inter_leaks, &queried[2], &tb.inter));
    lap("end to end");

    // A two-seed kernel also holds combinations that only these two seeds happen to agree on
    // (a component with more independent columns than blinding rows). A third seed removes them;
    // what stays is seed-invariant.
    let mut tb = tb;
    tb.base.iter_mut().chain(tb.inter.iter_mut()).for_each(|c| c.lde = vec![]);
    let seed_c = seed_a.map(|x| x ^ 0xc3);
    let (ctx_c, pp_c) = build(seed_c);
    assert!(pp_c.preprocessed_trace.ids() == pp.preprocessed_trace.ids());
    let tc = traces(ctx_c.values(), &pp_c, pcs, Challenges::From(ta.draw_channel.clone()), false);
    drop(ctx_c);
    lap("traces C");
    let (base3, _) = audit("base", &ta.base, &[&tb.base, &tc.base]);
    let (inter3, _) = audit("interaction", &ta.inter, &[&tb.inter, &tc.inter]);
    lap("rank audit, three seeds");

    let report = json!({
        "scope": "PROOF2 leaf-verifier circuit as the prover server pins it (broody/proving@b54ed94f): the job's own Cairo proof, the leaf prover's blinding seed (Cairo trace root) and a second seed, registry padding, the registry's circuit FRI config",
        "job": job.file_name().unwrap().to_string_lossy(),
        "cairo_trace_log_size": trace_log_size, "circuit_hash": circuit_hash, "circuit_trace_log_size": pp.trace_log_size,
        "n_blinding": n_blinding, "fri": format!("{:?}", circuit_cfg.fri_config),
        "reproduces_job_proof": reproduced, "replayed_roots_match_proof": true,
        "rank_audit_two_seeds": base.into_iter().chain(inter).collect::<Vec<_>>(), "end_to_end": e2e,
        "rank_audit_three_seeds": base3.into_iter().chain(inter3).collect::<Vec<_>>(),
        "seconds": t0.elapsed().as_secs_f64(),
    });
    std::fs::write(out.join("report.json"), serde_json::to_vec_pretty(&report).unwrap()).unwrap();
}
