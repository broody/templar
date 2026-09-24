//! Hiding audit, full-transcript invariant search: with the transcript's challenges pinned, is
//! any linear combination of everything a proof reveals independent of the blinding seed?
//!
//! A test-only channel (`PinnedChannel`) ignores everything mixed into it, so the OODS point,
//! the lookup and DEEP coefficients, the FRI folding values and the query positions are the same
//! for every proof; its PoW accepts nonce 0. The same witness is proved under many seeds. Each
//! proof's revealed vector holds:
//! - the OODS samples and opened values of the base, interaction and composition trees (the
//!   preprocessed tree is public);
//! - every FRI layer's witness values and the last-layer polynomial;
//! - the claimed LogUp sums.
//!
//! The rank of the seed-to-seed differences falls short of the vector length by exactly the
//! number of seed-invariant (witness-only) combinations. This covers FRI and the composition
//! and interaction trees jointly, which the linear rank tests cannot. It is still a necessary
//! condition: nonlinear relations are not detected.
//!
//! Scale: a small synthetic circuit with private multiplications and a reduced query count
//! keeps the vector (and so the number of proofs) small. The blinding follows the same H1 rule
//! for that query count. The property tested, no blinding-free combination, does not depend on
//! scale.
//! Usage: hiding_transcript OUT [N_QUERIES] [N_GATES]
#[path = "support/mod.rs"]
mod support;
use circuit_common::finalize::{Profile, add_zk_blinding_for, pad_context_for};
use circuit_common::preprocessed::PreprocessedCircuit;
use circuit_prover::prover::{BaseColumnPool, CircuitProof, SimdBackend, prove_circuit_assignment_bounded};
use circuits::context::{Context, FinalizedContext};
use circuits::ivalue::{IValue, NoValue, qm31_from_u32s};
use circuits::ops::{add_into, mul};
use rand::{Rng, SeedableRng, rngs::StdRng};
use serde_json::json;
use stwo::core::channel::{Blake2sChannel, Channel, MerkleChannel};
use stwo::core::fields::m31::P;
use stwo::core::fields::qm31::{QM31, SecureField};
use stwo::core::fri::FriConfig;
use stwo::core::pcs::PcsConfig;
use stwo::core::vcs_lifted::blake2_merkle::Blake2sMerkleHasher;
use stwo::prover::backend::BackendForChannel;
use stwo::core::proof_of_work::GrindOps;

const PP: u64 = P as u64;

/// Draws from a fixed stream; mixing is ignored, so challenges never depend on the proof.
#[derive(Default, Clone, Debug)]
struct PinnedChannel(Blake2sChannel);
impl Channel for PinnedChannel {
    const BYTES_PER_HASH: usize = Blake2sChannel::BYTES_PER_HASH;
    fn verify_pow_nonce(&self, _: u32, _: u64) -> bool {
        true
    }
    fn mix_u32s(&mut self, _: &[u32]) {}
    fn mix_felts(&mut self, _: &[SecureField]) {}
    fn mix_u64(&mut self, _: u64) {}
    fn draw_secure_felt(&mut self) -> SecureField {
        self.0.draw_secure_felt()
    }
    fn draw_secure_felts(&mut self, n: usize) -> Vec<SecureField> {
        self.0.draw_secure_felts(n)
    }
    fn draw_u32s(&mut self) -> Vec<u32> {
        self.0.draw_u32s()
    }
}
#[derive(Default)]
struct PinnedMC;
impl MerkleChannel for PinnedMC {
    type C = PinnedChannel;
    type H = Blake2sMerkleHasher;
    fn mix_hash(_: &mut PinnedChannel, _: <Blake2sMerkleHasher as stwo::core::vcs_lifted::hasher::Hasher>::Hash) {}
}
impl GrindOps<PinnedChannel> for SimdBackend {
    fn grind(_: &PinnedChannel, _: u32) -> u64 {
        0
    }
}
impl BackendForChannel<PinnedMC> for SimdBackend {}

/// A small relation with private multiplications: sixteen private QM31 values (drawn from
/// `witness`), mixed through `n_gates` alternating mul and add gates. The public output is
/// `acc + (0 − acc) = 0` for every witness, so two witnesses share one public statement.
fn circuit<V: IValue>(n_gates: usize, witness: u64, seed: [u8; 32], blinding: usize) -> FinalizedContext<V> {
    let mut c = Context::<V>::new(1);
    let mut rng = StdRng::seed_from_u64(witness);
    let zero = c.zero();
    let privs: Vec<_> = (0..16)
        .map(|_| {
            let v = c.new_var(V::from_qm31(qm31_from_u32s(rng.r#gen(), rng.r#gen(), rng.r#gen(), rng.r#gen())));
            add_into(&mut c, v, zero, v);
            v
        })
        .collect();
    let mut acc = privs[0];
    for g in 0..n_gates {
        let other = privs[(g * 7 + 3) % 16];
        acc = if g % 2 == 0 { mul(&mut c, acc, other) } else { circuits::ops::add(&mut c, acc, other) };
    }
    for &p in &privs[1..] {
        acc = circuits::ops::add(&mut c, acc, p);
    }
    let neg = circuits::ops::sub(&mut c, zero, acc);
    let out = circuits::ops::add(&mut c, acc, neg);
    c.set_outputs(&[out]);
    let mut c = c.finalize(true);
    add_zk_blinding_for(&mut c, seed, blinding, Profile::Arithmetic);
    pad_context_for(&mut c, Profile::Arithmetic);
    c
}

fn fri(n_queries: usize) -> FriConfig {
    FriConfig { log_blowup_factor: 2, n_queries, pow_bits: 26, ..support::bridge_fri() }
}

/// The H1 rule for this query count: every FRI layer's coset per query, plus 10.
fn budget(trace_log_size: u32, fri: &FriConfig) -> usize {
    let mut remaining = trace_log_size - fri.log_last_layer_degree_bound;
    let mut per_query = 0;
    while remaining > 0 {
        let s = remaining.min(fri.fold_step);
        per_query += 1usize << s;
        remaining -= s;
    }
    fri.n_queries * per_query + support::NON_QUERY_INFO_LEAK
}

/// The revealed vector and a label per coordinate.
fn revealed(proof: &CircuitProof<Blake2sMerkleHasher>) -> (Vec<u64>, Vec<String>) {
    let p = &proof.stark_proof.proof;
    let (mut v, mut l): (Vec<u64>, Vec<String>) = (vec![], vec![]);
    let push_q = |v: &mut Vec<u64>, l: &mut Vec<String>, x: &QM31, label: String| {
        for (k, m) in x.to_m31_array().iter().enumerate() {
            v.push(m.0 as u64);
            l.push(format!("{label}.c{k}"));
        }
    };
    for tree in 1..p.sampled_values.len() {
        for (c, col) in p.sampled_values[tree].iter().enumerate() {
            for (i, x) in col.iter().enumerate() {
                push_q(&mut v, &mut l, x, format!("sampled.t{tree}.col{c}.mask{i}"));
            }
        }
        for (c, col) in p.queried_values[tree].iter().enumerate() {
            for (q, m) in col.iter().enumerate() {
                v.push(m.0 as u64);
                l.push(format!("queried.t{tree}.col{c}.q{q}"));
            }
        }
    }
    let fri = &p.fri_proof;
    for (li, layer) in std::iter::once(&fri.first_layer).chain(&fri.inner_layers).enumerate() {
        for (i, x) in layer.fri_witness.iter().enumerate() {
            push_q(&mut v, &mut l, x, format!("fri.l{li}.w{i}"));
        }
    }
    fn ints(x: &serde_json::Value, path: String, out: &mut Vec<(u64, String)>) {
        match x {
            serde_json::Value::Number(n) => out.push((n.as_u64().unwrap() % PP, path)),
            serde_json::Value::Array(a) => a.iter().enumerate().for_each(|(i, y)| ints(y, format!("{path}.{i}"), out)),
            serde_json::Value::Object(o) => o.iter().for_each(|(k, y)| ints(y, format!("{path}.{k}"), out)),
            _ => {}
        }
    }
    let mut extra = vec![];
    ints(&serde_json::to_value(&fri.last_layer_poly).unwrap(), "fri.last".into(), &mut extra);
    // Claimed LogUp sums, named per component (absent components' sums are zero).
    for (name, sum) in proof.interaction_claim.claimed_sums.clone().into_named_iter() {
        for (k, m) in sum.to_m31_array().iter().enumerate() {
            extra.push((m.0 as u64, format!("claim.{name}.c{k}")));
        }
    }
    for (x, lab) in extra {
        v.push(x);
        l.push(lab);
    }
    (v, l)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let out = std::path::Path::new(args.get(1).map(String::as_str).unwrap_or("target/hiding-transcript"));
    let n_queries: usize = args.get(2).map(|s| s.parse().unwrap()).unwrap_or(5);
    let n_gates: usize = args.get(3).map(|s| s.parse().unwrap()).unwrap_or(400);
    std::fs::create_dir_all(out).unwrap();
    let fri = fri(n_queries);
    let mut blinding = 0;
    let pp = loop {
        let topology = circuit::<NoValue>(n_gates, 5, [0; 32], blinding);
        let pp = PreprocessedCircuit::from_finalized_circuit(topology.circuit());
        let need = budget(pp.trace_log_size(), &fri);
        if blinding >= need {
            break pp;
        }
        blinding = need;
    };
    let cfg = PcsConfig::from_fri_and_trace_size(fri, pp.trace_log_size());
    let pool = BaseColumnPool::<SimdBackend>::new();
    let prove_w = |witness: u64, seed: [u8; 32]| -> (Vec<u64>, Vec<String>, CircuitProof<Blake2sMerkleHasher>) {
        let c = circuit::<QM31>(n_gates, witness, seed, blinding);
        assert!(c.circuit() == circuit::<NoValue>(n_gates, 5, [0; 32], blinding).circuit(), "topology depends on the witness");
        let proof = prove_circuit_assignment_bounded::<PinnedMC>(c.values(), &pp, &pool, cfg, None).unwrap();
        let (v, l) = revealed(&proof);
        (v, l, proof)
    };
    let prove = |seed: [u8; 32]| prove_w(5, seed);
    let (v0, labels, p0) = prove([0; 32]);
    let n = v0.len();
    let breakdown = json!({
        "sampled_and_queried": v0.len() - std::iter::once(&p0.stark_proof.proof.fri_proof.first_layer).chain(&p0.stark_proof.proof.fri_proof.inner_layers).map(|l| 4 * l.fri_witness.len()).sum::<usize>(),
        "fri_witness_m31": std::iter::once(&p0.stark_proof.proof.fri_proof.first_layer).chain(&p0.stark_proof.proof.fri_proof.inner_layers).map(|l| 4 * l.fri_witness.len()).sum::<usize>(),
    });
    println!("{}", json!({"trace_log_size": pp.trace_log_size(), "blinding": blinding, "n_queries": n_queries, "functionals": n, "breakdown": breakdown}));
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
    let mut seeds = 0usize;
    let mut stall = 0usize;
    while basis.len() < n && stall < 40 {
        seeds += 1;
        let mut seed = [0u8; 32];
        seed[..8].copy_from_slice(&(seeds as u64).to_le_bytes());
        seed[9] = 0x7c;
        let (v, _, _) = prove(seed);
        assert_eq!(v.len(), n, "revealed vector length changed");
        let mut row: Vec<u64> = (0..n).map(|j| (v[j] + PP - v0[j]) % PP).collect();
        for (piv, b) in &basis {
            let f = row[*piv];
            if f != 0 {
                for j in *piv..n {
                    row[j] = (row[j] + PP - f * b[j] % PP) % PP;
                }
            }
        }
        match (0..n).find(|&j| row[j] != 0) {
            Some(piv) => {
                let s = inv(row[piv]);
                for x in row.iter_mut().skip(piv) {
                    *x = *x * s % PP;
                }
                let at = basis.partition_point(|(p, _)| *p < piv);
                basis.insert(at, (piv, row));
                stall = 0;
            }
            None => stall += 1,
        }
        if seeds % 100 == 0 {
            println!("{}", json!({"seeds": seeds, "rank": basis.len(), "seconds": started.elapsed().as_secs_f64()}));
        }
    }
    // Fully reduce, then read off a kernel basis: each invariant combination, by label.
    basis.sort_by_key(|(p, _)| *p);
    for i in (0..basis.len()).rev() {
        let (piv, row) = basis[i].clone();
        for k in 0..i {
            let f = basis[k].1[piv];
            if f != 0 {
                for j in piv..n {
                    basis[k].1[j] = (basis[k].1[j] + PP - f * row[j] % PP) % PP;
                }
            }
        }
    }
    let pivots: std::collections::HashSet<usize> = basis.iter().map(|(p, _)| *p).collect();
    let signed = |x: u64| if x > PP / 2 { x as i64 - PP as i64 } else { x as i64 };
    let kernel: Vec<Vec<u64>> = (0..n)
        .filter(|j| !pivots.contains(j))
        .map(|free| {
            let mut c = vec![0u64; n];
            c[free] = 1;
            for (piv, b) in &basis {
                c[*piv] = (PP - b[free]) % PP;
            }
            c
        })
        .collect();
    // Evaluate every invariant on a second witness with the same public output: an invariant
    // whose value moves is witness-dependent (a leak); one that stays is public structure.
    let mut witness_dependent = vec![false; kernel.len()];
    for s in 1..=3u64 {
        let mut seed = [0u8; 32];
        seed[..8].copy_from_slice(&(10_000 + s).to_le_bytes());
        let (v1, _, _) = prove_w(6, seed);
        assert_eq!(v1.len(), n);
        for (k, c) in kernel.iter().enumerate() {
            let dot = (0..n).fold(0u64, |acc, j| (acc + c[j] * ((v1[j] + PP - v0[j]) % PP)) % PP);
            if dot != 0 {
                witness_dependent[k] = true;
            }
        }
    }
    let n_dependent = witness_dependent.iter().filter(|&&d| d).count();
    let invariants: Vec<serde_json::Value> = (0..n)
        .filter(|j| !pivots.contains(j))
        .map(|free| {
            let mut terms = vec![json!([labels[free].clone(), 1])];
            for (piv, b) in &basis {
                if b[free] != 0 {
                    terms.push(json!([labels[*piv].clone(), signed((PP - b[free]) % PP)]));
                }
            }
            json!({"free": labels[free].clone(), "n_terms": terms.len(), "terms": terms.into_iter().take(12).collect::<Vec<_>>()})
        })
        .collect();
    let report = json!({
        "witness_dependent_invariants": n_dependent,
        "invariants_witness_dependent_flags": witness_dependent,
        "invariants": invariants,
        "scope": "full revealed transcript (trees 1-3 samples and openings, FRI witnesses, last layer, claimed sums) with pinned challenges; small synthetic circuit with private muls; fork blinding",
        "trace_log_size": pp.trace_log_size(), "blinding_iterations": blinding, "n_queries": n_queries, "n_gates": n_gates,
        "functionals": n, "breakdown": breakdown, "seeds": seeds, "rank": basis.len(), "seed_invariant_combinations": n - basis.len(),
        "stopped_after_dependent_seeds": stall, "seconds": started.elapsed().as_secs_f64(),
    });
    std::fs::write(out.join("report.json"), serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    println!("{}", json!({"functionals": n, "seeds": seeds, "rank": basis.len(), "seed_invariant_combinations": n - basis.len(), "witness_dependent_invariants": n_dependent}));
}
