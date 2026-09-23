//! R0 payment (2-in/2-out, one token) as a blinded arithmetic-only stwo-circuits client proof.
//! The relation is `src/payment.rs`; the 23 outputs carry the 92-limb public statement.
//! `prove_payment_r0 OUT [MAX_FRI_COLUMNS]` (bounded-memory mode when the batch size is given).
use std::{fs, path::Path, time::Instant};
#[path = "support/mod.rs"]
mod support;
use circuit_cairo_serialize::prepare_circuit_proof_for_cairo_verifier;
use circuit_common::finalize::{Profile, add_zk_blinding_for, pad_context_for};
use circuit_common::preprocessed::PreprocessedCircuit;
use circuit_prover::prover::{BaseColumnPool, SimdBackend, prove_circuit_assignment_bounded};
use circuit_verifier::statement::{all_circuit_components, circuit_component_log_sizes};
use circuits::context::{Context, FinalizedContext};
use circuits::ivalue::{NoValue, qm31_from_u32s};
use serde_json::json;
use stwo::core::fields::qm31::QM31;
use templar_client_verifier_circuit::payment::{self, N_OUTPUTS, Private, Public, STATEMENT_TAG, statement_limbs};

/// Upstream sizing: n_queries + NON_QUERY_INFO_LEAK.
const BLINDING: usize = 35 + 10;

fn circuit<V: templar_client_verifier_circuit::membership::Lanes>(public: &Public, private: &Private, seed: [u8; 32]) -> FinalizedContext<V> {
    let mut c = Context::<V>::new(N_OUTPUTS);
    let outputs = payment::build(&mut c, public, private);
    c.set_outputs(&outputs);
    let mut c = c.finalize(true);
    add_zk_blinding_for(&mut c, seed, BLINDING, Profile::Arithmetic);
    pad_context_for(&mut c, Profile::Arithmetic);
    c
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    assert!(a.len() == 2 || a.len() == 3, "prove_payment_r0 OUT [MAX_FRI_COLUMNS]");
    let out = Path::new(&a[1]);
    let max_fri_columns: Option<usize> = a.get(2).map(|n| n.parse().unwrap());
    fs::create_dir_all(out).unwrap();
    let mut rng = rand::rngs::OsRng;
    let (public, private) = payment::fresh(&mut rng);
    let mut seed = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rng, &mut seed);
    let started = Instant::now();
    // Topology is independent of the witness and of the blinding seed.
    let topology = circuit::<NoValue>(&public, &private, [0; 32]);
    let context = circuit::<QM31>(&public, &private, seed);
    assert!(topology.circuit() == context.circuit());
    context.validate_circuit();
    let pp = PreprocessedCircuit::from_finalized_circuit(topology.circuit());
    assert_eq!(pp.preprocessed_trace.profile(), Profile::Arithmetic);
    drop(topology);
    let cfg = support::config(pp.trace_log_size());
    let root = pp.preprocessed_root(cfg.fri_config.log_blowup_factor);
    let circuit_hash = support::circuit_hash_of(&pp, &cfg, root);
    let wanted: Vec<QM31> =
        statement_limbs(&public).chunks_exact(4).map(|q| qm31_from_u32s(q[0], q[1], q[2], q[3])).collect();
    let build_seconds = started.elapsed().as_secs_f64();
    let t = Instant::now();
    let mut proof = prove_circuit_assignment_bounded::<support::MC>(
        context.values(), &pp, &BaseColumnPool::<SimdBackend>::new(), cfg, max_fri_columns,
    )
    .unwrap();
    let proving_seconds = t.elapsed().as_secs_f64();
    drop(context);
    support::native_verify(&proof, &pp, root, &wanted);
    let negatives = support::negatives(&mut proof, &pp, root, &wanted);
    let log_sizes = circuit_component_log_sizes(&all_circuit_components::<NoValue>(), &pp.preprocessed_trace.log_sizes());
    let felts = prepare_circuit_proof_for_cairo_verifier(proof, &log_sizes);
    support::write(&out.join("trusted-config.json"), &support::manifest(
        "tmpzr0-client-payment", &pp, &cfg, root, circuit_hash,
        json!({
            "stack": "broody/proving templar/arithmetic-profile (on starkware-libs/proving@5a7c5ed), arithmetic profile, bridge FRI",
            "statement_tag_u32": STATEMENT_TAG,
            "statement_layout": "92 limbs, 4 per output: tag 2, chain 9, pool 9, token 9 (28-bit LE), root 9, nf0 9, nf1 9, cm0 9, delivery0 9 (28-bit LE), cm1 9, delivery1 9 (28-bit LE)",
            "blinding_rows": BLINDING,
        }),
    ));
    let mut arguments = vec![format!("0x{:x}", felts.len())];
    arguments.extend(felts.iter().map(|f| format!("{f:#x}")));
    fs::write(out.join("cairo-arguments.json"), serde_json::to_vec(&arguments).unwrap()).unwrap();
    fs::write(out.join("public.json"), serde_json::to_vec_pretty(&public).unwrap()).unwrap();
    let report = json!({
        "scope": "blinded arithmetic-only R0 payment client proof (2-in/2-out, depth 32; fork templar/arithmetic-profile)",
        "trace_log_size": pp.trace_log_size(),
        "component_log_sizes": log_sizes.into_array().to_vec(),
        "blinding_rows": BLINDING,
        "max_fri_columns": max_fri_columns,
        "build_seconds": build_seconds,
        "proving_seconds": proving_seconds,
        "proof_felts": felts.len(),
        "native_negatives": negatives,
    });
    support::write(&out.join("report.json"), &report);
    println!("{report}");
}
