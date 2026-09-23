//! Wallet commands for the Sepolia run (option A pool, R0 V2, single-permutation nodes). Every
//! value is JSON on stdout; digests are nine M31 words.
//!
//! - `wallet keys SK_JSON`: `{receiver, nk}` for a 9-word spending secret.
//! - `wallet inner RECEIVER_JSON RHO_JSON`: the note's `inner` hash (a deposit's argument).
//! - `wallet commitment CHAIN POOL TOKEN AMOUNT INNER_JSON`: the note commitment the pool computes.
//! - `wallet prove SPEND_JSON OUT [MAX_FRI_COLUMNS]`: an R0 proof for a spend described by
//!   `{chain, pool, token, leaves, inputs: [{sk, rho, amount, position}] x2,
//!     outputs: [{active, receiver, rho, amount, delivery}] x2, withdrawal: {recipient, amount}}`,
//!   with paths computed from `leaves` (the pool's commitments in order). Writes the Cairo
//!   arguments, public statement, trusted manifest and report, as `prove_payment_r0` does.
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
use serde::Deserialize;
use serde_json::json;
use stwo::core::fields::qm31::QM31;
use templar_client_verifier_circuit::membership::Lanes;
use templar_client_verifier_circuit::payment::{
    self, Digest, INNER, Identity, Input, N_OUTPUTS, NOTE, Output, Private, Public, Tree, amount_limbs, felt_limbs, h,
    receiver_of, statement_limbs, tree_paths,
};

const TREE: Tree = Tree::Compress;

#[derive(Deserialize)]
struct SpendIn {
    sk: Digest,
    rho: Digest,
    amount: String,
    position: u32,
}
#[derive(Deserialize)]
struct SpendOut {
    active: bool,
    receiver: Digest,
    rho: Digest,
    amount: String,
    delivery: String,
}
#[derive(Deserialize)]
struct WithdrawalIn {
    recipient: String,
    amount: String,
}
#[derive(Deserialize)]
struct SpendJson {
    chain: String,
    pool: String,
    token: String,
    leaves: Vec<Digest>,
    inputs: [SpendIn; 2],
    outputs: [SpendOut; 2],
    withdrawal: WithdrawalIn,
    /// V3: the open-note execution intent (a felt; `0x0` for none).
    #[serde(default = "no_intent")]
    intent: String,
    /// V3: the shadow-account identity scope, when the spend publishes an identity handle.
    #[serde(default)]
    identity_scope: Option<Digest>,
}

fn no_intent() -> String {
    "0x0".into()
}

fn circuit<V: Lanes>(public: &Public, private: &Private, seed: [u8; 32], blinding: usize) -> FinalizedContext<V> {
    let mut c = Context::<V>::new(N_OUTPUTS);
    let outputs = payment::build(&mut c, TREE, public, private);
    c.set_outputs(&outputs);
    let mut c = c.finalize(true);
    add_zk_blinding_for(&mut c, seed, blinding, Profile::Arithmetic);
    pad_context_for(&mut c, Profile::Arithmetic);
    c
}

fn prove(spec: SpendJson, out: &Path, max_fri_columns: Option<usize>) {
    fs::create_dir_all(out).unwrap();
    let u128_of = |s: &str| s.parse::<u128>().expect("decimal u128");
    let positions = [spec.inputs[0].position, spec.inputs[1].position];
    let (root, paths) = tree_paths(TREE, &spec.leaves, &positions);
    let private = Private {
        inputs: std::array::from_fn(|i| Input {
            sk: spec.inputs[i].sk,
            rho: spec.inputs[i].rho,
            amount: u128_of(&spec.inputs[i].amount),
            position: positions[i],
            siblings: paths[i].clone(),
        }),
        outputs: std::array::from_fn(|j| Output {
            active: spec.outputs[j].active,
            receiver: spec.outputs[j].receiver,
            rho: spec.outputs[j].rho,
            amount: u128_of(&spec.outputs[j].amount),
        }),
        identity: Identity { active: spec.identity_scope.is_some(), scope: spec.identity_scope.unwrap_or([0; 9]) },
    };
    let deliveries = [spec.outputs[0].delivery.clone(), spec.outputs[1].delivery.clone()];
    let public = payment::statement(
        TREE, &spec.chain, &spec.pool, &spec.token, deliveries,
        (spec.withdrawal.recipient.clone(), u128_of(&spec.withdrawal.amount)), &spec.intent, &private,
    )
    .unwrap_or_else(|e| panic!("invalid spend: {e}"));
    assert_eq!(public.root, root);
    let mut seed = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
    let started = Instant::now();
    let mut blinding = 0;
    let (topology, pp) = loop {
        let topology = circuit::<NoValue>(&public, &private, [0; 32], blinding);
        let pp = PreprocessedCircuit::from_finalized_circuit(topology.circuit());
        let need = support::blinding_budget(pp.trace_log_size());
        if blinding >= need {
            break (topology, pp);
        }
        blinding = need;
    };
    let context = circuit::<QM31>(&public, &private, seed, blinding);
    assert!(topology.circuit() == context.circuit());
    context.validate_circuit();
    drop(topology);
    let cfg = support::config(pp.trace_log_size());
    let pp_root = pp.preprocessed_root(cfg.fri_config.log_blowup_factor);
    let circuit_hash = support::circuit_hash_of(&pp, &cfg, pp_root);
    let wanted: Vec<QM31> =
        statement_limbs(TREE, &public).chunks_exact(4).map(|q| qm31_from_u32s(q[0], q[1], q[2], q[3])).collect();
    let t = Instant::now();
    let mut proof = prove_circuit_assignment_bounded::<support::MC>(
        context.values(), &pp, &BaseColumnPool::<SimdBackend>::new(), cfg, max_fri_columns,
    )
    .unwrap();
    let proving_seconds = t.elapsed().as_secs_f64();
    let revealed = support::revealed_fri_values(&proof);
    assert!(revealed + support::NON_QUERY_INFO_LEAK <= blinding);
    drop(context);
    support::native_verify(&proof, &pp, pp_root, &wanted);
    let negatives = support::negatives(&mut proof, &pp, pp_root, &wanted);
    let log_sizes = circuit_component_log_sizes(&all_circuit_components::<NoValue>(), &pp.preprocessed_trace.log_sizes());
    let felts = prepare_circuit_proof_for_cairo_verifier(proof, &log_sizes);
    support::write(&out.join("trusted-config.json"), &support::manifest(
        "tmpzr0-client-payment", &pp, &cfg, pp_root, circuit_hash,
        json!({
            "stack": "broody/proving templar/arithmetic-profile (on starkware-libs/proving@5a7c5ed), arithmetic profile, bridge FRI",
            "statement_tag_u32": payment::statement_tag(TREE),
            "blinding_rows": blinding,
            "tree_nodes": "Compress",
        }),
    ));
    let mut arguments = vec![format!("0x{:x}", felts.len())];
    arguments.extend(felts.iter().map(|f| format!("{f:#x}")));
    fs::write(out.join("cairo-arguments.json"), serde_json::to_vec(&arguments).unwrap()).unwrap();
    fs::write(out.join("public.json"), serde_json::to_vec_pretty(&public).unwrap()).unwrap();
    let report = json!({
        "scope": "R0 V2 wallet proof for a live spend (Tree::Compress)",
        "trace_log_size": pp.trace_log_size(),
        "blinding_rows": blinding,
        "revealed_fri_values": revealed,
        "build_seconds": started.elapsed().as_secs_f64() - proving_seconds,
        "proving_seconds": proving_seconds,
        "proof_felts": felts.len(),
        "native_negatives": negatives,
    });
    support::write(&out.join("report.json"), &report);
    println!("{report}");
}

fn digest(arg: &str) -> Digest {
    serde_json::from_str(arg).expect("digest JSON: nine words")
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    match a.get(1).map(String::as_str) {
        Some("keys") => {
            let (receiver, nk) = receiver_of(&digest(&a[2]));
            println!("{}", json!({"receiver": receiver, "nk": nk}));
        }
        Some("inner") => {
            println!("{}", json!(h(INNER, 0, &[digest(&a[2]), digest(&a[3])].concat())));
        }
        Some("commitment") => {
            let context = [felt_limbs(&a[2]), felt_limbs(&a[3]), felt_limbs(&a[4])].concat();
            let amount: u128 = a[5].parse().unwrap();
            let cm = h(NOTE, 0, &[context, amount_limbs(amount).to_vec(), digest(&a[6]).to_vec()].concat());
            println!("{}", json!(cm));
        }
        Some("prove") => {
            let spec: SpendJson = serde_json::from_slice(&fs::read(&a[2]).unwrap()).unwrap();
            prove(spec, Path::new(&a[3]), a.get(4).map(|n| n.parse().unwrap()));
        }
        _ => panic!("wallet keys|inner|commitment|prove ..."),
    }
}
