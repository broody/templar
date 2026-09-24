//! R0 V4 payment (hidden asset, dummy input, always-present outputs; `docs/hidden-asset-spec.md`
//! §4) as a blinded arithmetic-only stwo-circuits client proof. The relation is `src/payment4.rs`;
//! the 32 outputs carry the 127-limb public statement.
//! `prove_payment_r4 OUT [MAX_FRI_COLUMNS] [--compress-nodes] [--shape transfer|single|one-out|partial|full|invoke|shadow|nft]
//! [--forge voluntary-reveal|zero-delivery|recipient-only|identity-no-intent|duplicate-nullifier]`.
//! `--forge` proves a statement the native reference rejects but the circuit admits, so the
//! bridge's own checks (spec §4.5) can be shown to reject it; `voluntary-reveal` needs the
//! `tamper` feature.
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
use templar_client_verifier_circuit::payment::{self, Tree};
use templar_client_verifier_circuit::payment4::{self, N_OUTPUTS, Private, Public, Shape, statement_limbs};


fn circuit<V: templar_client_verifier_circuit::membership::Lanes>(tree: Tree, public: &Public, private: &Private, seed: [u8; 32], blinding: usize) -> FinalizedContext<V> {
    let mut c = Context::<V>::new(N_OUTPUTS);
    let outputs = payment4::build(&mut c, tree, public, private);
    c.set_outputs(&outputs);
    let mut c = c.finalize(true);
    add_zk_blinding_for(&mut c, seed, blinding, Profile::Arithmetic);
    pad_context_for(&mut c, Profile::Arithmetic);
    c
}

fn main() {
    let mut a: Vec<String> = std::env::args().collect();
    let shape = if let Some(k) = a.iter().position(|x| x == "--shape") {
        let v = a.remove(k + 1);
        a.remove(k);
        match v.as_str() {
            "transfer" => Shape::Transfer,
            "single" => Shape::Single,
            "one-out" => Shape::OneOut,
            "partial" => Shape::Partial,
            "full" => Shape::Full,
            "invoke" => Shape::Invoke,
            "shadow" => Shape::Shadow,
            "nft" => Shape::Nft,
            other => panic!("unknown shape {other}"),
        }
    } else {
        Shape::Transfer
    };
    let forge = a.iter().position(|x| x == "--forge").map(|k| {
        let v = a.remove(k + 1);
        a.remove(k);
        v
    });
    let tree = if let Some(k) = a.iter().position(|x| x == "--compress-nodes") {
        a.remove(k);
        Tree::Compress
    } else {
        Tree::Sponge
    };
    assert!(a.len() == 2 || a.len() == 3, "prove_payment_r4 OUT [MAX_FRI_COLUMNS] [--compress-nodes] [--shape S]");
    let out = Path::new(&a[1]);
    let max_fri_columns: Option<usize> = a.get(2).map(|n| n.parse().unwrap());
    fs::create_dir_all(out).unwrap();
    let mut rng = rand::rngs::OsRng;
    let (mut public, mut private) = payment4::fresh_shape(tree, shape, &mut rng);
    if let Some(kind) = &forge {
        (public, private) = forged(tree, kind, public, private);
    }
    let mut seed = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rng, &mut seed);
    let started = Instant::now();
    // Topology is independent of the witness and of the blinding seed.
    // Size the blinding for the final trace: every FRI layer's coset per query (math review H1).
    let mut blinding = 0;
    let (topology, pp) = loop {
        let topology = circuit::<NoValue>(tree, &public, &private, [0; 32], blinding);
        let pp = PreprocessedCircuit::from_finalized_circuit(topology.circuit());
        let need = support::blinding_budget(pp.trace_log_size());
        if blinding >= need {
            break (topology, pp);
        }
        blinding = need;
    };
    let context = circuit::<QM31>(tree, &public, &private, seed, blinding);
    assert!(topology.circuit() == context.circuit());
    context.validate_circuit();

    assert_eq!(pp.preprocessed_trace.profile(), Profile::Arithmetic);
    drop(topology);
    let cfg = support::config(pp.trace_log_size());
    let root = pp.preprocessed_root(cfg.fri_config.log_blowup_factor);
    let circuit_hash = support::circuit_hash_of(&pp, &cfg, root);
    let wanted: Vec<QM31> =
        statement_limbs(tree, &public).chunks_exact(4).map(|q| qm31_from_u32s(q[0], q[1], q[2], q[3])).collect();
    let build_seconds = started.elapsed().as_secs_f64();
    let t = Instant::now();
    let mut proof = prove_circuit_assignment_bounded::<support::MC>(
        context.values(), &pp, &BaseColumnPool::<SimdBackend>::new(), cfg, max_fri_columns,
    )
    .unwrap();
    let proving_seconds = t.elapsed().as_secs_f64();
    // Every FRI value the proof reveals, plus the out-of-domain allowance, is covered by the
    // blinding rows each committed column received.
    let revealed = support::revealed_fri_values(&proof);
    assert!(revealed + support::NON_QUERY_INFO_LEAK <= blinding, "blinding {blinding} < revealed {revealed}");
    support::native_verify(&proof, &pp, root, &wanted);
    let negatives = support::negatives(&mut proof, &pp, root, &wanted);
    drop(context);
    let log_sizes = circuit_component_log_sizes(&all_circuit_components::<NoValue>(), &pp.preprocessed_trace.log_sizes());
    let felts = prepare_circuit_proof_for_cairo_verifier(proof, &log_sizes);
    support::write(&out.join("trusted-config.json"), &support::manifest(
        "tmpzr4-client-payment", &pp, &cfg, root, circuit_hash,
        json!({
            "stack": "broody/proving templar/arithmetic-profile (on starkware-libs/proving@5a7c5ed), arithmetic profile, bridge FRI",
            "statement_tag_u32": payment4::statement_tag(tree),
            "statement_layout": "127 limbs padded to 128, 4 per output: tag 2, chain 9, pool 9, token_out 9 (28-bit LE, zero unless exit), root 9, nf0 9, nf1 9, cm0 9, delivery0 9 (28-bit LE), cm1 9, delivery1 9 (28-bit LE), withdrawal recipient 9 (28-bit LE), withdrawal amount 8 (16-bit LE), intent 9 (28-bit LE), identity 9, zero 1; both outputs always published",
            "blinding_rows": blinding,
            "tree_nodes": format!("{tree:?}"),
        }),
    ));
    let mut arguments = vec![format!("0x{:x}", felts.len())];
    arguments.extend(felts.iter().map(|f| format!("{f:#x}")));
    fs::write(out.join("cairo-arguments.json"), serde_json::to_vec(&arguments).unwrap()).unwrap();
    fs::write(out.join("public.json"), serde_json::to_vec_pretty(&public).unwrap()).unwrap();
    let report = json!({
        "scope": "blinded arithmetic-only R0 V4 payment client proof (hidden asset, dummy input, depth 32; fork templar/arithmetic-profile)",
        "trace_log_size": pp.trace_log_size(),
        "component_log_sizes": log_sizes.into_array().to_vec(),
        "blinding_rows": blinding,
        "blinding_rule": "n_queries * sum over FRI layers of 2^fold_step + NON_QUERY_INFO_LEAK (math review H1)",
        "revealed_fri_values": revealed,
        "max_fri_columns": max_fri_columns,
        "tree_nodes": format!("{tree:?}"),
        "shape": format!("{shape:?}"),
        "forged": forge,
        "build_seconds": build_seconds,
        "proving_seconds": proving_seconds,
        "proof_felts": felts.len(),
        "native_negatives": negatives,
    });
    support::write(&out.join("report.json"), &report);
    println!("{report}");
}

/// Nine 28-bit little-endian limbs as `0x` hex.
fn limbs_hex(limbs: &[u32]) -> String {
    let mut bits = vec![];
    for l in limbs {
        for k in 0..28 {
            bits.push((l >> k) & 1);
        }
    }
    let nibbles: Vec<u32> = bits.chunks(4).map(|c| c.iter().enumerate().map(|(k, b)| b << k).sum()).collect();
    let hex: String = nibbles.iter().rev().map(|n| std::char::from_digit(*n, 16).unwrap()).collect();
    let trimmed = hex.trim_start_matches('0');
    format!("0x{}", if trimmed.is_empty() { "0" } else { trimmed })
}

fn digest(limbs: &[u32]) -> payment::Digest {
    limbs.try_into().unwrap()
}

/// The statement the circuit proves for this witness, read from its outputs (the ground truth
/// when the native reference would reject the witness).
fn public_from_circuit(tree: Tree, public: &Public, private: &Private) -> Public {
    let mut c = Context::<QM31>::new(N_OUTPUTS);
    let out = payment4::build(&mut c, tree, public, private);
    assert!(c.is_circuit_valid(), "forged witness must satisfy the circuit");
    let x: Vec<u32> = out.iter().flat_map(|v| c.get(*v).to_m31_array().map(|m| m.0)).collect();
    let amount = (0..8).map(|k| (x[101 + k] as u128) << (16 * k)).sum();
    Public {
        chain: limbs_hex(&x[2..11]),
        pool: limbs_hex(&x[11..20]),
        token_out: limbs_hex(&x[20..29]),
        root: digest(&x[29..38]),
        nullifiers: [digest(&x[38..47]), digest(&x[47..56])],
        commitments: [digest(&x[56..65]), digest(&x[74..83])],
        deliveries: [limbs_hex(&x[65..74]), limbs_hex(&x[83..92])],
        withdrawal_recipient: limbs_hex(&x[92..101]),
        withdrawal_amount: amount,
        intent: limbs_hex(&x[109..118]),
        identity: digest(&x[118..127]),
    }
}

/// A witness and public data the circuit admits but the bridge must reject.
fn forged(tree: Tree, kind: &str, mut public: Public, mut private: Private) -> (Public, Private) {
    match kind {
        "voluntary-reveal" => {
            assert!(cfg!(feature = "tamper"), "voluntary-reveal needs --features tamper");
            payment4::TAMPER.with(|t| t.borrow_mut().x = Some(1));
        }
        "zero-delivery" => public.deliveries[1] = "0x0".into(),
        "recipient-only" => public.withdrawal_recipient = "0x1234".into(),
        "identity-no-intent" => private.identity = payment::Identity { active: true, scope: [7; 9] },
        "duplicate-nullifier" => {
            private.inputs[1] = private.inputs[0].clone();
            private.dummy = false;
            let total = 2 * private.inputs[0].amount;
            private.outputs[0].amount = 1;
            private.outputs[1].amount = total - 1;
        }
        other => panic!("unknown forgery {other}"),
    }
    let forged = public_from_circuit(tree, &public, &private);
    assert!(
        payment4::statement(tree, &forged.chain, &forged.pool, forged.deliveries.clone(),
            (forged.withdrawal_recipient.clone(), forged.withdrawal_amount), &forged.intent, &private).map_or(true, |p| p != forged),
        "the native reference must not produce the forged statement",
    );
    (forged, private)
}
