//! R0 V5 payment (account-bound notes and a public expiry; `docs/account-bound-note-spec.md` §4)
//! as a blinded arithmetic-only stwo-circuits client proof. The relation is `src/payment5.rs`;
//! the 35 outputs carry the 138-limb public statement and two zero limbs.
//! `prove_payment_r5 OUT [MAX_FRI_COLUMNS] [--compress-nodes] [--bound]
//! [--shape transfer|single|one-out|partial|full|invoke|shadow|nft]
//! [--forge voluntary-reveal|zero-delivery|recipient-only|identity-no-intent|duplicate-nullifier|asset-range|recipient-range|zero-chain|account-range|valid-until-zero|account-limb-range|valid-until-limb-range]`.
//! `asset-range` and `recipient-range` need an exiting shape (e.g. `--shape partial`); `account-range`
//! and `account-limb-range` need `--bound`. `--forge` proves a statement the circuit admits and
//! the bridge must reject (spec §5.1), for the bridge's real-proof negatives (F11);
//! `voluntary-reveal` and the two `*-limb-range` forgeries need the `tamper` feature.
//! `statement-limbs.json` holds the exact published limbs (a limb-range forgery has no hex form).
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
use templar_client_verifier_circuit::payment::{self, Digest, Tree};
use templar_client_verifier_circuit::payment5::{self, Mode, N_OUTPUTS, Private, Public, Shape};

fn circuit<V: templar_client_verifier_circuit::membership::Lanes>(tree: Tree, public: &Public, private: &Private, seed: [u8; 32], blinding: usize) -> FinalizedContext<V> {
    let mut c = Context::<V>::new(N_OUTPUTS);
    let outputs = payment5::build(&mut c, tree, public, private);
    c.set_outputs(&outputs);
    let mut c = c.finalize(true);
    add_zk_blinding_for(&mut c, seed, blinding, Profile::Arithmetic);
    pad_context_for(&mut c, Profile::Arithmetic);
    c
}

fn flag(a: &mut Vec<String>, name: &str) -> bool {
    if let Some(k) = a.iter().position(|x| x == name) {
        a.remove(k);
        true
    } else {
        false
    }
}

fn option(a: &mut Vec<String>, name: &str) -> Option<String> {
    a.iter().position(|x| x == name).map(|k| {
        let v = a.remove(k + 1);
        a.remove(k);
        v
    })
}

fn main() {
    let mut a: Vec<String> = std::env::args().collect();
    let shape = match option(&mut a, "--shape").as_deref() {
        None | Some("transfer") => Shape::Transfer,
        Some("single") => Shape::Single,
        Some("one-out") => Shape::OneOut,
        Some("partial") => Shape::Partial,
        Some("full") => Shape::Full,
        Some("invoke") => Shape::Invoke,
        Some("shadow") => Shape::Shadow,
        Some("nft") => Shape::Nft,
        Some(other) => panic!("unknown shape {other}"),
    };
    let forge = option(&mut a, "--forge");
    let tree = if flag(&mut a, "--compress-nodes") { Tree::Compress } else { Tree::Sponge };
    let mode = if flag(&mut a, "--bound") { Mode::Bound } else { Mode::Ordinary };
    assert!(a.len() == 2 || a.len() == 3, "prove_payment_r5 OUT [MAX_FRI_COLUMNS] [--compress-nodes] [--bound] [--shape S] [--forge F]");
    let out = Path::new(&a[1]);
    let max_fri_columns: Option<usize> = a.get(2).map(|n| n.parse().unwrap());
    fs::create_dir_all(out).unwrap();
    let mut rng = rand::rngs::OsRng;
    let (mut public, mut private) = payment5::fresh_shape(tree, shape, mode, &mut rng);
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
    let limbs = circuit_limbs(tree, &public, &private);
    let wanted: Vec<QM31> = limbs.chunks_exact(4).map(|q| qm31_from_u32s(q[0], q[1], q[2], q[3])).collect();
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
        "tmpzr5-client-payment", &pp, &cfg, root, circuit_hash,
        json!({
            "stack": "broody/proving templar/arithmetic-profile (on starkware-libs/proving@5a7c5ed), arithmetic profile, bridge FRI",
            "statement_tag_u32": payment5::statement_tag(tree),
            "statement_layout": "138 limbs padded to 140, 4 per output: tag 2, chain 9, pool 9, token_out 9 (28-bit LE, zero unless exit), root 9, nf0 9, nf1 9, cm0 9, delivery0 9 (28-bit LE), cm1 9, delivery1 9 (28-bit LE), withdrawal recipient 9 (28-bit LE), withdrawal amount 8 (16-bit LE), intent 9 (28-bit LE), identity 9, account 9 (28-bit LE, zero in ordinary mode), valid_until 2 (28-bit LE), zero 2; both outputs always published",
            "blinding_rows": blinding,
            "tree_nodes": format!("{tree:?}"),
        }),
    ));
    let mut arguments = vec![format!("0x{:x}", felts.len())];
    arguments.extend(felts.iter().map(|f| format!("{f:#x}")));
    fs::write(out.join("cairo-arguments.json"), serde_json::to_vec(&arguments).unwrap()).unwrap();
    fs::write(out.join("public.json"), serde_json::to_vec_pretty(&public).unwrap()).unwrap();
    fs::write(out.join("statement-limbs.json"), serde_json::to_vec(&limbs).unwrap()).unwrap();
    let report = json!({
        "scope": "blinded arithmetic-only R0 V5 payment client proof (account-bound notes, public expiry, hidden asset, depth 32; fork templar/arithmetic-profile)",
        "trace_log_size": pp.trace_log_size(),
        "component_log_sizes": log_sizes.into_array().to_vec(),
        "blinding_rows": blinding,
        "blinding_rule": "n_queries * sum over FRI layers of 2^fold_step + NON_QUERY_INFO_LEAK (math review H1)",
        "revealed_fri_values": revealed,
        "max_fri_columns": max_fri_columns,
        "tree_nodes": format!("{tree:?}"),
        "mode": format!("{mode:?}"),
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

/// The limbs the circuit publishes for this witness (the ground truth for a forged witness).
fn circuit_limbs(tree: Tree, public: &Public, private: &Private) -> Vec<u32> {
    let mut c = Context::<QM31>::new(N_OUTPUTS);
    let out = payment5::build(&mut c, tree, public, private);
    assert!(c.is_circuit_valid(), "the witness must satisfy the circuit");
    out.iter().flat_map(|v| c.get(*v).to_m31_array().map(|m| m.0)).collect()
}

/// Nine limbs as `0x` hex without range checks (a forged statement may be non-canonical; a limb
/// above 28 bits has no hex form and is written as its low 28 bits; `statement-limbs.json` is exact).
fn lenient_hex(limbs: &[u32]) -> String {
    let mut acc = [0u64; 5];
    for l in limbs.iter().rev() {
        let mut carry = (l & 0xfff_ffff) as u64;
        for w in acc.iter_mut() {
            let v = (*w << 28) | carry;
            carry = *w >> 36;
            *w = v;
        }
    }
    let hex: String = acc.iter().rev().map(|w| format!("{w:016x}")).collect();
    let trimmed = hex.trim_start_matches('0');
    format!("0x{}", if trimmed.is_empty() { "0" } else { trimmed })
}

/// The statement read back from the circuit's limbs, without the bridge's checks.
fn public_from_limbs(x: &[u32]) -> Public {
    let d = |at: usize| -> Digest { x[at..at + 9].try_into().unwrap() };
    Public {
        chain: lenient_hex(&x[2..11]),
        pool: lenient_hex(&x[11..20]),
        token_out: lenient_hex(&x[20..29]),
        root: d(29),
        nullifiers: [d(38), d(47)],
        commitments: [d(56), d(74)],
        deliveries: [lenient_hex(&x[65..74]), lenient_hex(&x[83..92])],
        withdrawal_recipient: lenient_hex(&x[92..101]),
        withdrawal_amount: (0..8).map(|k| (x[101 + k] as u128) << (16 * k)).sum(),
        intent: lenient_hex(&x[109..118]),
        identity: d(118),
        account: lenient_hex(&x[127..136]),
        valid_until: (x[136] & 0xfff_ffff) as u64 | ((x[137] & 0xfff_ffff) as u64) << 28,
    }
}

/// Re-plants the real inputs under the witness's current chain, pool, asset and receivers
/// (bound to `account` words).
fn replant(tree: Tree, public: &Public, private: &mut Private, account: &Digest) {
    let context = [payment::felt_limbs(&public.chain), payment::felt_limbs(&public.pool), payment::felt_limbs(&private.token)].concat();
    let real = if private.dummy { 1 } else { 2 };
    let leaves: Vec<(u32, Digest)> = private.inputs[..real]
        .iter()
        .map(|i| (i.position, payment::commitment(&context, i.amount, &payment5::receiver_of(account, &i.sk).0, &i.rho)))
        .collect();
    let (_, siblings) = payment5::sparse_paths(tree, &leaves, &mut rand::rngs::OsRng);
    for (i, s) in private.inputs.iter_mut().zip(siblings) {
        i.siblings = s;
    }
}

/// A witness and public data the circuit admits but the bridge must reject.
fn forged(tree: Tree, kind: &str, mut public: Public, mut private: Private) -> (Public, Private) {
    let account = payment::felt_limbs(&private.account);
    let needs_tamper = || assert!(cfg!(feature = "tamper"), "{kind} needs --features tamper");
    match kind {
        "voluntary-reveal" => {
            needs_tamper();
            payment5::TAMPER.with(|t| t.borrow_mut().x = Some(1));
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
        "asset-range" => {
            assert!(public.withdrawal_amount != 0, "asset-range needs an exit");
            private.token = format!("0x8{}", "0".repeat(62));
            replant(tree, &public, &mut private, &account);
        }
        "recipient-range" => {
            assert!(public.withdrawal_amount != 0, "recipient-range needs a withdrawal");
            public.withdrawal_recipient = format!("0x8{}", "0".repeat(62));
        }
        "zero-chain" => {
            public.chain = "0x0".into();
            replant(tree, &public, &mut private, &account);
        }
        "account-range" => {
            assert!(!private.account.ends_with("x0"), "account-range needs --bound");
            private.account = format!("0x8{}", "0".repeat(62));
            let a = payment::felt_limbs(&private.account);
            replant(tree, &public, &mut private, &a);
        }
        "valid-until-zero" => public.valid_until = 0,
        "account-limb-range" => {
            needs_tamper();
            assert!(!private.account.ends_with("x0"), "account-limb-range needs --bound");
            let mut raw = account;
            raw[0] |= 1 << 28;
            payment5::TAMPER.with(|t| t.borrow_mut().account = Some(raw));
            replant(tree, &public, &mut private, &raw);
        }
        "valid-until-limb-range" => {
            needs_tamper();
            payment5::TAMPER.with(|t| t.borrow_mut().valid_until = Some([1 << 28, 0]));
        }
        other => panic!("unknown forgery {other}"),
    }
    let limbs = circuit_limbs(tree, &public, &private);
    let reason = payment5::decode_statement(tree, &limbs).expect_err("the forged statement must fail the bridge");
    eprintln!("forged {kind}: the bridge mirror rejects it with '{reason}'");
    (public_from_limbs(&limbs), private)
}
