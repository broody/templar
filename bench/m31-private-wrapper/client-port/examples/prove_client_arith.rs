//! Step 2 of the stwo-circuits client route: the membership relation as a blinded
//! *arithmetic-only* stwo-circuits proof (eq + qm31_ops; the fork's `Profile::Arithmetic`).
//! No Blake, XOR, M31-to-u32 gates and no lookup tables, so no statement hash either: the
//! eight output wires carry the statement itself, 32 M31 limbs packed four per QM31
//! (`from_partial_evals`, coordinates in order):
//!
//! | limbs   | content                                     |
//! | ------- | ------------------------------------------- |
//! | 0..2    | tag `TMPZ`, `SA01` (constants)              |
//! | 2..11   | chain id, 28-bit limbs, little-endian       |
//! | 11..20  | pool address, 28-bit limbs, little-endian   |
//! | 20..29  | membership root (computed by the relation)  |
//! | 29..32  | zero                                        |
//!
//! Every guessed limb is an upstream `guess_m31` (base-field constrained), so each output
//! decodes to exactly one limb tuple; the bridge checks the chain/pool limbs are < 2^28.
use std::{fs, path::Path, time::Instant};
#[path = "support/mod.rs"]
mod support;
use circuit_cairo_serialize::prepare_circuit_proof_for_cairo_verifier;
use circuit_common::N_RESERVED;
use circuit_common::finalize::{Profile, add_zk_blinding_for, pad_context_for};
use circuit_common::preprocessed::PreprocessedCircuit;
use circuit_prover::prover::{BaseColumnPool, SimdBackend, prove_circuit_assignment_bounded};
use circuit_verifier::statement::{all_circuit_components, circuit_component_log_sizes};
use circuits::context::{Context, FinalizedContext, Var};
use circuits::ivalue::{IValue, NoValue, qm31_from_u32s};
use circuits::ops::from_partial_evals;
use serde_json::json;
use stwo::core::fields::m31::M31;
use stwo::core::fields::qm31::QM31;
use templar_client_verifier_circuit::air::{self, Private, Public};
use templar_client_verifier_circuit::membership;
use templar_client_verifier_circuit::ro::guess_m31;

/// `TMPZ`, `SA01` as big-endian u32 (both < 2^31 - 1).
pub const TAG: [u32; 2] = [0x544d_505a, 0x5341_3031];
const LIMB_BITS: usize = 28;
const N_FELT_LIMBS: usize = 9;

/// A felt252 given as `0x` hex, as nine 28-bit little-endian limbs.
fn felt_limbs(hex: &str) -> [u32; N_FELT_LIMBS] {
    let digits = hex.strip_prefix("0x").expect("0x hex");
    let nibbles: Vec<u32> = digits.chars().rev().map(|c| c.to_digit(16).expect("hex digit")).collect();
    assert!(nibbles.len() <= 63, "felt252 exceeds 252 bits");
    let bit = |k: usize| nibbles.get(k / 4).map_or(0, |n| (n >> (k % 4)) & 1);
    std::array::from_fn(|l| (0..LIMB_BITS).map(|b| bit(l * LIMB_BITS + b) << b).sum())
}

fn statement_limbs(public: &Public) -> [u32; 4 * N_RESERVED] {
    let mut limbs = TAG.to_vec();
    limbs.extend(felt_limbs(&public.chain));
    limbs.extend(felt_limbs(&public.pool));
    limbs.extend(public.root);
    limbs.resize(4 * N_RESERVED, 0);
    limbs.try_into().unwrap()
}

fn circuit<V: IValue>(public: &Public, private: &Private, seed: [u8; 32], blinding: usize) -> FinalizedContext<V> {
    let mut c = Context::<V>::new(N_RESERVED);
    let root = membership::build(&mut c, &private.secret, &private.siblings, &private.bits);
    let limbs = statement_limbs(public);
    let mut vars: Vec<Var> = TAG.iter().map(|t| c.constant(M31::from(*t).into())).collect();
    vars.extend(limbs[2..20].iter().map(|l| guess_m31(&mut c, *l)));
    vars.extend(root);
    let zero = c.zero();
    vars.resize(4 * N_RESERVED, zero);
    let outputs: Vec<Var> = vars.chunks_exact(4).map(|q| from_partial_evals(&mut c, q.try_into().unwrap())).collect();
    c.set_outputs(&outputs);
    let mut c = c.finalize(true);
    add_zk_blinding_for(&mut c, seed, blinding, Profile::Arithmetic);
    pad_context_for(&mut c, Profile::Arithmetic);
    c
}

fn expected(public: &Public) -> Vec<QM31> {
    statement_limbs(public).chunks_exact(4).map(|q| qm31_from_u32s(q[0], q[1], q[2], q[3])).collect()
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    assert!(a.len() == 2 || a.len() == 3, "prove_client_arith OUT [MAX_FRI_COLUMNS]");
    let out = Path::new(&a[1]);
    // Optional bounded-memory mode (fork patch): FRI quotients over this many columns at a time,
    // owned trees keep coefficients only. The proof is identical either way.
    let max_fri_columns: Option<usize> = a.get(2).map(|n| n.parse().unwrap());
    fs::create_dir_all(out).unwrap();
    let mut rng = rand::rngs::OsRng;
    let (public, private) = air::fresh(&mut rng).unwrap();
    let mut seed = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rng, &mut seed);
    let started = Instant::now();
    // Topology is independent of values and of the blinding seed.
    // Size the blinding for the final trace: every FRI layer's coset per query (math review H1).
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

    assert_eq!(pp.preprocessed_trace.profile(), Profile::Arithmetic);
    drop(topology);
    let cfg = support::config(pp.trace_log_size());
    let root = pp.preprocessed_root(cfg.fri_config.log_blowup_factor);
    let circuit_hash = support::circuit_hash_of(&pp, &cfg, root);
    let wanted = expected(&public);
    let build_seconds = started.elapsed().as_secs_f64();
    let t = Instant::now();
    let mut proof = prove_circuit_assignment_bounded::<support::MC>(context.values(), &pp, &BaseColumnPool::<SimdBackend>::new(), cfg, max_fri_columns).unwrap();
    let proving_seconds = t.elapsed().as_secs_f64();
    // Every FRI value the proof reveals, plus the out-of-domain allowance, is covered by the
    // blinding rows each committed column received.
    let revealed = support::revealed_fri_values(&proof);
    assert!(revealed + support::NON_QUERY_INFO_LEAK <= blinding, "blinding {blinding} < revealed {revealed}");
    support::native_verify(&proof, &pp, root, &wanted);
    let mut negatives = support::negatives(&mut proof, &pp, root, &wanted);
    // Opt-in: the forgery runs a second (unbounded) prover.
    if std::env::var("TEMPLAR_FORGE_NEGATIVE").is_ok() {
        negatives.push(support::forgery_negative(context.values(), &pp, root));
    }
    drop(context);
    let log_sizes = circuit_component_log_sizes(&all_circuit_components::<NoValue>(), &pp.preprocessed_trace.log_sizes());
    let felts = prepare_circuit_proof_for_cairo_verifier(proof, &log_sizes);
    support::write(&out.join("trusted-config.json"), &support::manifest(
        "tmpzsa-client-membership", &pp, &cfg, root, circuit_hash,
        json!({
            "stack": "broody/proving templar/arithmetic-profile (on starkware-libs/proving@5a7c5ed), arithmetic profile, bridge FRI",
            "statement_tag_u32": TAG,
            "statement_layout": "limbs 0..2 tag, 2..11 chain (28-bit LE), 11..20 pool (28-bit LE), 20..29 root, 29..32 zero; 4 limbs per output",
            "blinding_rows": blinding,
        }),
    ));
    let mut arguments = vec![format!("0x{:x}", felts.len())];
    arguments.extend(felts.iter().map(|f| format!("{f:#x}")));
    fs::write(out.join("cairo-arguments.json"), serde_json::to_vec(&arguments).unwrap()).unwrap();
    fs::write(out.join("public.json"), serde_json::to_vec_pretty(&public).unwrap()).unwrap();
    let report = json!({
        "scope": "blinded arithmetic-only stwo-circuits client membership proof (fork templar/arithmetic-profile)",
        "trace_log_size": pp.trace_log_size(),
        "component_log_sizes": log_sizes.into_array().to_vec(),
        "preprocessed_columns": pp.preprocessed_trace.n_columns(),
        "blinding_rows": blinding,
        "blinding_rule": "n_queries * sum over FRI layers of 2^fold_step + NON_QUERY_INFO_LEAK (math review H1)",
        "revealed_fri_values": revealed,
        "max_fri_columns": max_fri_columns,
        "build_seconds": build_seconds,
        "proving_seconds": proving_seconds,
        "proof_felts": felts.len(),
        "native_negatives": negatives,
    });
    support::write(&out.join("report.json"), &report);
    println!("{report}");
}
