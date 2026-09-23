//! Step 1 of the stwo-circuits client route: the membership relation as a *stock* blinded
//! stwo-circuits proof (upstream `add_zk_blinding`, 45 rows), exposing one statement digest
//! `Blake2s("TMPZSC01" || serde_json(Public) || root LE u32)`. Writes the trusted manifest,
//! the Cairo verifier input and the public statement for the bridge.
use std::{fs, path::Path, time::Instant};
#[path = "support/mod.rs"]
mod support;
use blake2::{Blake2s256, Digest};
use circuit_cairo_serialize::prepare_circuit_proof_for_cairo_verifier;
use circuit_common::N_RESERVED;
use circuit_common::finalize::{add_zk_blinding, pad_context};
use circuit_common::preprocessed::PreprocessedCircuit;
use circuit_prover::prover::{BaseColumnPool, SimdBackend, prove_circuit_assignment_with_channel};
use circuit_verifier::statement::{all_circuit_components, circuit_component_log_sizes};
use circuits::context::{Context, FinalizedContext};
use circuits::ivalue::{IValue, NoValue};
use serde_json::json;
use stwo::core::fields::qm31::QM31;
use templar_client_verifier_circuit::air::{self, Private, Public};
use templar_client_verifier_circuit::membership;
use templar_client_verifier_circuit::ro::{blake2s, guess_bytes, m31_bytes};

pub const PREFIX: &[u8; 8] = b"TMPZSC01";

fn statement_x(public: &Public) -> Vec<u8> {
    let mut x = PREFIX.to_vec();
    x.extend(serde_json::to_vec(public).unwrap());
    x
}

fn circuit<V: IValue>(public: &Public, private: &Private, seed: [u8; 32], blinding: usize) -> FinalizedContext<V> {
    let mut c = Context::<V>::new(N_RESERVED);
    let root = membership::build(&mut c, &private.secret, &private.siblings, &private.bits);
    let mut message = guess_bytes(&mut c, &statement_x(public));
    for r in &root {
        message.extend(m31_bytes(&mut c, *r));
    }
    let digest = blake2s(&mut c, &message);
    c.set_outputs(&digest);
    let mut c = c.finalize(true);
    add_zk_blinding(&mut c, seed, blinding);
    pad_context(&mut c);
    c
}

fn expected(public: &Public) -> Vec<QM31> {
    let mut m = statement_x(public);
    for r in public.root {
        m.extend(r.to_le_bytes());
    }
    Blake2s256::digest(&m).chunks_exact(4).map(|c| *QM31::pack_u32(u32::from_le_bytes(c.try_into().unwrap())).get()).collect()
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    assert_eq!(a.len(), 2, "prove_client_sc OUT");
    let out = Path::new(&a[1]);
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
    drop(topology);
    let cfg = support::config(pp.trace_log_size());
    let root = pp.preprocessed_root(cfg.fri_config.log_blowup_factor);
    let circuit_hash = support::circuit_hash_of(&pp, &cfg, root);
    let wanted = expected(&public);
    let build_seconds = started.elapsed().as_secs_f64();
    let t = Instant::now();
    let mut proof = prove_circuit_assignment_with_channel::<support::MC>(context.values(), &pp, &BaseColumnPool::<SimdBackend>::new(), cfg).unwrap();
    let proving_seconds = t.elapsed().as_secs_f64();
    let revealed = support::revealed_fri_values(&proof);
    assert!(revealed + support::NON_QUERY_INFO_LEAK <= blinding, "blinding {blinding} < revealed {revealed}");
    drop(context);
    support::native_verify(&proof, &pp, root, &wanted);
    let negatives = support::negatives(&mut proof, &pp, root, &wanted);
    let log_sizes = circuit_component_log_sizes(&all_circuit_components::<NoValue>(), &pp.preprocessed_trace.log_sizes());
    let felts = prepare_circuit_proof_for_cairo_verifier(proof, &log_sizes);
    support::write(&out.join("trusted-config.json"), &support::manifest(
        "tmpzsc-client-membership", &pp, &cfg, root, circuit_hash,
        json!({"stack": "starkware-libs/proving@5a7c5ed, stock components, bridge FRI", "statement_prefix_hex": hex(PREFIX), "blinding_rows": blinding}),
    ));
    let mut arguments = vec![format!("0x{:x}", felts.len())];
    arguments.extend(felts.iter().map(|f| format!("{f:#x}")));
    fs::write(out.join("cairo-arguments.json"), serde_json::to_vec(&arguments).unwrap()).unwrap();
    fs::write(out.join("public.json"), serde_json::to_vec_pretty(&public).unwrap()).unwrap();
    let report = json!({
        "scope": "stock blinded stwo-circuits client membership proof (proving@5a7c5ed)",
        "trace_log_size": pp.trace_log_size(),
        "component_log_sizes": log_sizes.into_array().to_vec(),
        "blinding_rows": blinding,
        "revealed_fri_values": revealed,
        "build_seconds": build_seconds,
        "proving_seconds": proving_seconds,
        "proof_felts": felts.len(),
        "native_negatives": negatives,
    });
    support::write(&out.join("report.json"), &report);
    println!("{report}");
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
