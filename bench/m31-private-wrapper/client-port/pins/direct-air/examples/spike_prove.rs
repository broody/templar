//! Spike: proves the membership relation as a blinded stwo-circuits proof (the client's
//! would-be proof) and verifies it natively. Modes: full | floor (trivial circuit), blinded or not.
use std::{fs, path::Path, time::Instant};
#[path = "../../../direct-air/cairo/serialize_full_config.rs"]
mod bridge_serialize;
use circuit_common::finalize::finalize_context;
use circuit_common::preprocessed::PreprocessedCircuit;
use circuit_prover::circuit_air::circuit_components::CircuitComponents;
use circuit_prover::prover::{BaseColumnPool, SimdBackend, prove_circuit_assignment_with_channel};
use circuit_verifier::circuit_claim::{CircuitClaim, CircuitInteractionClaim, CircuitInteractionElements, column_log_sizes_per_tree, lookup_sum};
use circuit_verifier::circuit_components::N_COMPONENTS;
use circuit_verifier::statement::{INTERACTION_POW_BITS, all_circuit_components};
use circuits::context::{Context, FinalizedContext};
use circuits::ivalue::{IValue, NoValue};
use num_traits::{One, Zero};
use serde_json::json;
use stwo::core::air::Component;
use stwo::core::channel::{Blake2sChannel, Channel};
use stwo::core::fields::m31::M31;
use stwo::core::fields::qm31::QM31;
use stwo::core::fri::FriConfig;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::proof::StarkProof;
use stwo::core::vcs::blake2_hash::Blake2sHash;
use stwo::core::vcs_lifted::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher};
use stwo::prover::CommitmentTreeProver;
use stwo::prover::poly::circle::PolyOps;
use circuit_common::finalize::add_zk_blinding;
use templar_client_verifier_circuit::air;
use templar_client_verifier_circuit::membership::build;

fn config() -> PcsConfig {
    PcsConfig {
        pow_bits: 26,
        fri_config: FriConfig { log_blowup_factor: 2, log_last_layer_degree_bound: 0, n_queries: 35, fold_step: 4 },
        lifting_log_size: None,
    }
}

#[derive(Clone)]
struct PublicProof {
    pcs_config: PcsConfig,
    output_values: Vec<QM31>,
    interaction_pow_nonce: u64,
    interaction_claim: [QM31; N_COMPONENTS],
    stark_proof: StarkProof<Blake2sMerkleHasher>,
    channel_salt: u32,
}

fn component_log_sizes(pp: &PreprocessedCircuit) -> [u32; N_COMPONENTS] {
    let sizes = pp.preprocessed_trace.log_sizes();
    all_circuit_components::<NoValue>().values().map(|c| c.log_size(&sizes).unwrap()).collect::<Vec<_>>().try_into().unwrap()
}

fn native_verify(public: &PublicProof, pp: &PreprocessedCircuit, trusted_root: Blake2sHash, expected: &[QM31]) {
    assert_eq!(public.stark_proof.commitments[0], trusted_root);
    let mut expected_config = config();
    expected_config.lifting_log_size = Some(pp.trace_log_size + config().fri_config.log_blowup_factor);
    assert_eq!(public.pcs_config, expected_config);
    assert_eq!(public.stark_proof.config, expected_config);
    assert_eq!(public.output_values, expected);
    let claim = CircuitClaim { output_values: public.output_values.clone() };
    let interaction_claim = CircuitInteractionClaim { claimed_sums: public.interaction_claim };
    let mut channel = Blake2sChannel::default();
    channel.mix_felts(&[public.channel_salt.into()]);
    public.pcs_config.mix_into(&mut channel);
    let mut scheme = CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(public.pcs_config);
    let sizes = component_log_sizes(pp);
    let [trace_sizes, interaction_sizes] = column_log_sizes_per_tree(&sizes);
    let pp_sizes = pp.preprocessed_trace.log_sizes().values().copied().collect::<Vec<_>>();
    scheme.commit(public.stark_proof.commitments[0], &pp_sizes, &mut channel);
    claim.mix_into(&mut channel);
    scheme.commit(public.stark_proof.commitments[1], &trace_sizes, &mut channel);
    assert!(channel.verify_pow_nonce(INTERACTION_POW_BITS, public.interaction_pow_nonce));
    channel.mix_u64(public.interaction_pow_nonce);
    let elements = CircuitInteractionElements::draw(&mut channel);
    interaction_claim.mix_into(&mut channel);
    scheme.commit(public.stark_proof.commitments[2], &interaction_sizes, &mut channel);
    let components = CircuitComponents::new(&elements, &interaction_claim, &sizes, &pp.preprocessed_trace.ids()).components();
    stwo::core::verifier::verify_ex(
        &components.iter().map(|c| c.as_ref()).collect::<Vec<&dyn Component>>(),
        &mut channel,
        &mut scheme,
        public.stark_proof.clone(),
        true,
    )
    .unwrap();
    assert_eq!(lookup_sum(&claim, &interaction_claim, &elements), QM31::zero());
}

const N_OUTPUTS: usize = 9;
const BLINDING: usize = 35 + 10; // n_queries + NON_QUERY_INFO_LEAK, as upstream

fn finish<V: IValue>(mut c: Context<V>, lint: bool) -> FinalizedContext<V> {
    let basis = c.constant(circuits::ivalue::qm31_from_u32s(1, 1, 1, 1));
    circuits::ops::eq(&mut c, basis, basis);
    c.finalize(lint)
}

fn circuit<V: IValue>(private: &air::Private, floor: bool, blinding: Option<[u8; 32]>) -> FinalizedContext<V> {
    let mut c = Context::<V>::new(N_OUTPUTS);
    let root = if floor {
        // Trivial relation with the same interface: nine guessed outputs.
        (0..9).map(|k| templar_client_verifier_circuit::ro::guess_m31(&mut c, private.secret[k])).collect()
    } else {
        build(&mut c, &private.secret, &private.siblings, &private.bits)
    };
    c.set_outputs(&root);
    // The floor circuit is only a size probe; its unused constants are expected.
    let mut c = finish(c, !floor);
    if let Some(seed) = blinding {
        add_zk_blinding(&mut c, seed, BLINDING);
    }
    finalize_context(&mut c);
    c
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    assert_eq!(a.len(), 4, "spike_prove full|floor blind|plain OUT");
    let floor = a[1] == "floor";
    let blind = a[2] == "blind";
    let out = Path::new(&a[3]);
    fs::create_dir_all(out).unwrap();
    let started = Instant::now();
    let mut rng = rand::rngs::OsRng;
    let (public, private) = air::fresh(&mut rng).unwrap();
    let mut seed = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rng, &mut seed);
    let topology = circuit::<NoValue>(&private, floor, blind.then_some([0; 32]));
    let context = circuit::<QM31>(&private, floor, blind.then_some(seed));
    assert!(topology.circuit() == context.circuit());
    context.validate_circuit();
    let wanted: Vec<QM31> = if floor {
        private.secret.iter().map(|v| QM31::from(M31::from(*v))).collect()
    } else {
        public.root.iter().map(|v| QM31::from(M31::from(*v))).collect()
    };
    let build_seconds = started.elapsed().as_secs_f64();
    let pp = PreprocessedCircuit::from_finalized_circuit(topology.circuit());
    drop(topology);
    let sizes = component_log_sizes(&pp);
    let trusted_root = {
        let tw = SimdBackend::precompute_twiddles(CanonicCoset::new(pp.trace_log_size + 2).half_coset());
        let polys = SimdBackend::interpolate_columns(pp.preprocessed_trace.get_trace::<SimdBackend>(), &tw);
        let tree = CommitmentTreeProver::<SimdBackend, Blake2sMerkleChannel>::new(polys, 2, &tw, false, Some(pp.trace_log_size + 2), &BaseColumnPool::new());
        tree.commitment.root()
    };
    let prove_start = Instant::now();
    // SPIKE_MAX_FRI_COLUMNS: optional bounded materialization (same proof format).
    let bounded: Option<usize> = std::env::var("SPIKE_MAX_FRI_COLUMNS").ok().map(|v| v.parse().unwrap());
    let proof = match bounded {
        None => prove_circuit_assignment_with_channel::<Blake2sMerkleChannel>(context.values(), &pp, &BaseColumnPool::<SimdBackend>::new(), config()).unwrap(),
        Some(k) => {
            let mut cfg = config();
            cfg.lifting_log_size = Some(pp.trace_log_size + cfg.fri_config.log_blowup_factor);
            let tw = SimdBackend::precompute_twiddles(CanonicCoset::new(pp.trace_log_size + 2).circle_domain().half_coset);
            let pool = BaseColumnPool::<SimdBackend>::new();
            let polys = SimdBackend::interpolate_columns(pp.preprocessed_trace.get_trace::<SimdBackend>(), &tw);
            let tree = CommitmentTreeProver::<SimdBackend, Blake2sMerkleChannel>::new(polys, 2, &tw, true, cfg.lifting_log_size, &pool);
            circuit_prover::prover::prove_circuit_with_precompute_bounded::<Blake2sMerkleChannel>(
                &pool, &tw, &pp, stwo::core::utils::MaybeOwned::Owned(tree), context.values(), cfg, Some(k)).unwrap()
        }
    };
    let proving_seconds = prove_start.elapsed().as_secs_f64();
    drop(context);
    let public_proof = PublicProof {
        pcs_config: proof.pcs_config,
        output_values: proof.claim.output_values.clone(),
        interaction_pow_nonce: proof.interaction_pow_nonce,
        interaction_claim: proof.interaction_claim.claimed_sums,
        stark_proof: proof.stark_proof.proof.clone(),
        channel_salt: proof.channel_salt,
    };
    native_verify(&public_proof, &pp, trusted_root, &wanted);
    let mut negatives = vec![];
    for case in ["output", "trace", "topology", "config"] {
        let mut bad = public_proof.clone();
        match case {
            "output" => bad.output_values[0] += QM31::one(),
            "trace" => bad.stark_proof.0.commitments[1] = Default::default(),
            "topology" => bad.stark_proof.0.commitments[0] = Default::default(),
            "config" => bad.pcs_config.pow_bits = 0,
            _ => unreachable!(),
        }
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| native_verify(&bad, &pp, trusted_root, &wanted))).is_err());
        negatives.push(case);
    }
    let felts = bridge_serialize::serialize_proof(proof, &sizes);
    let columns: Vec<_> = pp.preprocessed_trace.log_sizes().into_iter().map(|(id, l)| json!({"id": id.id, "log_size": l})).collect();
    let root_words: Vec<u32> = trusted_root.0.chunks_exact(4).map(|c| u32::from_le_bytes(c.try_into().unwrap())).collect();
    fs::write(out.join("trusted-config.json"), serde_json::to_vec_pretty(&json!({
        "purpose": "spike-blinded-membership-client-circuit",
        "pcs_config": public_proof.pcs_config,
        "preprocessed_columns": columns,
        "component_log_sizes": sizes,
        "n_outputs": N_OUTPUTS,
        "preprocessed_root_u32_le": root_words,
    })).unwrap()).unwrap();
    let mut arguments = vec![format!("0x{:x}", felts.len())];
    arguments.extend(felts.iter().map(|f| format!("{f:#x}")));
    fs::write(out.join("cairo-arguments.json"), serde_json::to_vec(&arguments).unwrap()).unwrap();
    fs::write(out.join("public.json"), serde_json::to_vec_pretty(&public).unwrap()).unwrap();
    let report = json!({
        "mode": if floor { "floor" } else { "full" }, "blinding_rows": if blind { BLINDING } else { 0 },
        "trace_log_size": pp.trace_log_size, "component_log_sizes": sizes,
        "build_seconds": build_seconds, "proving_seconds": proving_seconds,
        "proof_felts": felts.len(), "native_negatives": negatives,
    });
    fs::write(out.join("report.json"), serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    println!("{report}");
}
