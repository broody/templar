//! Compact-recursion M0 floor measurement.
//!
//! Proves a custom AIR (the simple squared-Fibonacci example), verifies that
//! proof inside a circuit via the generic `stark_verifier` machinery, then
//! proves the verification circuit itself with the pinned circuits
//! configuration, and natively verifies the result.
//!
//! This is measurement infrastructure only. No privacy claim attaches to any
//! artifact here.

use std::time::Instant;

use circuit_common::preprocessed::PreprocessedCircuit;
use circuit_prover::circuit_air::circuit_components::CircuitComponents;
use circuit_prover::prover::{BaseColumnPool, CircuitProof, SimdBackend, prove_circuit_assignment_with_channel};
use circuit_verifier::circuit_claim::{
    CircuitInteractionElements, column_log_sizes_per_tree, lookup_sum,
};
use circuit_verifier::circuit_proof::CircuitProof as RejectionCircuitProof;
use circuit_verifier::statement::{INTERACTION_POW_BITS, all_circuit_components};
use circuits::context::{Context, TraceContext};
use circuits::ivalue::NoValue;
use circuits::ops::Guess;
use circuits_stark_verifier::proof::{ProofConfig, empty_proof};
use circuits_stark_verifier::proof_from_stark_proof::proof_from_stark_proof;
use circuits_stark_verifier::verify::verify;
use circuits_stark_verifier_examples::simple_air::create_proof;
use circuits_stark_verifier_examples::simple_statement::{
    PREPROCESSED_COLUMN_LOG_SIZES, SimpleStatement, simple_statement_components,
};
use num_traits::Zero;
use serde_json::json;
use stwo::core::channel::{Blake2sChannel, Channel};
use stwo::core::fri::FriConfig;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
use stwo::core::vcs_lifted::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher};

/// Exactly the pinned circuit query/blowup/grinding/folding parameters
/// (mirrors bench/direct-air/client). Lifting is derived from the topology.
fn circuit_config() -> PcsConfig {
    PcsConfig {
        pow_bits: 26,
        fri_config: FriConfig {
            log_blowup_factor: 2,
            log_last_layer_degree_bound: 0,
            n_queries: 35,
            fold_step: 4,
        },
        lifting_log_size: None,
    }
}

fn component_log_sizes(preprocessed: &PreprocessedCircuit) -> [u32; 11] {
    let sizes = preprocessed.preprocessed_trace.log_sizes();
    all_circuit_components::<NoValue>()
        .values()
        .map(|component| component.log_size(&sizes).unwrap())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

#[allow(clippy::too_many_arguments)]
fn verify_outer(
    channel_salt: u32,
    pcs_config: PcsConfig,
    interaction_pow_nonce: u64,
    claim: &circuit_verifier::circuit_claim::CircuitClaim,
    interaction_claim: &circuit_verifier::circuit_claim::CircuitInteractionClaim,
    stark_proof: &stwo::core::proof::StarkProof<Blake2sMerkleHasher>,
    preprocessed: &PreprocessedCircuit,
) {
    let mut channel = Blake2sChannel::default();
    channel.mix_felts(&[channel_salt.into()]);
    pcs_config.mix_into(&mut channel);
    let mut scheme = CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(pcs_config);
    let sizes = component_log_sizes(preprocessed);
    let [trace_sizes, interaction_sizes] = column_log_sizes_per_tree(&sizes);
    let pp_sizes = preprocessed
        .preprocessed_trace
        .log_sizes()
        .values()
        .copied()
        .collect::<Vec<_>>();
    scheme.commit(stark_proof.commitments[0], &pp_sizes, &mut channel);
    claim.mix_into(&mut channel);
    scheme.commit(stark_proof.commitments[1], &trace_sizes, &mut channel);
    assert!(channel.verify_pow_nonce(INTERACTION_POW_BITS, interaction_pow_nonce));
    channel.mix_u64(interaction_pow_nonce);
    let elements = CircuitInteractionElements::draw(&mut channel);
    interaction_claim.mix_into(&mut channel);
    scheme.commit(stark_proof.commitments[2], &interaction_sizes, &mut channel);
    let components = CircuitComponents::new(
        &elements,
        interaction_claim,
        &sizes,
        &preprocessed.preprocessed_trace.ids(),
    )
    .components();
    stwo::core::verifier::verify_ex(
        &components
            .iter()
            .map(|component| component.as_ref())
            .collect::<Vec<&dyn stwo::core::air::Component>>(),
        &mut channel,
        &mut scheme,
        stark_proof.clone(),
        true,
    )
    .unwrap();
    assert_eq!(
        lookup_sum(claim, interaction_claim, &elements),
        stwo::core::fields::qm31::QM31::zero()
    );
}

fn main() {
    // 1. Inner custom-AIR proof (squared-Fibonacci example statement).
    let (_components, claim, pcs_config, proof, interaction_pow_nonce, channel_salt) =
        create_proof();

    let components = simple_statement_components::<NoValue>();
    let config = ProofConfig::new(&components, PREPROCESSED_COLUMN_LOG_SIZES.len(), &pcs_config, 8);

    // 2. Value-free topology: the circuit that verifies such a proof.
    let novalue_circuit = {
        let empty_proof = empty_proof(&config);
        let mut novalue_context = Context::<NoValue>::default();
        let proof_vars = empty_proof.guess(&mut novalue_context);
        let statement = SimpleStatement::new(&mut novalue_context);
        verify(&mut novalue_context, &proof_vars, &config, &statement);
        novalue_context.finalize(false).context.circuit
    };

    // 3. Value context from the real proof; run the in-circuit verification.
    let mut context = TraceContext::default();
    let proof = proof_from_stark_proof(&proof, &config, claim, interaction_pow_nonce, channel_salt);
    let proof_vars = proof.guess(&mut context);
    let statement = SimpleStatement::new(&mut context);
    verify(&mut context, &proof_vars, &config, &statement);
    let context = context.finalize(true);

    // The inner proof verified in-circuit, and the topology matches value-free.
    novalue_circuit.check(context.values()).unwrap();
    assert_eq!(context.circuit(), &novalue_circuit);

    // Pad the components to power-of-two sizes (the provable pipeline), then
    // build the preprocessed tree and prove the verification circuit with the
    // pinned circuits config.
    let mut context = context;
    circuit_common::finalize::finalize_context(&mut context);
    let preprocessed = PreprocessedCircuit::from_finalized_circuit(context.circuit().clone());
    let trace_log_size = preprocessed.trace_log_size;
    let stats = context.stats();
    let prove_start = Instant::now();
    let circuit_proof = prove_circuit_assignment_with_channel::<Blake2sMerkleChannel>(
        context.values(),
        &preprocessed,
        &BaseColumnPool::<SimdBackend>::new(),
        circuit_config(),
    )
    .unwrap();
    let proving_seconds = prove_start.elapsed().as_secs_f64();

    // 5. Native verification of the outer circuit proof (accept + one mutation).
    let verify_start = Instant::now();
    verify_outer(
        circuit_proof.channel_salt,
        circuit_proof.pcs_config,
        circuit_proof.interaction_pow_nonce,
        &circuit_proof.claim,
        &circuit_proof.interaction_claim,
        &circuit_proof.stark_proof.proof,
        &preprocessed,
    );
    let verify_seconds = verify_start.elapsed().as_secs_f64();

    let mut mutated_proof = circuit_proof.stark_proof.proof.clone();
    mutated_proof.0.commitments[1] = Default::default();
    let rejected: RejectionCircuitProof<Blake2sMerkleHasher> = RejectionCircuitProof {
        pcs_config: circuit_proof.pcs_config,
        claim: circuit_verifier::circuit_claim::CircuitClaim {
            output_values: circuit_proof.claim.output_values.clone(),
        },
        interaction_pow_nonce: circuit_proof.interaction_pow_nonce,
        interaction_claim: circuit_verifier::circuit_claim::CircuitInteractionClaim {
            claimed_sums: circuit_proof.interaction_claim.claimed_sums.clone(),
        },
        stark_proof: stwo::core::proof::ExtendedStarkProof {
            proof: mutated_proof,
            aux: circuit_proof.stark_proof.aux.clone(),
        },
        channel_salt: circuit_proof.channel_salt,
    };
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        verify_outer(
            rejected.channel_salt,
            rejected.pcs_config,
            rejected.interaction_pow_nonce,
            &rejected.claim,
            &rejected.interaction_claim,
            &rejected.stark_proof.proof,
            &preprocessed,
        )
    }))
    .is_err());

    // 6. Report.
    let sizes = component_log_sizes(&preprocessed);
    let log_sizes_json: Vec<serde_json::Value> = all_circuit_components::<NoValue>()
        .keys()
        .cloned()
        .zip(sizes.iter())
        .map(|(name, &l)| json!({"component": name, "log_size": l}))
        .collect();
    let report = json!({
        "experiment": "compact-recursion-m0",
        "inner": "simple_air squared-fibonacci (pinned example)",
        "outer_config": {"pow_bits": 26, "blowup": 2, "queries": 35, "fold_step": 4},
        "trace_log_size": trace_log_size,
        "lifting_log_size": trace_log_size + circuit_config().fri_config.log_blowup_factor,
        "component_log_sizes": log_sizes_json,
        "context_stats": format!("{:?}", stats),
        "proving_seconds": proving_seconds,
        "verify_seconds": verify_seconds,
        "native_verify": "accepted; mutated trace-root rejected",
        "circuit_check": "inner proof verified in-circuit (NoValue check passed)",
    });
    println!("{}", serde_json::to_string_pretty(&report).unwrap());
    std::fs::create_dir_all("../results").unwrap();
    std::fs::write(
        "../results/m0-summary.json",
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
}
