//! Synthetic disclosure diagnostic. This is not a privacy-qualified application prover.
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;
use std::time::Instant;

use circuit_common::finalize::{add_zk_blinding, finalize_context};
use circuit_common::preprocessed::PreprocessedCircuit;
use circuit_prover::circuit_air::circuit_components::CircuitComponents;
use circuit_prover::prover::{
    BaseColumnPool, CircuitProof, SimdBackend, prove_circuit_assignment_with_channel,
};
use circuit_verifier::circuit_claim::{
    CircuitClaim, CircuitInteractionClaim, CircuitInteractionElements, column_log_sizes_per_tree,
    lookup_sum,
};
use circuit_verifier::circuit_components::N_COMPONENTS;
use circuit_verifier::statement::{INTERACTION_POW_BITS, all_circuit_components};
use circuits::context::{Context, FinalizedContext};
use circuits::ivalue::{IValue, NoValue};
use circuits::ops::{eq, guess};
use num_traits::{One, Zero};
use serde::{Deserialize, Serialize};
use serde_json::json;
use stwo::core::air::Component;
use stwo::core::channel::{Blake2sChannel, Channel, MerkleChannel};
use stwo::core::circle::CirclePoint;
use stwo::core::fields::m31::M31;
use stwo::core::fields::qm31::QM31;
use stwo::core::fri::{CirclePolyDegreeBound, FriConfig, FriVerifier};
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::proof::StarkProof;
use stwo::core::vcs::blake2_hash::Blake2sHash;
use stwo::core::vcs_lifted::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher};
use stwo::prover::CommitmentTreeProver;
use stwo::prover::backend::CpuBackend;
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::poly::circle::CircleEvaluation;
use stwo::prover::poly::circle::PolyOps;

const N_MASKS: usize = 35;

#[path = "../../cairo/serialize_full_config.rs"]
mod bridge_serialize;

// Exactly the pinned circuit query/blowup/grinding/folding parameters. Only the lifting size is
// derived from this diagnostic's fixed topology, as upstream prove_circuit_assignment does.
fn config() -> PcsConfig {
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

fn os_random<const N: usize>() -> [u8; N] {
    let mut bytes = [0; N];
    File::open("/dev/urandom")
        .unwrap()
        .read_exact(&mut bytes)
        .unwrap();
    bytes
}

fn random_qm31() -> QM31 {
    let bytes = os_random::<16>();
    QM31::from_m31_array(std::array::from_fn(|i| {
        M31::from(u32::from_le_bytes(
            bytes[4 * i..4 * i + 4].try_into().unwrap(),
        ))
    }))
}

struct Built<Value: IValue> {
    context: FinalizedContext<Value>,
    private_address: usize,
    mask_rows: Vec<usize>,
}

fn build<Value: IValue>(private: Value, blinding_seed: [u8; 32]) -> Built<Value> {
    let mut context = Context::<Value>::new(2);
    let private = guess(&mut context, private);
    eq(&mut context, private, private);
    let zero = context.zero();
    context.set_outputs(&[zero, zero]);
    let mut context = context.finalize(false);
    let first_mask_row = context.circuit().eq.len();
    add_zk_blinding(&mut context, blinding_seed, N_MASKS);
    let last_mask_row = context.circuit().eq.len();
    assert_eq!(last_mask_row - first_mask_row, N_MASKS);
    finalize_context(&mut context);
    Built {
        context,
        private_address: private.idx,
        mask_rows: (first_mask_row..last_mask_row).collect(),
    }
}

#[derive(Serialize, Deserialize)]
struct PublicProof {
    pcs_config: PcsConfig,
    output_values: Vec<QM31>,
    interaction_pow_nonce: u64,
    interaction_claim: [QM31; N_COMPONENTS],
    stark_proof: StarkProof<Blake2sMerkleHasher>,
    channel_salt: u32,
}

#[derive(Serialize, Deserialize)]
struct PublicTopology {
    eq_log_size: u32,
    private_rows: Vec<usize>,
    mask_rows: Vec<usize>,
    known_eq_values: Vec<[M31; 4]>,
}

fn component_log_sizes(preprocessed: &PreprocessedCircuit) -> [u32; N_COMPONENTS] {
    let sizes = preprocessed.preprocessed_trace.log_sizes();
    all_circuit_components::<NoValue>()
        .values()
        .map(|component| component.log_size(&sizes).unwrap())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

fn native_verify(
    public: &PublicProof,
    preprocessed: &PreprocessedCircuit,
    trusted_root: Blake2sHash,
) {
    assert_eq!(public.stark_proof.commitments[0], trusted_root);
    let mut expected_config = config();
    expected_config.lifting_log_size =
        Some(preprocessed.trace_log_size + config().fri_config.log_blowup_factor);
    assert_eq!(public.pcs_config, expected_config);
    assert_eq!(public.stark_proof.config, expected_config);
    assert_eq!(public.output_values, vec![QM31::zero(); 2]);
    let claim = CircuitClaim {
        output_values: public.output_values.clone(),
    };
    let interaction_claim = CircuitInteractionClaim {
        claimed_sums: public.interaction_claim,
    };
    let mut channel = Blake2sChannel::default();
    channel.mix_felts(&[public.channel_salt.into()]);
    public.pcs_config.mix_into(&mut channel);
    let mut scheme = CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(public.pcs_config);
    let sizes = component_log_sizes(preprocessed);
    let [trace_sizes, interaction_sizes] = column_log_sizes_per_tree(&sizes);
    let pp_sizes = preprocessed
        .preprocessed_trace
        .log_sizes()
        .values()
        .copied()
        .collect::<Vec<_>>();
    scheme.commit(public.stark_proof.commitments[0], &pp_sizes, &mut channel);
    claim.mix_into(&mut channel);
    scheme.commit(
        public.stark_proof.commitments[1],
        &trace_sizes,
        &mut channel,
    );
    assert!(channel.verify_pow_nonce(INTERACTION_POW_BITS, public.interaction_pow_nonce));
    channel.mix_u64(public.interaction_pow_nonce);
    let elements = CircuitInteractionElements::draw(&mut channel);
    interaction_claim.mix_into(&mut channel);
    scheme.commit(
        public.stark_proof.commitments[2],
        &interaction_sizes,
        &mut channel,
    );
    let components = CircuitComponents::new(
        &elements,
        &interaction_claim,
        &sizes,
        &preprocessed.preprocessed_trace.ids(),
    )
    .components();
    stwo::core::verifier::verify_ex(
        &components
            .iter()
            .map(|component| component.as_ref())
            .collect::<Vec<&dyn Component>>(),
        &mut channel,
        &mut scheme,
        public.stark_proof.clone(),
        true,
    )
    .unwrap();
    assert_eq!(
        lookup_sum(&claim, &interaction_claim, &elements),
        QM31::zero()
    );
}

/// Reconstructs challenges using only the serialized public transcript, never prover aux data.
fn public_challenges(proof: &PublicProof) -> (CirclePoint<QM31>, Vec<usize>) {
    let stark = &proof.stark_proof;
    let mut channel = Blake2sChannel::default();
    channel.mix_felts(&[proof.channel_salt.into()]);
    proof.pcs_config.mix_into(&mut channel);
    Blake2sMerkleChannel::mix_root(&mut channel, stark.commitments[0]);
    channel.mix_felts(&proof.output_values);
    Blake2sMerkleChannel::mix_root(&mut channel, stark.commitments[1]);
    assert!(channel.verify_pow_nonce(INTERACTION_POW_BITS, proof.interaction_pow_nonce));
    channel.mix_u64(proof.interaction_pow_nonce);
    let _ = CircuitInteractionElements::draw(&mut channel);
    channel.mix_felts(&proof.interaction_claim);
    Blake2sMerkleChannel::mix_root(&mut channel, stark.commitments[2]);
    let _composition_coefficient = channel.draw_secure_felt();
    Blake2sMerkleChannel::mix_root(&mut channel, stark.commitments[3]);
    let ood = CirclePoint::<QM31>::get_random_point(&mut channel);
    channel.mix_felts(&stark.sampled_values.clone().flatten_cols());
    let _fri_coefficient = channel.draw_secure_felt();
    let bound = CirclePolyDegreeBound::new(
        proof.pcs_config.lifting_log_size.unwrap() - proof.pcs_config.fri_config.log_blowup_factor,
    );
    let mut fri = FriVerifier::<Blake2sMerkleChannel>::commit(
        &mut channel,
        proof.pcs_config.fri_config,
        stark.fri_proof.clone(),
        bound,
    )
    .unwrap();
    assert!(channel.verify_pow_nonce(proof.pcs_config.pow_bits, stark.proof_of_work));
    channel.mix_u64(stark.proof_of_work);
    (ood, fri.sample_query_positions(&mut channel))
}

fn rref(mut rows: Vec<Vec<M31>>, n_columns: usize) -> (Vec<Vec<M31>>, Vec<usize>) {
    let mut pivots = Vec::new();
    for column in 0..n_columns {
        let row = pivots.len();
        let Some(pivot) = (row..rows.len()).find(|&i| !rows[i][column].is_zero()) else {
            continue;
        };
        rows.swap(row, pivot);
        let inverse = rows[row][column].inverse();
        for entry in &mut rows[row] {
            *entry *= inverse;
        }
        let pivot_row = rows[row].clone();
        for (other, values) in rows.iter_mut().enumerate() {
            if other == row {
                continue;
            }
            let factor = values[column];
            for (value, pivot_value) in values.iter_mut().zip(&pivot_row) {
                *value -= factor * *pivot_value;
            }
        }
        pivots.push(column);
    }
    (rows, pivots)
}

fn recovery(matrix: &[Vec<M31>], observations: &[M31]) -> (usize, usize, Option<M31>) {
    let n_columns = matrix[0].len();
    let masks = matrix
        .iter()
        .map(|row| row[1..].to_vec())
        .collect::<Vec<_>>();
    let mask_rank = rref(masks, n_columns - 1).1.len();
    let augmented = matrix
        .iter()
        .zip(observations)
        .map(|(row, value)| {
            let mut row = row.clone();
            row.push(*value);
            row
        })
        .collect();
    let (rows, pivots) = rref(augmented, n_columns);
    assert!(
        rows.iter()
            .all(|row| { !row[..n_columns].iter().all(Zero::is_zero) || row[n_columns].is_zero() }),
        "Public observations are inconsistent with the Eq linear model"
    );
    let secret = pivots
        .iter()
        .position(|&column| column == 0)
        .and_then(|row| {
            rows[row][1..n_columns]
                .iter()
                .all(Zero::is_zero)
                .then_some(rows[row][n_columns])
        });
    (mask_rank, pivots.len(), secret)
}

/// Attacker boundary: only serialized ordinary proof fields and fixed public topology enter.
/// Returns recovered coordinates separately so the caller can compare against its local witness.
fn attack(
    serialized_proof: &[u8],
    serialized_topology: &[u8],
) -> (serde_json::Value, [Option<M31>; 4]) {
    let proof: PublicProof = serde_json::from_slice(serialized_proof).unwrap();
    let topology: PublicTopology = serde_json::from_slice(serialized_topology).unwrap();
    let (ood, queries) = public_challenges(&proof);
    let eq_eval_log = topology.eq_log_size + proof.pcs_config.fri_config.log_blowup_factor;
    let shift = proof.pcs_config.lifting_log_size.unwrap() - eq_eval_log;
    let folded_ood = ood.repeated_double(shift);
    let mut positions = Vec::new();
    let mut query_indices = Vec::new();
    for (index, &query) in queries.iter().enumerate() {
        let folded = (query >> (shift + 1) << 1) + (query & 1);
        if !positions.contains(&folded) {
            positions.push(folded);
            query_indices.push(index);
        }
    }
    let trace_domain = CanonicCoset::new(topology.eq_log_size).circle_domain();
    let eval_domain = CanonicCoset::new(eq_eval_log).circle_domain();
    let observe = |trace: Vec<M31>| {
        let polynomial =
            CircleEvaluation::<CpuBackend, M31, BitReversedOrder>::new(trace_domain, trace)
                .interpolate();
        let values = polynomial.evaluate(eval_domain).values;
        let mut result = positions
            .iter()
            .map(|&position| values[position])
            .collect::<Vec<_>>();
        result.extend(polynomial.eval_at_point(folded_ood).to_m31_array());
        result
    };
    let mut unknown_rows = vec![topology.private_rows.clone()];
    unknown_rows.extend(topology.mask_rows.iter().map(|&row| vec![row]));
    let columns = unknown_rows
        .iter()
        .map(|rows| {
            let mut delta = vec![M31::zero(); trace_domain.size()];
            for &row in rows {
                delta[row] = M31::one();
            }
            observe(delta)
        })
        .collect::<Vec<_>>();
    let matrix = (0..positions.len() + 4)
        .map(|row| columns.iter().map(|column| column[row]).collect::<Vec<_>>())
        .collect::<Vec<_>>();
    let mut recovered = [None; 4];
    let mut reports = Vec::new();
    for coordinate in 0..4 {
        let known = observe(
            topology
                .known_eq_values
                .iter()
                .map(|value| value[coordinate])
                .collect(),
        );
        let mut disclosed = query_indices
            .iter()
            .map(|&index| proof.stark_proof.queried_values[1][coordinate][index])
            .collect::<Vec<_>>();
        assert_eq!(proof.stark_proof.sampled_values[1][coordinate].len(), 1);
        disclosed.extend(proof.stark_proof.sampled_values[1][coordinate][0].to_m31_array());
        let residual = disclosed
            .iter()
            .zip(known)
            .map(|(value, known)| *value - known)
            .collect::<Vec<_>>();
        let (mask_rank, private_rank, secret) = recovery(&matrix, &residual);
        let (query_mask_rank, query_private_rank, query_secret) =
            recovery(&matrix[..positions.len()], &residual[..positions.len()]);
        recovered[coordinate] = secret;
        reports.push(json!({"coordinate":coordinate,"mask_rank":mask_rank,"private_plus_mask_rank":private_rank,"recovered":secret.is_some(),"query_only_mask_rank":query_mask_rank,"query_only_private_plus_mask_rank":query_private_rank,"query_only_recovered":query_secret.is_some()}));
    }
    (
        json!({"global_query_count":queries.len(),"distinct_folded_eq_queries":positions.len(),"matrix_rows":matrix.len(),"matrix_columns":columns.len(),"mask_count":topology.mask_rows.len(),"eq_log_size":topology.eq_log_size,"coordinates":reports}),
        recovered,
    )
}

fn main() {
    let directory = std::env::args()
        .nth(1)
        .expect("Usage: diagnostic OUTPUT_DIRECTORY");
    let directory = Path::new(&directory);
    fs::create_dir_all(directory).unwrap();
    let start = Instant::now();
    let topology_context = build::<NoValue>(NoValue, [0; 32]);
    let public_context = build(QM31::zero(), [0; 32]);
    assert!(topology_context.context.circuit() == public_context.context.circuit());
    let preprocessed =
        PreprocessedCircuit::from_finalized_circuit(topology_context.context.circuit());
    let eq_rows = &topology_context.context.circuit().eq;
    let private_rows = eq_rows
        .iter()
        .enumerate()
        .filter_map(|(row, gate)| (gate.in0 == topology_context.private_address).then_some(row))
        .collect::<Vec<_>>();
    assert_eq!(private_rows, vec![0]);
    let mask_rows = topology_context.mask_rows;
    let known_eq_values = eq_rows
        .iter()
        .enumerate()
        .map(|(row, gate)| {
            if private_rows.contains(&row) || mask_rows.contains(&row) {
                [M31::zero(); 4]
            } else {
                public_context.context.values()[gate.in0].to_m31_array()
            }
        })
        .collect::<Vec<_>>();
    let topology = PublicTopology {
        eq_log_size: eq_rows.len().ilog2(),
        private_rows,
        mask_rows,
        known_eq_values,
    };
    let topology_json = serde_json::to_vec_pretty(&topology).unwrap();
    fs::write(directory.join("public-topology.json"), &topology_json).unwrap();
    let mut reports = Vec::new();
    let mut roots = Vec::new();
    let root_twiddles = SimdBackend::precompute_twiddles(
        CanonicCoset::new(preprocessed.trace_log_size + config().fri_config.log_blowup_factor)
            .half_coset(),
    );
    let root_polynomials = SimdBackend::interpolate_columns(
        preprocessed.preprocessed_trace.get_trace::<SimdBackend>(),
        &root_twiddles,
    );
    let root_tree = CommitmentTreeProver::<SimdBackend, Blake2sMerkleChannel>::new(
        root_polynomials,
        config().fri_config.log_blowup_factor,
        &root_twiddles,
        false,
        Some(preprocessed.trace_log_size + config().fri_config.log_blowup_factor),
        &BaseColumnPool::new(),
    );
    let trusted_root = root_tree.commitment.root();
    drop(root_tree);
    drop(root_twiddles);
    // Hold the private input fixed while refreshing the independent secret blinding seed.
    let private = random_qm31();
    for run in 0..2 {
        let context = build(private, os_random::<32>());
        assert!(context.context.circuit() == topology_context.context.circuit());
        assert!(context.context.is_circuit_valid());
        for (row, gate) in context.context.circuit().eq.iter().enumerate() {
            if !topology.private_rows.contains(&row) && !topology.mask_rows.contains(&row) {
                assert_eq!(
                    context.context.values()[gate.in0].to_m31_array(),
                    topology.known_eq_values[row]
                );
            }
        }
        let prove_start = Instant::now();
        let circuit_proof = prove_circuit_assignment_with_channel::<Blake2sMerkleChannel>(
            context.context.values(),
            &preprocessed,
            &BaseColumnPool::<SimdBackend>::new(),
            config(),
        )
        .unwrap();
        let proving_seconds = prove_start.elapsed().as_secs_f64();
        let bridge_proof = CircuitProof {
            pcs_config: circuit_proof.pcs_config,
            claim: CircuitClaim {
                output_values: circuit_proof.claim.output_values.clone(),
            },
            interaction_pow_nonce: circuit_proof.interaction_pow_nonce,
            interaction_claim: CircuitInteractionClaim {
                claimed_sums: circuit_proof.interaction_claim.claimed_sums,
            },
            stark_proof: circuit_proof.stark_proof.clone(),
            channel_salt: circuit_proof.channel_salt,
        };
        let bridge_felts =
            bridge_serialize::serialize_proof(bridge_proof, &component_log_sizes(&preprocessed));
        let mut bridge_arguments = vec![format!("0x{:x}", bridge_felts.len())];
        bridge_arguments.extend(bridge_felts.iter().map(|felt| format!("{felt:#x}")));
        fs::write(
            directory.join(format!("cairo-arguments-{run}.json")),
            serde_json::to_vec(&bridge_arguments).unwrap(),
        )
        .unwrap();
        let CircuitProof {
            pcs_config,
            claim,
            interaction_pow_nonce,
            interaction_claim,
            stark_proof,
            channel_salt,
        } = circuit_proof;
        let public = PublicProof {
            pcs_config,
            output_values: claim.output_values,
            interaction_pow_nonce,
            interaction_claim: interaction_claim.claimed_sums,
            stark_proof: stark_proof.proof,
            channel_salt,
        };
        let root = trusted_root;
        native_verify(&public, &preprocessed, root);
        roots.push(format!("{:?}", public.stark_proof.commitments[1]));
        let serialized = serde_json::to_vec(&public).unwrap();
        fs::write(
            directory.join(format!("public-proof-{run}.json")),
            &serialized,
        )
        .unwrap();
        let (mut report, recovered) = attack(&serialized, &topology_json);
        let matches = recovered
            .iter()
            .zip(private.to_m31_array())
            .map(|(recovered, expected)| recovered.map(|value| value == expected))
            .collect::<Vec<_>>();
        report["recovered_matches_local_witness"] = json!(matches);
        report["native_verification_passed"] = json!(true);
        report["proving_seconds"] = json!(proving_seconds);
        report["serialized_public_proof_bytes"] = json!(serialized.len());
        reports.push(report);
    }
    assert_ne!(roots[0], roots[1]);
    let columns = preprocessed
        .preprocessed_trace
        .log_sizes()
        .iter()
        .map(|(id, size)| json!({"id":id.id,"log_size":size}))
        .collect::<Vec<_>>();
    let components = all_circuit_components::<NoValue>()
        .iter()
        .zip(component_log_sizes(&preprocessed))
        .map(|((name, _), size)| json!({"name":name,"log_size":size}))
        .collect::<Vec<_>>();
    let mut pcs_config = config();
    pcs_config.lifting_log_size =
        Some(preprocessed.trace_log_size + config().fri_config.log_blowup_factor);
    let root_u32 = trusted_root
        .0
        .chunks_exact(4)
        .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
        .collect::<Vec<_>>();
    let summary = json!({"classification":"synthetic privacy diagnostic; not a privacy-qualified prover","channel":"Blake2s","pcs_config":pcs_config,"interaction_pow_bits":INTERACTION_POW_BITS,"n_blinding_rows_per_component":N_MASKS,"preprocessed_root":trusted_root,"preprocessed_root_u32":root_u32,"preprocessed_columns":columns,"components":components,"output_addresses":[3,4,2],"independent_trace_roots":roots[0]!=roots[1],"total_seconds":start.elapsed().as_secs_f64(),"runs":reports});
    fs::write(
        directory.join("summary.json"),
        serde_json::to_vec_pretty(&summary).unwrap(),
    )
    .unwrap();
    println!("{}", serde_json::to_string_pretty(&summary).unwrap());
}
