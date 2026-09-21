//! Public synthetic validity/performance experiment. No protocol migration or privacy claim.
#[cfg(all(target_arch = "wasm32", not(target_feature = "simd128")))]
compile_error!("The documented WASM build requires simd128");
mod constants;
mod felt252;
mod felt_statement;
mod m31;
mod platform;
mod statement;
use anyhow::{Result, ensure};
use bincode::Options;
use cairo_air::relations::CommonLookupElements;
use platform::{Instant, phase};
use serde::{Deserialize, Serialize};
use serde_json::json;
use statement::{Mode, PublicData, Statement, mix_serialized};
use std::sync::Arc;
use stwo::core::{
    air::Component,
    channel::{Blake2sChannel, Channel},
    fields::{m31::M31, qm31::QM31},
    fri::FriConfig,
    pcs::{CommitmentSchemeVerifier, PcsConfig},
    poly::circle::CanonicCoset,
    proof::StarkProof,
    proof_of_work::GrindOps,
    vcs::blake2_hash::Blake2sHash,
    vcs_lifted::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher},
};
use stwo::prover::{
    CommitmentSchemeProver, ComponentProver,
    backend::simd::SimdBackend,
    poly::{BitReversedOrder, circle::PolyOps},
    prove,
};
use stwo_cairo_common::preprocessed_columns::preprocessed_trace::PreProcessedTrace;
use stwo_cairo_prover::witness::preprocessed_trace::gen_trace;
use stwo_constraint_framework::TraceLocationAllocator;
type Evaluation = stwo::prover::poly::circle::CircleEvaluation<SimdBackend, M31, BitReversedOrder>;
const INTERACTION_POW_BITS: u32 = 24;
const SCOPE: &str = "public synthetic M31 membership; mixed mode adds exact RTN residual hash union workload; no private/payment proof or protocol migration";
fn config(data: &PublicData) -> PcsConfig {
    PcsConfig {
        pow_bits: 27,
        fri_config: FriConfig::new(0, 3, 23, 4),
        lifting_log_size: Some(if data.residual.is_some() {
            23
        } else {
            data.m31_log() + 3
        }),
    }
}
fn twiddle_log(data: &PublicData) -> u32 {
    if data.residual.is_some() {
        24
    } else {
        data.m31_log() + 3
    }
}
fn preprocessing(data: &PublicData) -> Arc<PreProcessedTrace> {
    if let Some(r) = &data.residual {
        felt252::preprocessing(r.aggregator_log_size())
    } else {
        let mut p = PreProcessedTrace::canonical_without_pedersen();
        p.columns.clear();
        p.column_indices.clear();
        Arc::new(p)
    }
}
#[derive(Clone, Serialize, Deserialize)]
struct Claims {
    m31_log: u32,
    residual: Option<felt252::Claims>,
}
impl Claims {
    fn sizes(&self) -> [Vec<u32>; 2] {
        let mut sizes = self
            .residual
            .as_ref()
            .map_or([vec![], vec![]], |r| r.sizes());
        sizes[0].extend(vec![self.m31_log; m31::COLUMNS]);
        sizes[1].extend(vec![self.m31_log; 4]);
        sizes
    }
    fn validate(&self, data: &PublicData) -> Result<()> {
        ensure!(
            self.m31_log == data.m31_log() && self.m31_log == 8,
            "M31 component shape"
        );
        match (&self.residual, &data.residual) {
            (None, None) => (),
            (Some(c), Some(d)) => c.validate(d)?,
            _ => anyhow::bail!("component mode mismatch"),
        };
        Ok(())
    }
    fn components(
        &self,
        sums: &[QM31],
        lookup: &CommonLookupElements,
        pre: &PreProcessedTrace,
    ) -> Result<Vec<Box<dyn ComponentProver<SimdBackend>>>> {
        let mut allocator = TraceLocationAllocator::new_with_preprocessed_columns(&pre.ids());
        let n = if self.residual.is_some() { 12 } else { 0 };
        ensure!(sums.len() == n + 1, "claimed sum count");
        let mut out = if let Some(r) = &self.residual {
            r.components(&sums[..n], lookup, pre, &mut allocator)?
        } else {
            vec![]
        };
        out.push(Box::new(m31::Component::new(
            &mut allocator,
            m31::Eval {
                log_size: self.m31_log,
                lookup: lookup.clone(),
            },
            sums[n],
        )));
        allocator.validate_preprocessed_columns(&pre.ids());
        Ok(out)
    }
    fn metadata(&self) -> Vec<serde_json::Value> {
        let mut v = self.residual.as_ref().map_or(vec![], |r| r.metadata());
        v.push(json!({"name":"poseidon2_m31_width24","log_rows":self.m31_log,"rows":1u32<<self.m31_log,"trace_columns":m31::COLUMNS,"interaction_base_columns":4,"constraint_degree":2}));
        v
    }
}
#[derive(Clone, Serialize, Deserialize)]
struct Envelope {
    statement: Statement,
    claims: Claims,
    sums: Vec<QM31>,
    interaction_pow: u64,
    proof: StarkProof<Blake2sMerkleHasher>,
}
fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    Ok(bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .deserialize(bytes)?)
}

fn initial_channel(s: &Statement, data: &PublicData) -> Blake2sChannel {
    let mut c = Blake2sChannel::default();
    mix_serialized(&mut c, &"templar-public-m31-tree-v1");
    config(data).mix_into(&mut c);
    mix_serialized(&mut c, s);
    c
}
/// The pinned prover represents a zero-column tree as one empty leaf (height zero),
/// even when other trees use explicit lifting. Its generic verifier constructor instead
/// applies lifting to that empty tree. Normalize only the first, independently trusted
/// preprocessing tree; the commitment, transcript, and all nonempty trees are unchanged.
fn commit_trusted_preprocessing(
    pcs: &mut CommitmentSchemeVerifier<Blake2sMerkleChannel>,
    root: Blake2sHash,
    log_sizes: &[u32],
    channel: &mut Blake2sChannel,
) {
    assert!(pcs.trees.is_empty(), "preprocessing must be the first tree");
    pcs.commit(root, log_sizes, channel);
    if log_sizes.is_empty() {
        assert!(pcs.trees[0].column_log_sizes.is_empty());
        pcs.trees[0].height = 0;
    }
}

fn verify(e: Envelope, root: Blake2sHash, pre: &PreProcessedTrace) -> Result<()> {
    let data = e.statement.validate()?;
    e.claims.validate(&data)?;
    ensure!(e.proof.config == config(&data), "untrusted proof config");
    ensure!(
        e.proof.commitments.len() == 4 && e.proof.commitments[0] == root,
        "untrusted preprocessing root/commitment count"
    );
    if pre.columns.is_empty() {
        ensure!(
            e.proof.sampled_values.first().is_some_and(Vec::is_empty)
                && e.proof.queried_values.first().is_some_and(Vec::is_empty)
                && e.proof
                    .decommitments
                    .first()
                    .is_some_and(|d| d.hash_witness.is_empty()),
            "nonempty opening for empty preprocessing"
        );
    }
    let mut ch = initial_channel(&e.statement, &data);
    let mut pcs = CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(config(&data));
    commit_trusted_preprocessing(&mut pcs, root, &pre.log_sizes(), &mut ch);
    mix_serialized(&mut ch, &e.claims);
    let sizes = e.claims.sizes();
    pcs.commit(e.proof.commitments[1], &sizes[0], &mut ch);
    ensure!(
        ch.verify_pow_nonce(INTERACTION_POW_BITS, e.interaction_pow),
        "interaction PoW"
    );
    ch.mix_u64(e.interaction_pow);
    let lookup = CommonLookupElements::draw(&mut ch);
    ensure!(
        data.boundary(&lookup) + e.sums.iter().copied().sum::<QM31>() == QM31::from(0),
        "public lookup boundary"
    );
    ch.mix_felts(&e.sums);
    pcs.commit(e.proof.commitments[2], &sizes[1], &mut ch);
    let components = e.claims.components(&e.sums, &lookup, pre)?;
    stwo::core::verifier::verify(
        &components
            .iter()
            .map(|c| c.as_ref() as &dyn Component)
            .collect::<Vec<_>>(),
        &mut ch,
        &mut pcs,
        e.proof,
    )?;
    Ok(())
}

pub struct ProofArtifacts {
    pub proof_bytes: Vec<u8>,
    pub proof_json: Vec<u8>,
    pub summary_json: String,
    pub shape_json: String,
}
pub fn fixture_json(mixed: bool) -> Result<String> {
    let s = Statement::synthetic(if mixed { Mode::Mixed } else { Mode::TreeOnly })?;
    Ok(serde_json::to_string_pretty(&s)?)
}
pub fn prove_fixture(fixture_json: &str) -> Result<ProofArtifacts> {
    let full = Instant::now();
    platform::initialize();
    let mut phases = serde_json::Map::new();
    let start = Instant::now();
    let fixture: Statement = serde_json::from_str(fixture_json)?;
    let statement = fixture.regenerate()?;
    let data = statement.validate()?;
    phases.insert(
        "public_transcript_regeneration_seconds".into(),
        json!(start.elapsed().as_secs_f64()),
    );
    phase("public transcript regenerated and fixture parity passed");
    let start = Instant::now();
    let pre = preprocessing(&data);
    let twiddles = SimdBackend::precompute_twiddles(
        CanonicCoset::new(twiddle_log(&data))
            .circle_domain()
            .half_coset,
    );
    let mut ch = initial_channel(&statement, &data);
    let mut pcs =
        CommitmentSchemeProver::<SimdBackend, Blake2sMerkleChannel>::new(config(&data), &twiddles);
    pcs.set_bounded_memory_mode(16);
    let mut tree = pcs.tree_builder();
    tree.extend_evals(gen_trace(pre.clone()));
    tree.commit(&mut ch);
    let root = pcs.trees[0].commitment.root();
    phases.insert(
        "preprocessing_twiddles_and_commit_seconds".into(),
        json!(start.elapsed().as_secs_f64()),
    );
    phase("preprocessing commitment complete; generating witness");
    let start = Instant::now();
    let (mut evals, residual, generators) = if let Some(d) = &data.residual {
        let (e, c, g) = felt252::witness(d, pre.clone());
        (e, Some(c), Some(g))
    } else {
        (vec![], None, None)
    };
    evals.extend(m31::witness(&data.m31_rows)?);
    let claims = Claims {
        m31_log: data.m31_log(),
        residual,
    };
    claims.validate(&data)?;
    phases.insert(
        "base_witness_seconds".into(),
        json!(start.elapsed().as_secs_f64()),
    );
    let shape = serde_json::to_string_pretty(
        &json!({"mode":statement.mode,"pcs_config":config(&data),"interaction_pow_bits":INTERACTION_POW_BITS,"trusted_preprocessed_root":root,"components":claims.metadata(),"preprocessed":pre.columns.iter().map(|c|json!({"id":c.id().id,"log_size":c.log_size()})).collect::<Vec<_>>()}),
    )?;
    let start = Instant::now();
    phase("base witness complete; committing trace");
    mix_serialized(&mut ch, &claims);
    let mut tree = pcs.tree_builder();
    tree.extend_evals(evals);
    tree.commit(&mut ch);
    phases.insert(
        "base_commit_seconds".into(),
        json!(start.elapsed().as_secs_f64()),
    );
    let start = Instant::now();
    phase("base commitment complete; interaction PoW and witness");
    let interaction_pow = SimdBackend::grind(&ch, INTERACTION_POW_BITS);
    ch.mix_u64(interaction_pow);
    let lookup = CommonLookupElements::draw(&mut ch);
    let (mut evals, mut sums) = if let Some(g) = generators {
        g.interactions(&lookup)
    } else {
        (vec![], vec![])
    };
    let (e, sum) = m31::interaction(&data.m31_rows, &lookup);
    evals.extend(e);
    sums.push(sum);
    ensure!(
        data.boundary(&lookup) + sums.iter().copied().sum::<QM31>() == QM31::from(0),
        "prover lookup balance"
    );
    phases.insert(
        "interaction_pow_and_witness_seconds".into(),
        json!(start.elapsed().as_secs_f64()),
    );
    let start = Instant::now();
    phase("interaction witness complete; commitment and STARK proving");
    ch.mix_felts(&sums);
    let mut tree = pcs.tree_builder();
    tree.extend_evals(evals);
    tree.commit(&mut ch);
    let components = claims.components(&sums, &lookup, &pre)?;
    let proof = prove(
        &components.iter().map(|c| c.as_ref()).collect::<Vec<_>>(),
        &mut ch,
        pcs,
    )?;
    phases.insert(
        "interaction_commit_and_stark_prove_seconds".into(),
        json!(start.elapsed().as_secs_f64()),
    );
    phase("proof generated; verifying serialized public envelope");
    let envelope = Envelope {
        statement,
        claims,
        sums,
        interaction_pow,
        proof,
    };
    let binary = bincode::serialize(&envelope)?;
    let proof_json = serde_json::to_vec(&envelope)?;
    let start = Instant::now();
    verify(decode(&binary)?, root, &pre)?;
    phases.insert(
        "verify_seconds".into(),
        json!(start.elapsed().as_secs_f64()),
    );
    let summary = json!({"scope":SCOPE,"mode":envelope.statement.mode,"algorithm":statement::ALGORITHM,"plonky3_pin":"00fe0a985b398d3ef1f10d69543ca2b8f9f236da","max_fri_columns":16,"channel":"Blake2s","pcs_config":config(&data),"config_security_metric_bits":config(&data).security_bits(),"security_metric_note":"existing configured metric, not a new exact soundness bound for small domains","interaction_pow_bits":INTERACTION_POW_BITS,"interaction_pow_nonce":envelope.interaction_pow.to_string(),"fri_pow_nonce":envelope.proof.proof_of_work.to_string(),"trusted_preprocessed_root":root,"components":envelope.claims.metadata(),"m31_tree_requests":data.m31_requests.len(),"m31_tree_rows_with_padding":data.m31_rows.len(),"m31_padding_repeats":data.m31_rows.len()-data.m31_requests.len(),"felt252_residual_hash_calls":if data.residual.is_some(){17}else{0},"felt252_residual_permutations":data.residual.as_ref().map_or(0,|r|r.requests.len()),"felt252_aggregator_unique_rows":data.residual.as_ref().map_or(0,|r|r.unique.len()),"felt252_aggregator_padded_rows":data.residual.as_ref().map_or(0,|r|r.rows.len()),"felt252_public_memory_boundary_terms":data.residual.as_ref().map_or(0,|r|r.rows.len()*6),"binding_root_relationship":"mixed residual binding root independent of M31 root; workload union, no migrated payment statement","reference_parity":true,"proof_verified_in_runtime":true,"native_proof_verified":cfg!(not(target_arch="wasm32")),"execution_target":std::env::consts::ARCH,"runtime":if cfg!(target_arch="wasm32"){ "wasm32 single worker simd128"}else{"native shared in-memory core"},"binary_envelope_bytes":binary.len(),"json_envelope_bytes":proof_json.len(),"public_statement_json_bytes":serde_json::to_vec(&envelope.statement)?.len(),"binary_stark_proof_bytes":bincode::serialize(&envelope.proof)?.len(),"phases":phases,"complete_seconds":full.elapsed().as_secs_f64(),"wasm_linear_memory_bytes":platform::linear_memory_bytes()});
    Ok(ProofArtifacts {
        proof_bytes: binary,
        proof_json,
        summary_json: serde_json::to_string_pretty(&summary)?,
        shape_json: shape,
    })
}
fn trusted_preprocessing(e: &Envelope) -> Result<(Blake2sHash, Arc<PreProcessedTrace>)> {
    let data = e.statement.validate()?;
    let pre = preprocessing(&data);
    let twiddles = SimdBackend::precompute_twiddles(
        CanonicCoset::new(twiddle_log(&data))
            .circle_domain()
            .half_coset,
    );
    let mut ch = initial_channel(&e.statement, &data);
    let mut pcs =
        CommitmentSchemeProver::<SimdBackend, Blake2sMerkleChannel>::new(config(&data), &twiddles);
    pcs.set_bounded_memory_mode(16);
    let mut tree = pcs.tree_builder();
    tree.extend_evals(gen_trace(pre.clone()));
    tree.commit(&mut ch);
    Ok((pcs.trees[0].commitment.root(), pre))
}
pub fn verify_bytes(bytes: &[u8]) -> Result<()> {
    platform::initialize();
    let e: Envelope = decode(bytes)?;
    let (root, pre) = trusted_preprocessing(&e)?;
    verify(e, root, &pre)
}

pub fn mutation_checks(bytes: &[u8]) -> Result<String> {
    platform::initialize();
    let e: Envelope = decode(bytes)?;
    let (root, pre) = trusted_preprocessing(&e)?;
    verify(e.clone(), root, &pre)?;
    let mut checks = vec![];
    macro_rules! reject {
        ($name:expr,$edit:expr) => {{
            let mut bad = e.clone();
            ($edit)(&mut bad);
            ensure!(
                verify(bad, root, &pre).is_err(),
                "accepted mutation {}",
                $name
            );
            checks.push($name);
        }};
    }
    reject!("root", |e: &mut Envelope| e.statement.root[0] =
        (e.statement.root[0] + 1) % m31::P);
    reject!("packed_root", |e: &mut Envelope| e.statement.packed_root
        [1] = "0x1".into());
    reject!("leaf", |e: &mut Envelope| e.statement.paths[0].leaf =
        "0x0".into());
    reject!("index", |e: &mut Envelope| e.statement.paths[0].index ^= 1);
    reject!("sibling", |e: &mut Envelope| e.statement.paths[0]
        .siblings[0][0] =
        (e.statement.paths[0].siblings[0][0] + 1) % m31::P);
    reject!("domain_kind", |e: &mut Envelope| e.statement.paths[0]
        .nodes[0]
        .permutations[0]
        .input[2] = 1);
    reject!("domain_level", |e: &mut Envelope| e.statement.paths[0]
        .nodes[0]
        .permutations[0]
        .input[3] = 2);
    reject!("padding", |e: &mut Envelope| e.statement.paths[0].nodes
        [0]
    .permutations[1]
        .input[7] = 0);
    reject!("noncanonical_M31", |e: &mut Envelope| e.statement.paths
        [0]
    .siblings[0][0] =
        m31::P);
    reject!("component_log", |e: &mut Envelope| e.claims.m31_log += 1);
    reject!("claimed_sum", |e: &mut Envelope| e.sums[0] += QM31::from(1));
    reject!("interaction_pow", |e: &mut Envelope| e.interaction_pow ^= 1);
    reject!("PCS_config", |e: &mut Envelope| e
        .proof
        .0
        .config
        .pow_bits -= 1);
    reject!("STARK_sample", |e: &mut Envelope| e
        .proof
        .0
        .sampled_values[1][0][0] +=
        QM31::from(1));
    reject!("preprocessed_root", |e: &mut Envelope| e
        .proof
        .0
        .commitments[0] =
        Blake2sHash::default());
    let mut bad = e.clone();
    let output = &mut bad.statement.paths[0].nodes[0].permutations[1].output[23];
    *output = (*output + 1) % m31::P;
    bad.statement.validate()?;
    ensure!(
        verify(bad, root, &pre).is_err(),
        "unlinked M31 output accepted"
    );
    checks.push("structurally_valid_unlinked_M31_output");
    if e.statement.residual.is_some() {
        let mut bad = e.clone();
        let output = &mut bad
            .statement
            .residual
            .as_mut()
            .unwrap()
            .calls
            .last_mut()
            .unwrap()
            .permutations
            .last_mut()
            .unwrap()
            .output[2];
        *output = felt_statement::hex(
            felt_statement::felt(output)? + starknet_types_core::felt::Felt::ONE,
        );
        bad.statement.validate()?;
        ensure!(
            verify(bad, root, &pre).is_err(),
            "unlinked Hades output accepted"
        );
        checks.push("structurally_valid_unlinked_Hades_output");
    }
    if pre.columns.is_empty() {
        reject!("extra_empty_preprocessing_sample", |e: &mut Envelope| e
            .proof
            .0
            .sampled_values[0]
            .push(vec![QM31::from(1)]));
        reject!("extra_empty_preprocessing_query", |e: &mut Envelope| e
            .proof
            .0
            .queried_values[0]
            .push(vec![M31::from(1)]));
        reject!("extra_empty_preprocessing_witness", |e: &mut Envelope| e
            .proof
            .0
            .decommitments[0]
            .hash_witness
            .push(Blake2sHash::default()));
    }
    let data = e.statement.validate()?;
    let mut ch = initial_channel(&e.statement, &data);
    let mut pcs = CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(config(&data));
    commit_trusted_preprocessing(&mut pcs, root, &pre.log_sizes(), &mut ch);
    mix_serialized(&mut ch, &e.claims);
    pcs.commit(e.proof.commitments[1], &e.claims.sizes()[0], &mut ch);
    ch.mix_u64(e.interaction_pow);
    let lookup = CommonLookupElements::draw(&mut ch);
    let sums = e.sums.iter().copied().sum::<QM31>();
    let correct = data.boundary(&lookup);
    ensure!(correct + sums == QM31::from(0), "original boundary");
    let remainder = correct - m31::boundary(&data.m31_rows, &lookup);
    ensure!(
        m31::boundary(&data.m31_requests, &lookup) + remainder + sums != QM31::from(0),
        "M31 padding control not exercised"
    );
    let mut dedup = data.m31_rows.clone();
    dedup.sort_by_key(|r| (r.input, r.output));
    dedup.dedup();
    ensure!(
        m31::boundary(&dedup, &lookup) + remainder + sums != QM31::from(0),
        "M31 multiplicity control not exercised"
    );
    let mut report = json!({"rejected_mutations":checks,"omitted_M31_padding_boundary_rejected":true,"discarded_M31_duplicate_multiplicity_rejected":true});
    if let Some(mut d) = data.residual {
        let original = d.boundary(&lookup);
        d.values[0] += starknet_types_core::felt::Felt::ONE;
        ensure!(
            correct - original + d.boundary(&lookup) + sums != QM31::from(0),
            "wrong felt dictionary control"
        );
        report["wrong_felt_memory_dictionary_rejected"] = json!(true);
    }
    Ok(serde_json::to_string_pretty(&report)?)
}

#[cfg(target_arch = "wasm32")]
mod browser {
    use super::*;
    use wasm_bindgen::prelude::*;
    #[wasm_bindgen]
    pub struct MembershipResult {
        proof: Vec<u8>,
        summary: String,
        shape: String,
    }
    #[wasm_bindgen]
    impl MembershipResult {
        #[wasm_bindgen(getter)]
        pub fn proof_bytes(&self) -> Vec<u8> {
            self.proof.clone()
        }
        #[wasm_bindgen(getter)]
        pub fn summary_json(&self) -> String {
            self.summary.clone()
        }
        #[wasm_bindgen(getter)]
        pub fn shape_json(&self) -> String {
            self.shape.clone()
        }
    }
    #[wasm_bindgen]
    pub fn prove_membership(fixture_json: &str) -> Result<MembershipResult, JsValue> {
        let a = prove_fixture(fixture_json).map_err(|e| JsValue::from_str(&format!("{e:#}")))?;
        Ok(MembershipResult {
            proof: a.proof_bytes,
            summary: a.summary_json,
            shape: a.shape_json,
        })
    }
    #[wasm_bindgen]
    pub fn verify_membership(bytes: &[u8]) -> Result<bool, JsValue> {
        verify_bytes(bytes).map_err(|e| JsValue::from_str(&format!("{e:#}")))?;
        Ok(true)
    }
    #[wasm_bindgen]
    pub fn test_membership_mutations(bytes: &[u8]) -> Result<String, JsValue> {
        mutation_checks(bytes).map_err(|e| JsValue::from_str(&format!("{e:#}")))
    }
}

#[cfg(test)]
mod wire_tests {
    #[test]
    fn empty_preprocessing_matches_prover_height_without_transcript_change() {
        use super::*;
        use stwo::core::vcs_lifted::verifier::MerkleVerificationError;
        use stwo::prover::vcs_lifted::prover::MerkleProverLifted;
        let tree = MerkleProverLifted::<SimdBackend, Blake2sMerkleHasher>::commit(vec![], 11, 0);
        assert_eq!(tree.layers.len(), 1);
        let root = tree.root();
        let positions = [1, 4, 9];
        let (values, opening) = tree.decommit(&positions, vec![]);
        assert!(values.is_empty() && opening.decommitment.hash_witness.is_empty());
        let cfg = PcsConfig {
            pow_bits: 27,
            fri_config: FriConfig::new(0, 3, 23, 4),
            lifting_log_size: Some(11),
        };
        let mut raw = CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(cfg);
        let mut raw_channel = Blake2sChannel::default();
        raw.commit(root, &[], &mut raw_channel);
        assert_eq!(raw.trees[0].height, 11);
        assert_eq!(
            raw.trees[0].verify(&positions, values.clone(), opening.decommitment.clone()),
            Err(MerkleVerificationError::WitnessTooShort)
        );
        let mut normalized = CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(cfg);
        let mut normalized_channel = Blake2sChannel::default();
        commit_trusted_preprocessing(&mut normalized, root, &[], &mut normalized_channel);
        assert_eq!(normalized.trees[0].height, 0);
        assert_eq!(normalized.config, raw.config);
        assert_eq!(
            normalized_channel.draw_secure_felt(),
            raw_channel.draw_secure_felt()
        );
        normalized.trees[0]
            .verify(&positions, values, opening.decommitment)
            .unwrap();
    }
    #[test]
    fn fixed_encoding_requires_complete_envelope() {
        let bytes = bincode::serialize(&vec![1u64, 9, u64::MAX]).unwrap();
        assert_eq!(
            super::decode::<Vec<u64>>(&bytes).unwrap(),
            vec![1, 9, u64::MAX]
        );
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(super::decode::<Vec<u64>>(&trailing).is_err());
        assert!(super::decode::<Vec<u64>>(&bytes[..bytes.len() - 1]).is_err());
    }
}
