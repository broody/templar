//! Payment-shaped M31 statement: prove/verify harness for client-cost
//! measurement. Measurement pathfinding only — no privacy claim, no format
//! commitment; synthetic secrets are carried in the clear at this stage.
mod constants;
mod m31;
pub mod statement;
pub mod rank_dump;
pub mod dual;
pub mod solve_probe;


use crate::statement::{PaymentStatement, PublicData};
use starknet_types_core::felt::Felt;
use anyhow::{Result, ensure};
use bincode::Options;
use cairo_air::relations::CommonLookupElements;
use num_traits::One;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::time::Instant;
use stwo::core::{
    air::Component,
    channel::{Blake2sChannel, Channel},
    fields::qm31::QM31,
    fri::FriConfig,
    pcs::{CommitmentSchemeVerifier, PcsConfig},
    poly::circle::CanonicCoset,
    proof::StarkProof,
    proof_of_work::GrindOps,
    vcs::blake2_hash::Blake2sHash,
    vcs_lifted::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher},
};
use stwo::prover::{
    CommitmentSchemeProver, backend::simd::SimdBackend, poly::{BitReversedOrder, circle::PolyOps}, prove,
};
use stwo_constraint_framework::TraceLocationAllocator;

type Evaluation = stwo::prover::poly::circle::CircleEvaluation<SimdBackend, stwo::core::fields::m31::M31, BitReversedOrder>;

#[derive(Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub statement: PaymentStatement,
    pub interaction_pow: u64,
    pub claimed_sum: QM31,
    pub proof: StarkProof<Blake2sMerkleHasher>,
}
const INTERACTION_POW_BITS: u32 = 24;

fn config(d: &PublicData) -> PcsConfig {
    PcsConfig {
        pow_bits: 27,
        fri_config: FriConfig::new(0, 3, 23, 4),
        lifting_log_size: Some(d.log_size() + 3),
    }
}

fn initial(s: &PaymentStatement, d: &PublicData) -> Blake2sChannel {
    let _ = s;
    let mut ch = Blake2sChannel::default();
    statement::mix_words(&mut ch, &d.words);
    config(d).mix_into(&mut ch);
    ch
}

fn empty_root() -> Blake2sHash {
    use stwo::prover::vcs_lifted::prover::MerkleProverLifted;
    MerkleProverLifted::<SimdBackend, Blake2sMerkleHasher>::commit(vec![], 0, 0).root()
}

fn commit_preprocessing(
    pcs: &mut CommitmentSchemeVerifier<Blake2sMerkleChannel>,
    ch: &mut Blake2sChannel,
) {
    assert!(pcs.trees.is_empty());
    pcs.commit(empty_root(), &[], ch);
    pcs.trees[0].height = 0;
}

fn component(log: u32, lookup: &CommonLookupElements, sum: QM31) -> m31::Component {
    m31::Component::new(
        &mut TraceLocationAllocator::new_with_preprocessed_columns(&[]),
        m31::Eval {
            log_size: log,
            lookup: lookup.clone(),
        },
        sum,
    )
}

fn verify(e: Envelope) -> Result<()> {
    let d = e.statement.validate()?;
    let cfg = config(&d);
    ensure!(e.proof.config == cfg, "untrusted config");
    ensure!(
        e.proof.commitments.len() == 4 && e.proof.commitments[0] == empty_root(),
        "untrusted preprocessing root/shape"
    );
    ensure!(
        e.proof.sampled_values.first().is_some_and(Vec::is_empty)
            && e.proof.queried_values.first().is_some_and(Vec::is_empty)
            && e.proof
                .decommitments
                .first()
                .is_some_and(|x| x.hash_witness.is_empty()),
        "nonempty preprocessing opening"
    );
    let mut ch = initial(&e.statement, &d);
    let mut pcs = CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(cfg);
    commit_preprocessing(&mut pcs, &mut ch);
    ch.mix_u64(d.log_size() as u64);
    pcs.commit(
        e.proof.commitments[1],
        &vec![d.log_size(); m31::COLUMNS],
        &mut ch,
    );
    ensure!(
        ch.verify_pow_nonce(INTERACTION_POW_BITS, e.interaction_pow),
        "interaction PoW"
    );
    ch.mix_u64(e.interaction_pow);
    let lookup = CommonLookupElements::draw(&mut ch);
    ensure!(
        m31::boundary(&d.rows, &lookup) + e.claimed_sum == QM31::from(0),
        "payment public boundary"
    );
    ch.mix_felts(&[e.claimed_sum]);
    pcs.commit(e.proof.commitments[2], &[d.log_size(); 4], &mut ch);
    let component = component(d.log_size(), &lookup, e.claimed_sum);
    stwo::core::verifier::verify(&[&component as &dyn Component], &mut ch, &mut pcs, e.proof)?;
    Ok(())
}

fn decode(bytes: &[u8]) -> Result<Envelope> {
    Ok(bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .deserialize(bytes)?)
}
pub fn verify_bytes(bytes: &[u8]) -> Result<()> {
    verify(decode(bytes)?)
}

pub struct Artifacts {
    pub proof: Vec<u8>,
    pub proof_json: Vec<u8>,
    pub summary: String,
    pub statement: String,
}

pub fn prove_fixture(fixture: &str) -> Result<Artifacts> {
    let full = Instant::now();
    let statement: PaymentStatement = serde_json::from_str(fixture)?;
    let d = statement.validate()?;
    let mut phases = serde_json::Map::new();
    let start = Instant::now();
    let twiddles = SimdBackend::precompute_twiddles(
        CanonicCoset::new(d.log_size() + 3).circle_domain().half_coset,
    );
    let mut ch = initial(&statement, &d);
    let mut pcs =
        CommitmentSchemeProver::<SimdBackend, Blake2sMerkleChannel>::new(config(&d), &twiddles);
    pcs.set_bounded_memory_mode(16);
    pcs.tree_builder().commit(&mut ch);
    ensure!(
        pcs.trees[0].commitment.root() == empty_root(),
        "empty root parity"
    );
    let trace = m31::witness(&d.rows)?;
    phases.insert(
        "twiddles_and_witness_seconds".into(),
        json!(start.elapsed().as_secs_f64()),
    );
    let start = Instant::now();
    ch.mix_u64(d.log_size() as u64);
    let mut tree = pcs.tree_builder();
    tree.extend_evals(trace);
    tree.commit(&mut ch);
    phases.insert(
        "base_commit_seconds".into(),
        json!(start.elapsed().as_secs_f64()),
    );
    let start = Instant::now();
    let interaction_pow = SimdBackend::grind(&ch, INTERACTION_POW_BITS);
    ch.mix_u64(interaction_pow);
    let lookup = CommonLookupElements::draw(&mut ch);
    let (trace, sum) = m31::interaction(&d.rows, &lookup);
    ensure!(
        sum + m31::boundary(&d.rows, &lookup) == QM31::from(0),
        "witness lookup balance"
    );
    ch.mix_felts(&[sum]);
    let mut tree = pcs.tree_builder();
    tree.extend_evals(trace);
    tree.commit(&mut ch);
    phases.insert(
        "interaction_seconds".into(),
        json!(start.elapsed().as_secs_f64()),
    );
    let start = Instant::now();
    let component = component(d.log_size(), &lookup, sum);
    let proof = prove(&[&component], &mut ch, pcs)?;
    phases.insert(
        "stark_prove_seconds".into(),
        json!(start.elapsed().as_secs_f64()),
    );
    let envelope = Envelope {
        statement,
        interaction_pow,
        claimed_sum: sum,
        proof,
    };
    let bytes = bincode::serialize(&envelope)?;
    let start = Instant::now();
    verify_bytes(&bytes)?;
    phases.insert(
        "native_verify_seconds".into(),
        json!(start.elapsed().as_secs_f64()),
    );
    let summary = json!({
        "scope": "payment-shaped M31 statement measurement; no private-payment or privacy claim; secrets synthetic and in the clear",
        "requests": d.requests.len(),
        "rows": d.rows.len(),
        "trace_columns": m31::COLUMNS,
        "log_size": d.log_size(),
        "pcs_config": config(&d),
        "interaction_pow_bits": INTERACTION_POW_BITS,
        "binary_bytes": bytes.len(),
        "native_verified": true,
        "phases": phases,
        "complete_seconds": full.elapsed().as_secs_f64(),
    });
    Ok(Artifacts {
        proof: bytes,
        proof_json: serde_json::to_vec(&envelope)?,
        summary: serde_json::to_string_pretty(&summary)?,
        statement: serde_json::to_string_pretty(&envelope.statement)?,
    })
}

pub fn mutations(bytes: &[u8]) -> Result<String> {
    let e = decode(bytes)?;
    verify(e.clone())?;
    let mut names = vec![];
    macro_rules! reject {
        ($name:expr,$f:expr) => {{
            let mut bad = e.clone();
            ($f)(&mut bad);
            ensure!(verify(bad).is_err(), "accepted mutation {}", $name);
            names.push($name);
        }};
    }
    reject!("chain", |e: &mut Envelope| e.statement.chain_id = statement::hex(
        statement::felt(&e.statement.chain_id).unwrap() + Felt::ONE
    ));
    reject!("pool", |e: &mut Envelope| e.statement.pool = statement::hex(
        statement::felt(&e.statement.pool).unwrap() + Felt::ONE
    ));
    reject!("root", |e: &mut Envelope| e.statement.root[0] = (e.statement.root[0] + 1) % m31::P);
    reject!("nullifier", |e: &mut Envelope| e.statement.nullifiers[0][0] =
        (e.statement.nullifiers[0][0] + 1) % m31::P);
    reject!("leaf_substitution", |e: &mut Envelope| e.statement.leaves[0][0] =
        (e.statement.leaves[0][0] + 1) % m31::P);
    reject!("sibling", |e: &mut Envelope| e.statement.siblings[0][5][0] =
        (e.statement.siblings[0][5][0] + 1) % m31::P);
    reject!("index_bit", |e: &mut Envelope| e.statement.indices[0] ^= 2);
    reject!("secret", |e: &mut Envelope| e.statement.secrets[0][0] =
        (e.statement.secrets[0][0] + 1) % m31::P);
    reject!("interaction_pow", |e: &mut Envelope| e.interaction_pow ^= 1);
    reject!("base_commitment", |e: &mut Envelope| e.proof.0.commitments[1].0[0] ^= 1);
    reject!("untrusted_config", |e: &mut Envelope| e.proof.0.config.pow_bits -= 1);
    reject!("sampled_value", |e: &mut Envelope| e.proof.0.sampled_values[1][0][0] +=
        stwo::core::fields::qm31::QM31::one());
    reject!("sum", |e: &mut Envelope| e.claimed_sum += stwo::core::fields::qm31::QM31::one());
    reject!("preprocessing_root", |e: &mut Envelope| e.proof.0.commitments[0] =
        Blake2sHash::default());
    let mut trailing = bytes.to_vec();
    trailing.push(0);
    ensure!(decode(&trailing).is_err(), "trailing envelope accepted");
    names.push("trailing_envelope");
    ensure!(
        decode(&bytes[..bytes.len() - 1]).is_err(),
        "truncated envelope accepted"
    );
    names.push("truncated_envelope");
    // Padding omission control: the unpadded request set must not balance.
    let d = e.statement.validate()?;
    let mut ch = initial(&e.statement, &d);
    let mut pcs = CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(config(&d));
    commit_preprocessing(&mut pcs, &mut ch);
    ch.mix_u64(d.log_size() as u64);
    pcs.commit(e.proof.commitments[1], &vec![d.log_size(); m31::COLUMNS], &mut ch);
    ch.mix_u64(e.interaction_pow);
    let lookup = CommonLookupElements::draw(&mut ch);
    ensure!(
        m31::boundary(&d.requests, &lookup) + e.claimed_sum != QM31::from(0),
        "padding omission control"
    );
    Ok(serde_json::to_string_pretty(
        &json!({"rejected_mutations": names, "omitted_padding_rejected": true}),
    )?)
}


