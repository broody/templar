//! Public synthetic append validity experiment. No private payment or privacy claim.
mod constants;
mod m31;
pub mod statement;
mod wire;
use anyhow::{Result, ensure};
use bincode::Options;
use cairo_air::relations::CommonLookupElements;
use num_traits::One;
use serde::{Deserialize, Serialize};
use serde_json::json;
use statement::{PublicData, Statement};
use std::time::Instant;
use stwo::core::{
    air::{Component, accumulation::PointEvaluationAccumulator},
    channel::{Blake2sChannel, Channel},
    fields::{m31::M31, qm31::QM31},
    fri::FriConfig,
    pcs::{CommitmentSchemeVerifier, PcsConfig, TreeVec},
    poly::circle::CanonicCoset,
    proof::StarkProof,
    proof_of_work::GrindOps,
    vcs::blake2_hash::Blake2sHash,
    vcs_lifted::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher},
};
use stwo::prover::{
    CommitmentSchemeProver,
    backend::simd::SimdBackend,
    poly::{BitReversedOrder, circle::PolyOps},
    prove,
};
use stwo_constraint_framework::{FrameworkEval, PointEvaluator, TraceLocationAllocator};
type Evaluation = stwo::prover::poly::circle::CircleEvaluation<SimdBackend, M31, BitReversedOrder>;
const INTERACTION_POW_BITS: u32 = 24;
#[derive(Clone, Serialize, Deserialize)]
struct Envelope {
    statement: Statement,
    interaction_pow: u64,
    claimed_sum: QM31,
    proof: StarkProof<Blake2sMerkleHasher>,
}
fn config(d: &PublicData) -> PcsConfig {
    PcsConfig {
        pow_bits: 27,
        fri_config: FriConfig::new(0, 3, 23, 4),
        lifting_log_size: Some(d.log_size() + 3),
    }
}
fn initial(s: &Statement, d: &PublicData) -> Blake2sChannel {
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
        "append public boundary"
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
fn limbs(x: QM31) -> [u32; 4] {
    x.to_m31_array().map(|v| v.0)
}
fn checkpoint(ch: &Blake2sChannel) -> Vec<u32> {
    ch.clone().draw_u32s()
}
pub fn transcript_vectors(statement: &Statement) -> Result<serde_json::Value> {
    let d = statement.validate()?;
    let mut ch = Blake2sChannel::default();
    statement::mix_words(&mut ch, &d.words);
    let mut checkpoints = vec![checkpoint(&ch)];
    config(&d).mix_into(&mut ch);
    checkpoints.push(checkpoint(&ch));
    let mut pcs = CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(config(&d));
    commit_preprocessing(&mut pcs, &mut ch);
    checkpoints.push(checkpoint(&ch));
    ch.mix_u64(d.log_size() as u64);
    checkpoints.push(checkpoint(&ch));
    let fields = wire::serialize_statement(statement)?;
    let probes = (0..4u32)
        .map(|stage| {
            let mut args = vec![
                starknet_ff::FieldElement::from(stage),
                starknet_ff::FieldElement::from(fields.len()),
            ];
            args.extend(&fields);
            args.iter().map(|v| format!("{v:#x}")).collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    Ok(
        json!({"prefix_checkpoints":checkpoints,"prefix_probe_arguments":probes,"statement_cairo_felts":fields.iter().map(|v|format!("{v:#x}")).collect::<Vec<_>>(),"public_words":d.words}),
    )
}
fn numerator(
    log: u32,
    lookup: &CommonLookupElements,
    sum: QM31,
    random: QM31,
    base: &[Vec<QM31>],
    interaction: &[Vec<QM31>],
) -> QM31 {
    let mut accumulator = PointEvaluationAccumulator::new(random);
    let mask = TreeVec::new(vec![
        vec![],
        base.iter().collect(),
        interaction.iter().collect(),
    ]);
    m31::Eval {
        log_size: log,
        lookup: lookup.clone(),
    }
    .evaluate(PointEvaluator::new(
        mask,
        &mut accumulator,
        QM31::one(),
        log,
        sum,
    ));
    accumulator.finalize()
}
fn ood_wire(
    log: u32,
    za: &[QM31],
    sum: QM31,
    random: QM31,
    base: &[Vec<QM31>],
    interaction: &[Vec<QM31>],
) -> Vec<String> {
    use stwo_cairo_serialize::CairoSerialize;
    let mut data = vec![];
    CairoSerialize::serialize(&log, &mut data);
    CairoSerialize::serialize(&sum, &mut data);
    CairoSerialize::serialize(&za[0], &mut data);
    CairoSerialize::serialize(&za[1], &mut data);
    CairoSerialize::serialize(&random, &mut data);
    CairoSerialize::serialize(&base.to_vec(), &mut data);
    CairoSerialize::serialize(&interaction.to_vec(), &mut data);
    let mut args = vec![starknet_ff::FieldElement::from(data.len())];
    args.extend(data);
    args.iter().map(|v| format!("{v:#x}")).collect()
}
fn ood_fixture(
    log: u32,
    lookup: &CommonLookupElements,
    za: &[QM31],
    sum: QM31,
    random: QM31,
    base: &[Vec<QM31>],
    interaction: &[Vec<QM31>],
) -> serde_json::Value {
    let expected = numerator(log, lookup, sum, random, base, interaction);
    let mut mutated = base.to_vec();
    mutated[24][0] += QM31::one();
    let changed = numerator(log, lookup, sum, random, &mutated, interaction);
    assert_ne!(expected, changed);
    let mut changed_interaction = interaction.to_vec();
    changed_interaction[0][0] += QM31::one();
    let changed_interaction_result =
        numerator(log, lookup, sum, random, base, &changed_interaction);
    assert_ne!(expected, changed_interaction_result);
    json!({"log_size":log,"z":limbs(za[0]),"alpha":limbs(za[1]),"claimed_sum":limbs(sum),"composition_random_coeff":limbs(random),"base":base.iter().map(|c|c.iter().copied().map(limbs).collect::<Vec<_>>()).collect::<Vec<_>>(),"interaction":interaction.iter().map(|c|c.iter().copied().map(limbs).collect::<Vec<_>>()).collect::<Vec<_>>(),"expected_numerator":limbs(expected),"mutated_base_column":24,"mutated_base_sample":limbs(mutated[24][0]),"expected_mutated_numerator":limbs(changed),"mutated_interaction_column":0,"mutated_interaction_offset":0,"expected_interaction_mutated_numerator":limbs(changed_interaction_result),"cairo_arguments":ood_wire(log,za,sum,random,base,interaction),"cairo_base_mutation_arguments":ood_wire(log,za,sum,random,&mutated,interaction),"cairo_interaction_mutation_arguments":ood_wire(log,za,sum,random,base,&changed_interaction)})
}
pub struct Artifacts {
    pub proof: Vec<u8>,
    pub proof_json: Vec<u8>,
    pub cairo_arguments: String,
    pub cairo_proof: String,
    pub summary: String,
    pub statement: String,
    pub public_output: String,
    pub transcript: String,
    pub ood: String,
}
pub fn prove_fixture(fixture: &str) -> Result<Artifacts> {
    let full = Instant::now();
    let statement: Statement = serde_json::from_str(fixture)?;
    let d = statement.validate()?;
    let mut phases = serde_json::Map::new();
    let start = Instant::now();
    let twiddles = SimdBackend::precompute_twiddles(
        CanonicCoset::new(d.log_size() + 3)
            .circle_domain()
            .half_coset,
    );
    let mut ch = initial(&statement, &d);
    let mut checkpoints = transcript_vectors(&statement)?;
    checkpoints["after_public_words_and_config"] = json!(checkpoint(&ch));
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
    checkpoints["after_base_commit"] = json!(checkpoint(&ch));
    phases.insert(
        "base_commit_seconds".into(),
        json!(start.elapsed().as_secs_f64()),
    );
    let start = Instant::now();
    let interaction_pow = SimdBackend::grind(&ch, INTERACTION_POW_BITS);
    ch.mix_u64(interaction_pow);
    checkpoints["after_interaction_pow"] = json!(checkpoint(&ch));
    let za = ch.clone().draw_secure_felts(2);
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
    let random = ch.clone().draw_secure_felt();
    checkpoints["before_composition"] = json!(checkpoint(&ch));
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
    let ood = ood_fixture(
        d.log_size(),
        &lookup,
        &za,
        sum,
        random,
        &proof.sampled_values[1],
        &proof.sampled_values[2],
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
    let cairo = wire::serialize(&envelope)?;
    let mut arguments = vec![starknet_ff::FieldElement::from(cairo.len())];
    arguments.extend(&cairo);
    let encode = |values: &[starknet_ff::FieldElement]| {
        serde_json::to_string(&values.iter().map(|x| format!("{x:#x}")).collect::<Vec<_>>())
    };
    let output = envelope.statement.public_output()?;
    let public = json!({"transition_preimage":envelope.statement.transition_preimage()?.into_iter().map(statement::hex).collect::<Vec<_>>(),"transition_digest":statement::hex(output[6]),"public8":output.map(statement::hex),"old_root_packed":statement::pack(envelope.statement.old_root)?.map(statement::hex),"new_root_packed":statement::pack(envelope.statement.new_root)?.map(statement::hex)});
    let summary = json!({"scope":"public synthetic append validity; no private payment claim","n":envelope.statement.commitments.len(),"requests":d.requests.len(),"rows":d.rows.len(),"trace_columns":m31::COLUMNS,"pcs_config":config(&d),"interaction_pow_bits":INTERACTION_POW_BITS,"interaction_pow_nonce":interaction_pow.to_string(),"fri_pow_nonce":envelope.proof.proof_of_work.to_string(),"empty_preprocessed_root":empty_root(),"binary_bytes":bytes.len(),"cairo_proof_felts":cairo.len(),"native_verified":true,"phases":phases,"complete_seconds":full.elapsed().as_secs_f64()});
    Ok(Artifacts {
        proof: bytes,
        proof_json: serde_json::to_vec(&envelope)?,
        cairo_arguments: encode(&arguments)?,
        cairo_proof: encode(&cairo)?,
        summary: serde_json::to_string_pretty(&summary)?,
        statement: serde_json::to_string_pretty(&envelope.statement)?,
        public_output: serde_json::to_string_pretty(&public)?,
        transcript: serde_json::to_string_pretty(&checkpoints)?,
        ood: serde_json::to_string_pretty(&ood)?,
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
    reject!("chain", |e: &mut Envelope| e.statement.chain_id =
        statement::hex(
            statement::felt(&e.statement.chain_id).unwrap() + starknet_types_core::felt::Felt::ONE
        ));
    reject!(
        "pool",
        |e: &mut Envelope| e.statement.pool = statement::hex(
            statement::felt(&e.statement.pool).unwrap() + starknet_types_core::felt::Felt::ONE
        )
    );
    reject!("old_count", |e: &mut Envelope| e.statement.old_count += 1);
    reject!("new_count", |e: &mut Envelope| e.statement.new_count += 1);
    reject!("old_root", |e: &mut Envelope| e.statement.old_root[0] =
        (e.statement.old_root[0] + 1) % m31::P);
    reject!("new_root", |e: &mut Envelope| e.statement.new_root[0] =
        (e.statement.new_root[0] + 1) % m31::P);
    reject!("commitment_substitution", |e: &mut Envelope| e
        .statement
        .commitments[0] =
        statement::hex(
            statement::felt(&e.statement.commitments[0]).unwrap()
                + starknet_types_core::felt::Felt::ONE
        ));
    if e.statement.commitments.len() == 2 {
        reject!("ordered_commitment_swap", |e: &mut Envelope| e
            .statement
            .commitments
            .swap(0, 1));
    }
    reject!("sibling", |e: &mut Envelope| e.statement.steps[0]
        .siblings[0][0] =
        (e.statement.steps[0].siblings[0][0] + 1) % m31::P);
    reject!("interaction_pow", |e: &mut Envelope| e.interaction_pow ^= 1);
    reject!("base_commitment", |e: &mut Envelope| e
        .proof
        .0
        .commitments[1]
        .0[0] ^= 1);
    reject!("leaf_domain", |e: &mut Envelope| e.statement.steps[0]
        .requests[0]
        .input[2] = 3);
    reject!("leaf_padding", |e: &mut Envelope| e.statement.steps[0]
        .requests[0]
        .input[13] = 0);
    reject!("noncanonical_word", |e: &mut Envelope| e.statement.steps
        [0]
    .siblings[0][0] =
        m31::P);
    reject!("untrusted_config", |e: &mut Envelope| e
        .proof
        .0
        .config
        .pow_bits -= 1);
    reject!("sampled_value", |e: &mut Envelope| e
        .proof
        .0
        .sampled_values[1][0][0] +=
        QM31::one());
    reject!("sum", |e: &mut Envelope| e.claimed_sum += QM31::one());
    reject!("preprocessing_root", |e: &mut Envelope| e
        .proof
        .0
        .commitments[0] =
        Blake2sHash::default());
    reject!("extra_empty_pp_sample", |e: &mut Envelope| e
        .proof
        .0
        .sampled_values[0]
        .push(vec![QM31::one()]));
    reject!("extra_empty_pp_query", |e: &mut Envelope| e
        .proof
        .0
        .queried_values[0]
        .push(vec![M31::from(1)]));
    reject!("extra_empty_pp_witness", |e: &mut Envelope| e
        .proof
        .0
        .decommitments[0]
        .hash_witness
        .push(Blake2sHash::default()));
    let mut bad = e.clone();
    let v = &mut bad
        .statement
        .steps
        .last_mut()
        .unwrap()
        .requests
        .last_mut()
        .unwrap()
        .output[23];
    *v = (*v + 1) % m31::P;
    bad.statement.validate()?;
    ensure!(verify(bad).is_err(), "unused output accepted");
    names.push("structurally_valid_unused_output");
    let mut trailing = bytes.to_vec();
    trailing.push(0);
    ensure!(decode(&trailing).is_err(), "trailing envelope accepted");
    names.push("trailing_envelope");
    ensure!(
        decode(&bytes[..bytes.len() - 1]).is_err(),
        "truncated envelope accepted"
    );
    names.push("truncated_envelope");
    let d = e.statement.validate()?;
    let mut ch = initial(&e.statement, &d);
    let mut pcs = CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(config(&d));
    commit_preprocessing(&mut pcs, &mut ch);
    ch.mix_u64(d.log_size() as u64);
    pcs.commit(
        e.proof.commitments[1],
        &vec![d.log_size(); m31::COLUMNS],
        &mut ch,
    );
    ch.mix_u64(e.interaction_pow);
    let lookup = CommonLookupElements::draw(&mut ch);
    ensure!(
        m31::boundary(&d.requests, &lookup) + e.claimed_sum != QM31::from(0),
        "padding omission control"
    );
    let mut dedup = d.rows;
    dedup.sort_by_key(|r| (r.input, r.output));
    dedup.dedup();
    ensure!(
        m31::boundary(&dedup, &lookup) + e.claimed_sum != QM31::from(0),
        "multiplicity control"
    );
    Ok(serde_json::to_string_pretty(
        &json!({"rejected_mutations":names,"omitted_padding_rejected":true,"discarded_multiplicity_rejected":true}),
    )?)
}
pub fn arbitrary_ood_fixtures() -> serde_json::Value {
    let mut ch = Blake2sChannel::default();
    ch.mix_u64(0x415050454e44);
    let za = ch.clone().draw_secure_felts(2);
    let lookup = CommonLookupElements::draw(&mut ch);
    let word = |i: usize| {
        QM31::from_m31_array(std::array::from_fn(|j| {
            M31::from(((i * 19 + j * 37 + 1) % 104729) as u32)
        }))
    };
    let base = (0..m31::COLUMNS).map(|i| vec![word(i)]).collect::<Vec<_>>();
    let interaction = (0..4)
        .map(|i| vec![word(2000 + i * 2), word(2001 + i * 2)])
        .collect::<Vec<_>>();
    json!([
        ood_fixture(8, &lookup, &za, word(3000), word(3001), &base, &interaction),
        ood_fixture(9, &lookup, &za, word(3002), word(3003), &base, &interaction)
    ])
}
#[cfg(test)]
mod tests {
    #[test]
    fn arbitrary_ood_shapes_and_corruption() {
        let f = super::arbitrary_ood_fixtures();
        for v in f.as_array().unwrap() {
            assert_eq!(v["base"].as_array().unwrap().len(), 1172);
            assert_eq!(v["interaction"].as_array().unwrap().len(), 4);
            assert_ne!(v["expected_numerator"], v["expected_mutated_numerator"]);
        }
    }
}
