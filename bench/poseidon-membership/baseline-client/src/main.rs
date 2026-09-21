//! Validity-only public-transcript benchmark. No privacy or private-membership claim.
mod statement;
use anyhow::{Result, ensure};
use cairo_air::{
    components as air, relations::CommonLookupElements, verifier::INTERACTION_POW_BITS,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use statement::{PublicData, Statement, mix_serialized};
use std::{
    path::PathBuf,
    sync::{Arc, atomic::AtomicU32},
    time::Instant,
};
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
use stwo_cairo_adapter::memory::{Memory, MemoryConfig};
use stwo_cairo_common::preprocessed_columns::preprocessed_trace::{
    PreProcessedTrace, PreProcessedTraceVariant,
};
use stwo_cairo_prover::witness::{components as witness, preprocessed_trace::gen_trace};
use stwo_constraint_framework::TraceLocationAllocator;

type Evaluation = stwo::prover::poly::circle::CircleEvaluation<SimdBackend, M31, BitReversedOrder>;
const SCOPE: &str = "validity-only public-transcript two-path membership; no private membership, payment relation, zero knowledge, or WASM qualification";
fn config() -> PcsConfig {
    PcsConfig {
        pow_bits: 27,
        fri_config: FriConfig::new(0, 3, 23, 4),
        lifting_log_size: Some(23),
    }
}

macro_rules! components {
    ($($name:ident),+ $(,)?)=>{
        #[derive(Serialize,Deserialize,Clone)]
        struct Claims {$( $name:air::$name::Claim, )+}
        struct Generators {$( $name:witness::$name::InteractionClaimGenerator, )+}
        impl Claims {
            fn sizes(&self)->[Vec<u32>;2] {
                let mut sizes=[Vec::new(),Vec::new()];
                $(let local=self.$name.log_sizes();sizes[0].extend(&local[0]);sizes[1].extend(&local[1]);)+ sizes
            }
            fn components(&self,sums:&[QM31],lookup:&CommonLookupElements,pre:&PreProcessedTrace)->Result<Vec<Box<dyn ComponentProver<SimdBackend>>>> {
                let mut allocator=TraceLocationAllocator::new_with_preprocessed_columns(&pre.ids());
                let mut sums=sums.iter(); let mut out:Vec<Box<dyn ComponentProver<SimdBackend>>>=Vec::new();
                $(out.push(Box::new(air::$name::Component::new(&mut allocator,air::$name::Eval{claim:self.$name,common_lookup_elements:lookup.clone()},*sums.next().ok_or_else(||anyhow::anyhow!("missing component sum"))?)));)+
                ensure!(sums.next().is_none(),"extra component sum");
                allocator.validate_preprocessed_columns(&pre.ids()); Ok(out)
            }
            fn metadata(&self)->Vec<serde_json::Value>{vec![$({let s=self.$name.log_sizes();json!({"name":stringify!($name),"log_rows":s[0][0],"rows":1u64<<s[0][0],"trace_columns":s[0].len(),"interaction_base_columns":s[1].len()})}),+]}
            fn validate(&self,data:&PublicData)->Result<()> {
                ensure!(self.poseidon_aggregator.log_size==data.aggregator_log_size(),"aggregator shape");
                ensure!(self.sizes().iter().flatten().all(|&l|(4..=20).contains(&l)),"component size bounds");
                let mut terms=0u64;
                $(for r in air::$name::RELATION_USES_PER_ROW {terms+=(1u64<<self.$name.log_sizes()[0][0])*r.uses as u64;})+
                ensure!(terms+((data.rows.len()*6+128) as u64) < (1u64<<31)-1,"relation count bound");
                Ok(())
            }
        }
        impl Generators {
            fn interactions(self,lookup:&CommonLookupElements)->(Vec<Evaluation>,Vec<QM31>){
                let mut evals=Vec::new();let mut sums=Vec::new();
                $(let (trace,claim)=self.$name.write_interaction_trace(lookup);evals.extend(trace);sums.push(claim.claimed_sum);)+
                (evals,sums)
            }
        }
    }
}
components!(
    poseidon_aggregator,
    poseidon_full_round_chain,
    poseidon_3_partial_rounds_chain,
    cube_252,
    range_check_252_width_27,
    poseidon_round_keys,
    range_check_3_3_3_3_3,
    range_check_4_4_4_4,
    range_check_4_4,
    range_check_9_9,
    range_check_20,
    range_check_18
);

/// Canonical column definitions are lightweight; unselected tables are never generated.
fn preprocessing(aggregator_log: u32) -> Arc<PreProcessedTrace> {
    let mut pre = PreProcessedTrace::canonical_without_pedersen();
    pre.columns.retain(|c| {
        let id = c.id().id;
        [
            format!("seq_{aggregator_log}"),
            "seq_6".into(),
            "seq_18".into(),
            "seq_20".into(),
        ]
        .contains(&id)
            || id.starts_with("poseidon_round_keys_")
            || [
                "range_check_3_3_3_3_3_column_",
                "range_check_4_4_4_4_column_",
                "range_check_4_4_column_",
                "range_check_9_9_column_",
            ]
            .iter()
            .any(|p| id.starts_with(p))
    });
    pre.column_indices = pre
        .columns
        .iter()
        .enumerate()
        .map(|(i, c)| (c.id(), i))
        .collect();
    // The enum is an upstream storage field, not canonical-root authority. This subset is custom.
    pre.variant = PreProcessedTraceVariant::CanonicalWithoutPedersen;
    Arc::new(pre)
}

fn witness(
    data: &PublicData,
    pre: Arc<PreProcessedTrace>,
) -> (Vec<Evaluation>, Claims, Generators) {
    let mem = Memory {
        config: MemoryConfig::default(),
        address_to_id: Vec::new(),
        f252_values: data
            .values
            .iter()
            .map(|v| {
                let bytes = v.to_bytes_le();
                std::array::from_fn(|i| {
                    u32::from_le_bytes(bytes[i * 4..i * 4 + 4].try_into().unwrap())
                })
            })
            .collect(),
        small_values: Vec::new(),
    };
    let memory = witness::memory_id_to_big::ClaimGenerator::new(Arc::new(mem));
    let aggregator = witness::poseidon_aggregator::ClaimGenerator::new();
    for (r, n) in &data.unique {
        aggregator.mults.insert(*r, AtomicU32::new(*n));
    }
    let mut full = witness::poseidon_full_round_chain::ClaimGenerator::new();
    let mut partial = witness::poseidon_3_partial_rounds_chain::ClaimGenerator::new();
    let mut cube = witness::cube_252::ClaimGenerator::new();
    let mut width = witness::range_check_252_width_27::ClaimGenerator::new();
    let keys = witness::poseidon_round_keys::ClaimGenerator::new(pre.clone());
    let rc3 = witness::range_check_3_3_3_3_3::ClaimGenerator::new(pre.clone());
    let rc4 = witness::range_check_4_4_4_4::ClaimGenerator::new(pre.clone());
    let rc44 = witness::range_check_4_4::ClaimGenerator::new(pre.clone());
    let rc99 = witness::range_check_9_9::ClaimGenerator::new(pre.clone());
    let rc20 = witness::range_check_20::ClaimGenerator::new(pre.clone());
    let rc18 = witness::range_check_18::ClaimGenerator::new(pre);
    let mut evals = Vec::new();
    let (trace, ac, ag) = aggregator.write_trace(
        &memory,
        &mut full,
        &mut width,
        &mut cube,
        &rc3,
        &rc4,
        &rc44,
        &mut partial,
    );
    evals.extend(trace.to_evals());
    drop(memory);
    let (trace, fc, fg) = full.write_trace(&mut cube, &keys, &rc3);
    evals.extend(trace.to_evals());
    let (trace, pc, pg) = partial.write_trace(&keys, &mut cube, &rc4, &rc44, &mut width);
    evals.extend(trace.to_evals());
    let (trace, cc, cg) = cube.write_trace(&rc99, &rc20);
    evals.extend(trace.to_evals());
    let (trace, wc, wg) = width.write_trace(&rc99, &rc18);
    evals.extend(trace.to_evals());
    let (trace, kc, kg) = keys.write_trace();
    evals.extend(trace.to_evals());
    let (trace, r3c, r3g) = rc3.write_trace();
    evals.extend(trace.to_evals());
    let (trace, r4c, r4g) = rc4.write_trace();
    evals.extend(trace.to_evals());
    let (trace, r44c, r44g) = rc44.write_trace();
    evals.extend(trace.to_evals());
    let (trace, r99c, r99g) = rc99.write_trace();
    evals.extend(trace.to_evals());
    let (trace, r20c, r20g) = rc20.write_trace();
    evals.extend(trace.to_evals());
    let (trace, r18c, r18g) = rc18.write_trace();
    evals.extend(trace.to_evals());
    (
        evals,
        Claims {
            poseidon_aggregator: ac,
            poseidon_full_round_chain: fc,
            poseidon_3_partial_rounds_chain: pc,
            cube_252: cc,
            range_check_252_width_27: wc,
            poseidon_round_keys: kc,
            range_check_3_3_3_3_3: r3c,
            range_check_4_4_4_4: r4c,
            range_check_4_4: r44c,
            range_check_9_9: r99c,
            range_check_20: r20c,
            range_check_18: r18c,
        },
        Generators {
            poseidon_aggregator: ag,
            poseidon_full_round_chain: fg,
            poseidon_3_partial_rounds_chain: pg,
            cube_252: cg,
            range_check_252_width_27: wg,
            poseidon_round_keys: kg,
            range_check_3_3_3_3_3: r3g,
            range_check_4_4_4_4: r4g,
            range_check_4_4: r44g,
            range_check_9_9: r99g,
            range_check_20: r20g,
            range_check_18: r18g,
        },
    )
}

#[derive(Serialize, Deserialize, Clone)]
struct Envelope {
    statement: Statement,
    claims: Claims,
    sums: Vec<QM31>,
    interaction_pow: u64,
    proof: StarkProof<Blake2sMerkleHasher>,
}
fn initial_channel(s: &Statement) -> Blake2sChannel {
    let mut ch = Blake2sChannel::default();
    mix_serialized(&mut ch, &"templar-public-poseidon-membership-v1");
    config().mix_into(&mut ch);
    mix_serialized(&mut ch, s);
    ch
}
fn verify(envelope: Envelope, trusted_root: Blake2sHash, pre: &PreProcessedTrace) -> Result<()> {
    let data = envelope.statement.validate()?;
    envelope.claims.validate(&data)?;
    ensure!(envelope.proof.config == config(), "untrusted PCS config");
    ensure!(
        envelope.proof.commitments.first() == Some(&trusted_root),
        "untrusted preprocessing root"
    );
    ensure!(envelope.proof.commitments.len() == 4, "commitment count");
    let mut ch = initial_channel(&envelope.statement);
    let mut pcs = CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(config());
    let sizes = envelope.claims.sizes();
    pcs.commit(trusted_root, &pre.log_sizes(), &mut ch);
    mix_serialized(&mut ch, &envelope.claims);
    pcs.commit(envelope.proof.commitments[1], &sizes[0], &mut ch);
    ensure!(
        ch.verify_pow_nonce(INTERACTION_POW_BITS, envelope.interaction_pow),
        "interaction PoW"
    );
    ch.mix_u64(envelope.interaction_pow);
    let lookup = CommonLookupElements::draw(&mut ch);
    ensure!(
        data.boundary(&lookup) + envelope.sums.iter().copied().sum::<QM31>() == QM31::from(0),
        "public lookup boundary mismatch"
    );
    ch.mix_felts(&envelope.sums);
    pcs.commit(envelope.proof.commitments[2], &sizes[1], &mut ch);
    let components = envelope.claims.components(&envelope.sums, &lookup, pre)?;
    stwo::core::verifier::verify(
        &components
            .iter()
            .map(|c| c.as_ref() as &dyn Component)
            .collect::<Vec<_>>(),
        &mut ch,
        &mut pcs,
        envelope.proof,
    )?;
    Ok(())
}

fn negative_tests(
    e: &Envelope,
    root: Blake2sHash,
    pre: &PreProcessedTrace,
) -> Result<serde_json::Value> {
    let mut results = Vec::new();
    macro_rules! reject {
        ($name:expr,$edit:expr) => {{
            let mut altered = e.clone();
            ($edit)(&mut altered);
            ensure!(
                verify(altered, root, pre).is_err(),
                "mutation accepted: {}",
                $name
            );
            results.push($name);
        }};
    }
    reject!("root", |x: &mut Envelope| x.statement.root = "0x0".into());
    reject!("leaf", |x: &mut Envelope| x.statement.paths[0].leaf =
        "0x0".into());
    reject!("index", |x: &mut Envelope| x.statement.paths[0].index ^= 1);
    reject!("sibling", |x: &mut Envelope| x.statement.paths[0]
        .siblings[0] =
        "0x1".into());
    reject!("padding", |x: &mut Envelope| x.statement.permutations[1]
        .input[0] = "0x0".into());
    reject!("call_order", |x: &mut Envelope| x
        .statement
        .permutations
        .swap(0, 1));
    reject!("aggregator_log", |x: &mut Envelope| x
        .claims
        .poseidon_aggregator
        .log_size += 1);
    reject!("claimed_sum", |x: &mut Envelope| x.sums[0] += QM31::from(1));
    reject!("interaction_pow", |x: &mut Envelope| x.interaction_pow ^= 1);
    reject!("PCS_config", |x: &mut Envelope| x
        .proof
        .0
        .config
        .pow_bits -= 1);
    reject!("STARK_sample", |x: &mut Envelope| x
        .proof
        .0
        .sampled_values[1][0][0] +=
        QM31::from(1));
    reject!("preprocessed_root", |x: &mut Envelope| x
        .proof
        .0
        .commitments[0] =
        Blake2sHash::default());
    // Changes a public permutation output which has no cheap path linkage. It passes the
    // structural checks and must be rejected by the transcript/lookup/proof protocol.
    let mut structurally_valid = e.clone();
    structurally_valid.statement.permutations[1].output[2] = "0x1234".into();
    structurally_valid.statement.validate()?;
    ensure!(
        verify(structurally_valid, root, pre).is_err(),
        "unlinked output mutation accepted"
    );
    results.push("structurally_valid_unlinked_permutation_output");
    let data = e.statement.validate()?;
    let mut ch = initial_channel(&e.statement);
    let mut pcs = CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(config());
    pcs.commit(root, &pre.log_sizes(), &mut ch);
    mix_serialized(&mut ch, &e.claims);
    pcs.commit(e.proof.commitments[1], &e.claims.sizes()[0], &mut ch);
    ch.mix_u64(e.interaction_pow);
    let lookup = CommonLookupElements::draw(&mut ch);
    let correct = data.boundary(&lookup);
    let sum = e.sums.iter().copied().sum::<QM31>();
    ensure!(correct + sum == QM31::from(0), "original boundary invalid");
    let mut bad = e.statement.validate()?;
    bad.rows.truncate(bad.unique.len());
    ensure!(
        bad.boundary(&lookup) + sum != QM31::from(0),
        "padding control not exercised"
    );
    let mut bad = e.statement.validate()?;
    bad.requests = bad.unique.iter().map(|(r, _)| *r).collect();
    ensure!(
        bad.boundary(&lookup) + sum != QM31::from(0),
        "duplicate control not exercised"
    );
    let mut bad = e.statement.validate()?;
    bad.values[0] += starknet_types_core::felt::Felt::ONE;
    ensure!(
        bad.boundary(&lookup) + sum != QM31::from(0),
        "memory dictionary control not exercised"
    );
    Ok(
        json!({"rejected_mutations":results,"omitted_padding_boundary_rejected":true,"discarded_duplicate_multiplicity_rejected":true,"wrong_memory_dictionary_rejected":true}),
    )
}

fn verify_saved(proof_path: &str, output: &str) -> Result<()> {
    let out = PathBuf::from(output);
    ensure!(!out.exists(), "output directory must be fresh");
    std::fs::create_dir_all(&out)?;
    let envelope: Envelope = bincode::deserialize(&std::fs::read(proof_path)?)?;
    let data = envelope.statement.validate()?;
    let pre = preprocessing(data.aggregator_log_size());
    let twiddles =
        SimdBackend::precompute_twiddles(CanonicCoset::new(24).circle_domain().half_coset);
    let mut ch = initial_channel(&envelope.statement);
    let mut pcs =
        CommitmentSchemeProver::<SimdBackend, Blake2sMerkleChannel>::new(config(), &twiddles);
    let mut builder = pcs.tree_builder();
    builder.extend_evals(gen_trace(pre.clone()));
    builder.commit(&mut ch);
    let root = pcs.trees[0].commitment.root();
    drop(pcs);
    drop(twiddles);
    verify(envelope.clone(), root, &pre)?;
    let report = negative_tests(&envelope, root, &pre)?;
    std::fs::write(
        out.join("negative-tests.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn main() -> Result<()> {
    let full = Instant::now();
    let args = std::env::args().collect::<Vec<_>>();
    ensure!(
        args.len() == 3 || args.len() == 4,
        "usage: templar-poseidon-membership FIXTURE NEW_OUTPUT_DIR [--negative-tests]"
    );
    if args[1] == "--verify-tests" {
        ensure!(args.len() == 4, "--verify-tests PROOF_BIN NEW_OUTPUT_DIR");
        return verify_saved(&args[2], &args[3]);
    }
    let out = PathBuf::from(&args[2]);
    ensure!(!out.exists(), "output directory must be fresh");
    std::fs::create_dir_all(&out)?;
    let mut phases = serde_json::Map::new();
    let start = Instant::now();
    let fixture: Statement = serde_json::from_slice(&std::fs::read(&args[1])?)?;
    let statement = fixture.regenerate()?;
    let data = statement.validate()?;
    phases.insert(
        "public_transcript_regeneration_seconds".into(),
        json!(start.elapsed().as_secs_f64()),
    );
    eprintln!("public transcript regenerated and fixture parity passed");
    let pre = preprocessing(data.aggregator_log_size());
    let start = Instant::now();
    let twiddles =
        SimdBackend::precompute_twiddles(CanonicCoset::new(24).circle_domain().half_coset);
    let mut ch = initial_channel(&statement);
    let mut pcs =
        CommitmentSchemeProver::<SimdBackend, Blake2sMerkleChannel>::new(config(), &twiddles);
    pcs.set_store_polynomials_coefficients();
    let mut builder = pcs.tree_builder();
    builder.extend_evals(gen_trace(pre.clone()));
    builder.commit(&mut ch);
    let trusted_root = pcs.trees[0].commitment.root();
    phases.insert(
        "preprocessing_twiddles_and_commit_seconds".into(),
        json!(start.elapsed().as_secs_f64()),
    );
    eprintln!("preprocessing commitment complete; generating witness");
    let start = Instant::now();
    let (evals, claims, generators) = witness(&data, pre.clone());
    claims.validate(&data)?;
    phases.insert(
        "base_witness_seconds".into(),
        json!(start.elapsed().as_secs_f64()),
    );
    std::fs::write(
        out.join("shape.json"),
        serde_json::to_vec_pretty(
            &json!({"pcs_config":config(),"interaction_pow_bits":INTERACTION_POW_BITS,"trusted_preprocessed_root":trusted_root,"components":claims.metadata(),"preprocessed":pre.columns.iter().map(|c|json!({"id":c.id().id,"log_size":c.log_size()})).collect::<Vec<_>>()}),
        )?,
    )?;
    let start = Instant::now();
    eprintln!("base witness complete; committing trace");
    mix_serialized(&mut ch, &claims);
    let mut builder = pcs.tree_builder();
    builder.extend_evals(evals);
    builder.commit(&mut ch);
    phases.insert(
        "base_commit_seconds".into(),
        json!(start.elapsed().as_secs_f64()),
    );
    let start = Instant::now();
    eprintln!("base commitment complete; interaction PoW and witness");
    let interaction_pow = SimdBackend::grind(&ch, INTERACTION_POW_BITS);
    ch.mix_u64(interaction_pow);
    let lookup = CommonLookupElements::draw(&mut ch);
    let (evals, sums) = generators.interactions(&lookup);
    ensure!(
        data.boundary(&lookup) + sums.iter().copied().sum::<QM31>() == QM31::from(0),
        "prover public lookup balance"
    );
    phases.insert(
        "interaction_pow_and_witness_seconds".into(),
        json!(start.elapsed().as_secs_f64()),
    );
    let start = Instant::now();
    eprintln!("interaction witness complete; commitment and STARK proving");
    ch.mix_felts(&sums);
    let mut builder = pcs.tree_builder();
    builder.extend_evals(evals);
    builder.commit(&mut ch);
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
    eprintln!("proof generated; verifying serialized public envelope");
    let envelope = Envelope {
        statement,
        claims,
        sums,
        interaction_pow,
        proof,
    };
    let binary = bincode::serialize(&envelope)?;
    let proof_json = serde_json::to_vec(&envelope)?;
    // Verification deserializes only the public envelope. The root is locally generated from
    // pinned column definitions, and is not authority supplied by the proof envelope.
    let start = Instant::now();
    verify(bincode::deserialize(&binary)?, trusted_root, &pre)?;
    phases.insert(
        "native_verify_seconds".into(),
        json!(start.elapsed().as_secs_f64()),
    );
    std::fs::write(out.join("proof.bin"), &binary)?;
    std::fs::write(out.join("proof.json"), &proof_json)?;
    let summary = json!({"scope":SCOPE,"storage":"upstream cached coefficients and full evaluations; baseline","channel":"Blake2s","pcs_config":config(),"config_security_metric_bits":config().security_bits(),"interaction_pow_bits":INTERACTION_POW_BITS,"trusted_preprocessed_root":trusted_root,"components":envelope.claims.metadata(),"requested_permutations":128,"unique_permutations":data.unique.len(),"aggregator_rows":data.rows.len(),"public_memory_boundary_terms":data.rows.len()*6,"reference_parity":true,"native_proof_verified":true,"binary_envelope_bytes":binary.len(),"json_envelope_bytes":proof_json.len(),"public_statement_json_bytes":serde_json::to_vec(&envelope.statement)?.len(),"binary_stark_proof_bytes":bincode::serialize(&envelope.proof)?.len(),"json_stark_proof_bytes":serde_json::to_vec(&envelope.proof)?.len(),"phases":phases,"complete_seconds":full.elapsed().as_secs_f64()});
    std::fs::write(
        out.join("summary.json"),
        serde_json::to_vec_pretty(&summary)?,
    )?;
    println!("{}", serde_json::to_string_pretty(&summary)?);
    if args.get(3).map(String::as_str) == Some("--negative-tests") {
        std::fs::write(
            out.join("negative-tests.json"),
            serde_json::to_vec_pretty(&negative_tests(&envelope, trusted_root, &pre)?)?,
        )?;
    }
    Ok(())
}
