//! Public batch circuit: binds canonical input words and all full Blake outputs.
//! No membership/AIR/FRI verification yet and no private client inputs accepted.
use std::{fs, path::Path, time::Instant};
use blake2::{Blake2s256, Digest};
use circuit_common::finalize::finalize_context;
mod full_blake;
#[path = "../../../direct-air/cairo/serialize_full_config.rs"]
mod bridge_serialize;
use circuit_common::preprocessed::PreprocessedCircuit;
use circuit_prover::circuit_air::circuit_components::CircuitComponents;
use circuit_prover::prover::{
    BaseColumnPool, SimdBackend, prove_circuit_assignment_with_channel,
};
use circuit_verifier::circuit_claim::{
    CircuitClaim, CircuitInteractionClaim, CircuitInteractionElements, column_log_sizes_per_tree,
    lookup_sum,
};
use circuit_verifier::circuit_components::N_COMPONENTS;
use circuit_verifier::statement::{INTERACTION_POW_BITS, all_circuit_components};
use circuits::context::{Context, FinalizedContext};
use circuits::ivalue::{IValue, NoValue};
use circuits::ops::guess;
use num_traits::{One, Zero};
use serde::{Deserialize, Serialize};
use serde_json::json;
use stwo::core::air::Component;
use stwo::core::channel::{Blake2sChannel, Channel};
use stwo::core::fields::qm31::QM31;
use stwo::core::fri::FriConfig;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::proof::StarkProof;
use stwo::core::vcs::blake2_hash::Blake2sHash;
use stwo::core::vcs_lifted::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher};
use stwo::prover::CommitmentTreeProver;
use stwo::prover::poly::circle::PolyOps;

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

#[derive(Clone, Serialize, Deserialize)]
struct PublicProof {
    pcs_config: PcsConfig,
    output_values: Vec<QM31>,
    interaction_pow_nonce: u64,
    interaction_claim: [QM31; N_COMPONENTS],
    stark_proof: StarkProof<Blake2sMerkleHasher>,
    channel_salt: u32,
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
    expected: &[QM31],
) {
    assert_eq!(public.stark_proof.commitments[0], trusted_root);
    let mut expected_config = config();
    expected_config.lifting_log_size =
        Some(preprocessed.trace_log_size + config().fri_config.log_blowup_factor);
    assert_eq!(public.pcs_config, expected_config);
    assert_eq!(public.stark_proof.config, expected_config);
    assert_eq!(public.output_values, expected);
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

#[derive(Clone, Deserialize)]
struct Job { message: Vec<u8>, digest: Vec<u8> }
fn pack(bytes: &[u8]) -> Vec<u32> {
    bytes.chunks(4).map(|c| { let mut w=[0;4]; w[..c.len()].copy_from_slice(c); u32::from_le_bytes(w) }).collect()
}
fn hash_words(words: &[u32]) -> Vec<u32> {
    pack(&Blake2s256::digest(words.iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<_>>()))
}
fn finish<Value: IValue>(mut c: Context<Value>) -> FinalizedContext<Value> {
    // The upstream constant finalizer eagerly constructs this broadcast basis.
    // Register a use so its unused-wire diagnostic remains enabled for all wires.
    let basis=c.constant(circuits::ivalue::qm31_from_u32s(1,1,1,1));
    circuits::ops::eq(&mut c,basis,basis);
    c.finalize(true)
}
fn build<Value: IValue>(jobs: &[Job]) -> FinalizedContext<Value> {
    let mut c = Context::<Value>::new(16);
    let mut input_binding = Vec::new();
    let mut outputs = Vec::new();
    for job in jobs {
        let words: Vec<_> = pack(&job.message).into_iter().map(|x| guess(&mut c, Value::pack_u32(x))).collect();
        input_binding.push(c.constant(QM31::pack_u32(job.message.len() as u32)));
        input_binding.extend_from_slice(&words);
        outputs.extend(full_blake::full_blake(&mut c, &words, job.message.len()));
    }
    let mut result = full_blake::full_blake(&mut c, &input_binding, input_binding.len()*4).to_vec();
    result.extend(full_blake::full_blake(&mut c, &outputs, outputs.len()*4));
    c.set_outputs(&result);
    let mut c = finish(c);
    finalize_context(&mut c);
    c
}
fn expected(jobs: &[Job]) -> Vec<QM31> {
    let mut inputs=Vec::new(); let mut outputs=Vec::new();
    for job in jobs {
        assert_eq!(Blake2s256::digest(&job.message).as_slice(), job.digest);
        inputs.push(job.message.len() as u32); inputs.extend(pack(&job.message));
        outputs.extend(pack(&job.digest));
    }
    hash_words(&inputs).into_iter().chain(hash_words(&outputs)).map(QM31::pack_u32).collect()
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    let jobs: Vec<Job> = serde_json::from_slice(&fs::read(&args[1]).unwrap()).unwrap();
    assert!(!jobs.is_empty() && jobs.len()<=8192);
    let out=Path::new(&args[2]); fs::create_dir_all(out).unwrap();
    let started=Instant::now();
    let topology=build::<NoValue>(&jobs);
    let context=build::<QM31>(&jobs);
    assert_eq!(topology.circuit(),context.circuit());
    context.validate_circuit();
    let preprocessed=PreprocessedCircuit::from_finalized_circuit(topology.circuit());
    let sizes=component_log_sizes(&preprocessed);
    let trusted_root={
        let twiddles=SimdBackend::precompute_twiddles(CanonicCoset::new(preprocessed.trace_log_size+2).half_coset());
        let polys=SimdBackend::interpolate_columns(preprocessed.preprocessed_trace.get_trace::<SimdBackend>(),&twiddles);
        let tree=CommitmentTreeProver::<SimdBackend,Blake2sMerkleChannel>::new(polys,2,&twiddles,false,Some(preprocessed.trace_log_size+2),&BaseColumnPool::new());
        tree.commitment.root()
    };
    let wanted=expected(&jobs);
    let prove_start=Instant::now();
    let p=prove_circuit_assignment_with_channel::<Blake2sMerkleChannel>(context.values(),&preprocessed,&BaseColumnPool::<SimdBackend>::new(),config()).unwrap();
    let proving_seconds=prove_start.elapsed().as_secs_f64();
    let public=PublicProof{pcs_config:p.pcs_config,output_values:p.claim.output_values.clone(),interaction_pow_nonce:p.interaction_pow_nonce,interaction_claim:p.interaction_claim.claimed_sums,stark_proof:p.stark_proof.proof.clone(),channel_salt:p.channel_salt};
    let verify_start=Instant::now(); native_verify(&public,&preprocessed,trusted_root,&wanted);
    let verify_seconds=verify_start.elapsed().as_secs_f64();
    let mut negatives=Vec::new();
    for case in ["output", "trace", "topology", "config"] {
        let mut bad=public.clone();
        match case {
            "output"=>bad.output_values[0]+=QM31::one(),
            "trace"=>bad.stark_proof.0.commitments[1]=Default::default(),
            "topology"=>bad.stark_proof.0.commitments[0]=Default::default(),
            "config"=>bad.pcs_config.pow_bits=0,
            _=>unreachable!()
        }
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(||native_verify(&bad,&preprocessed,trusted_root,&wanted))).is_err());
        negatives.push(case);
    }
    let columns:Vec<_>=preprocessed.preprocessed_trace.log_sizes().into_iter().map(|(id,log_size)|json!({"id":id.id,"log_size":log_size})).collect();
    let root_words=pack(&trusted_root.0);
    let manifest=json!({"purpose":"public-blake-server-circuit","channel":"Blake2sMerkleChannel","merkle_hasher":"Blake2sMerkleHasher","pcs_config":p.pcs_config,"preprocessed_columns":columns,"component_log_sizes":sizes,"output_addresses":(3..19).collect::<Vec<_>>(),"u_address":2,"preprocessed_root_u32_le":root_words});
    fs::write(out.join("trusted-config.json"),serde_json::to_vec_pretty(&manifest).unwrap()).unwrap();
    let mut verification_preimage=trusted_root.0.to_vec();
    for value in &wanted { for word in value.to_m31_array() { verification_preimage.extend_from_slice(&word.0.to_le_bytes()); } }
    let output_hash=pack(&Blake2s256::digest(verification_preimage));
    fs::write(out.join("public-proof.json"),serde_json::to_vec(&public).unwrap()).unwrap();
    let felts=bridge_serialize::serialize_proof(p,&sizes);
    let mut arguments=vec![format!("0x{:x}",felts.len())]; arguments.extend(felts.iter().map(|f|format!("{f:#x}")));
    fs::write(out.join("cairo-arguments.json"),serde_json::to_vec(&arguments).unwrap()).unwrap();
    let rows=json!({"scope":"public hash batch with input/output bindings; no membership verification","jobs":jobs.len(),"input_bytes":jobs.iter().map(|j|j.message.len()).sum::<usize>(),"trace_log_size":preprocessed.trace_log_size,"component_log_sizes":sizes,"blake_g_rows_padded":context.circuit().blake_g_gate.len(),"triple_xor_rows_padded":context.circuit().triple_xor.len(),"qm31_ops_rows_padded":context.circuit().n_qm31_ops_rows(),"proving_seconds":proving_seconds,"native_verify_seconds":verify_seconds,"total_seconds":started.elapsed().as_secs_f64(),"proof_felts":felts.len(),"native_negatives":negatives,"verification_output_u32_le":output_hash,"public_outputs":wanted.iter().map(|v|v.to_m31_array().map(|x|x.0)).collect::<Vec<_>>()});
    fs::write(out.join("report.json"),serde_json::to_vec_pretty(&rows).unwrap()).unwrap();
    println!("{}",rows);
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn full_digest_boundaries_and_topology() {
        for n in [0,1,2,3,4,63,64,65,127,128,129,161,5053] {
            let msg:Vec<_>=(0..n).map(|i|((i*73+11)%256)as u8).collect();
            let jobs=vec![Job{digest:Blake2s256::digest(&msg).to_vec(),message:msg}];
            let c=build::<QM31>(&jobs); c.validate_circuit();
            assert_eq!(&c.values()[3..19],expected(&jobs));
            assert_eq!(build::<NoValue>(&jobs).circuit(),c.circuit());
            let mut bad=c.values().clone(); bad[3]+=QM31::one();
            assert!(c.circuit().check(&bad).is_err());
            let gate=&c.circuit().blake_g_gate[0];
            let mut bad=c.values().clone(); bad[gate.out_a]+=QM31::one();
            assert!(c.circuit().check(&bad).is_err());
        }
    }
    #[test]
    fn noncanonical_padding_is_constrained() {
        let mut c=Context::<QM31>::new(8);
        let word=guess(&mut c,QM31::pack_u32(256));
        let result=full_blake::full_blake(&mut c,&[word],1);
        c.set_outputs(&result);
        let c=finish(c);
        assert!(!c.is_circuit_valid());
    }
    #[test]
    fn canonical_packed_words_and_value_independent_topology() {
        let msg=vec![255;64];
        let jobs=vec![Job{digest:Blake2s256::digest(&msg).to_vec(),message:msg}];
        let c=build::<QM31>(&jobs);
        let mut other=jobs.clone(); other[0].message=vec![0;64];
        assert_eq!(build::<QM31>(&other).circuit(),c.circuit());
        // First guessed message word is immediately after the 16 reserved outputs.
        for bad_word in [[65536,0,0,0],[0,65536,0,0],[0,0,1,0],[0,0,0,1]] {
            let mut bad=c.values().clone();
            bad[19]=QM31::from_m31_array(bad_word.map(|x| x.into()));
            assert!(c.circuit().check(&bad).is_err());
        }
    }

}
