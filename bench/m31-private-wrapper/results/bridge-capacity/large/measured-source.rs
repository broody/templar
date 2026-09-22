//! Isolated capacity probe. Geometry is selected by the operator, never by a proof.
//! All prior verifier/prover binaries and security knobs remain unchanged.
use std::{fs, path::Path, sync::Arc, time::Instant, error::Error, rc::Rc};
use serde_json::json;
use cairo_vm::vm::runners::cairo_pie::CairoPie;
use cairo_air::{flat_claims::FlatClaim,verifier::INTERACTION_POW_BITS};
use cairo_program_runner_lib::{ProgramInput, Task, TaskSpec, cairo_run_program};
use cairo_program_runner_lib::types::{HashFunc,PrivacySimpleBootloaderInput,SimpleBootloaderInput};
use circuit_cairo_verifier::{all_components::all_components,verify::{build_fixed_cairo_circuit,prepare_cairo_proof_for_circuit_verifier,CairoVerifierConfig}};
use circuit_common::{preprocessed::PreprocessedCircuit,finalize::{add_zk_blinding,finalize_context}};
use circuit_prover::prover::{prove_circuit_assignment_with_channel,prepare_circuit_proof_for_circuit_verifier};
use circuit_verifier::{verify::{CircuitConfig,CircuitPublicData,verify_circuit},statement::all_circuit_components};
use circuit_serialize::{serialize::CircuitSerialize,deserialize::deserialize_proof_with_config};
use circuits::ivalue::{NoValue,IValue};
use circuits_stark_verifier::{proof::ProofConfig,proof_from_stark_proof::pack_into_qm31s};
use privacy_circuit_verify::{consts::*,get_cairo_verifier_config,get_cairo_preprocessed_circuit,get_privacy_bootloader_program,compute_privacy_bootloader_output,Version};
use privacy_prove::consts::{CAIRO_RUN_CONFIG,CAIRO_PROVER_PARAMS};
use stwo::{core::{fields::qm31::QM31,poly::circle::CanonicCoset,vcs_lifted::blake2_merkle::Blake2sM31MerkleChannel},prover::{backend::simd::SimdBackend,mempool::BaseColumnPool,poly::circle::PolyOps,CommitmentTreeProver}};
use stwo_cairo_adapter::{ProverInput,adapter::adapt};
use stwo_cairo_prover::{prover::prove_cairo,witness::{cairo::create_cairo_claim_generator}};
use starknet_types_core::felt::Felt;
use tempfile::NamedTempFile;
fn boot(pie:CairoPie)->Result<(ProverInput,Vec<Felt>),Box<dyn Error>> {
    let temp=NamedTempFile::new()?;
    let input=PrivacySimpleBootloaderInput {simple_bootloader_input:SimpleBootloaderInput{fact_topologies_path:None,single_page:true,tasks:vec![TaskSpec{task:Rc::new(Task::Pie(pie)),program_hash_function:HashFunc::Blake}]},output_preimage_dump_path:temp.path().to_path_buf()};
    let runner=cairo_run_program(&get_privacy_bootloader_program()?,Some(ProgramInput::Value(Box::new(input))),CAIRO_RUN_CONFIG,None)?;
    let output=serde_json::from_slice(&fs::read(temp.path())?)?;
    Ok((adapt(&runner)?,output))
}
fn configuration(log:u32)->Result<(CairoVerifierConfig,PreprocessedCircuit,CircuitConfig,ProofConfig),Box<dyn Error>> {
    assert!((20..=23).contains(&log));
    let mut pcs=CAIRO_PCS_CONFIG;pcs.lifting_log_size=Some(log+CAIRO_LOG_BLOWUP_FACTOR);
    let components=all_components::<NoValue>().into_iter().filter(|(name,_)|PRIVACY_TRANSACTION_COMPONENTS.contains(name)).collect();
    let mut cfg=get_cairo_verifier_config()?;
    cfg.proof_config=ProofConfig::new(&components,cfg.preprocessed_trace_variant.n_columns(),&pcs,INTERACTION_POW_BITS);
    cfg.preprocessed_root={
        let tw=SimdBackend::precompute_twiddles(CanonicCoset::new(log+3).circle_domain().half_coset);
        let trace=Arc::new(cfg.preprocessed_trace_variant.to_preprocessed_trace());
        let polys=SimdBackend::interpolate_columns(stwo_cairo_prover::witness::preprocessed_trace::gen_trace(trace),&tw);
        let tree=CommitmentTreeProver::<SimdBackend,Blake2sM31MerkleChannel>::new(polys,3,&tw,false,Some(log+3),&BaseColumnPool::new());
        tree.commitment.root().into()
    };
    let prep=get_cairo_preprocessed_circuit(&cfg);
    let mut outer_pcs=CIRCUIT_PCS_CONFIG;outer_pcs.lifting_log_size=Some(prep.trace_log_size+CIRCUIT_LOG_BLOWUP_FACTOR);
    let root={
        let tw=SimdBackend::precompute_twiddles(CanonicCoset::new(outer_pcs.lifting_log_size.unwrap()).circle_domain().half_coset);
        let polys=SimdBackend::interpolate_columns(prep.preprocessed_trace.get_trace::<SimdBackend>(),&tw);
        let tree=CommitmentTreeProver::<SimdBackend,Blake2sM31MerkleChannel>::new(polys,CIRCUIT_LOG_BLOWUP_FACTOR,&tw,false,outer_pcs.lifting_log_size,&BaseColumnPool::new());
        tree.commitment.root()
    };
    let circuit=CircuitConfig{config:outer_pcs,n_outputs:2,preprocessed_column_log_sizes:prep.preprocessed_trace.log_sizes(),preprocessed_root:root.into()};
    let proof_config=ProofConfig::new(&all_circuit_components::<QM31>(),circuit.preprocessed_column_log_sizes.len(),&outer_pcs,circuit_verifier::statement::INTERACTION_POW_BITS);
    Ok((cfg,prep,circuit,proof_config))
}
fn save(path:&Path,value:&impl serde::Serialize){fs::write(path,serde_json::to_vec_pretty(value).unwrap()).unwrap();}
fn config_json(c:&CircuitConfig,log:u32)->serde_json::Value{
    json!({"scope":"research configuration; new trusted verifier root required","cairo_trace_log":log,"cairo_lifting_log":log+3,"cairo_pow_bits":CAIRO_PCS_CONFIG.pow_bits,"cairo_fri":CAIRO_PCS_CONFIG.fri_config,"circuit_pcs":c.config,"circuit_preprocessed_columns":c.preprocessed_column_log_sizes.iter().map(|(id,size)|json!({"id":id.id,"log_size":size})).collect::<Vec<_>>(),"circuit_preprocessed_root":format!("{:?}",c.preprocessed_root),"matches_original_root":c.preprocessed_root==privacy_circuit_verify::get_recursive_circuit_config().preprocessed_root})
}
fn main()->Result<(),Box<dyn Error>> {
    let a:Vec<_>=std::env::args().collect();assert!(a.len()>=4,"capacity shape LOG OUT | trace PIE OUT | prove LOG PIE OUT");
    let mode=a[1].as_str();let out=Path::new(a.last().unwrap());fs::create_dir_all(out)?;
    if mode=="shape" {
        let log=a[2].parse()?;let (_,_,c,_)=configuration(log)?;save(&out.join("config.json"),&config_json(&c,log));return Ok(())
    }
    let pie_path=if mode=="trace" || mode=="trace-input" || mode=="boot" {&a[2]} else {&a[3]};
    let start=Instant::now();
    let (input,preimage)=if mode=="trace-input" {(serde_json::from_reader(std::io::BufReader::new(fs::File::open(pie_path)?))?,vec![])} else {boot(CairoPie::read_zip_file(Path::new(pie_path))?)?};
    save(&out.join("output-preimage.json"),&preimage);
    save(&out.join("boot.json"),&json!({"seconds":start.elapsed().as_secs_f64(),"pc_count":input.pc_count,"builtin_segments":input.builtin_segments,"blake_compressions":input.state_transitions.casm_states_by_opcode.blake_compress_opcode.len(),"qm31_opcodes":input.state_transitions.casm_states_by_opcode.qm_31_add_mul_opcode.len(),"generic_opcodes":input.state_transitions.casm_states_by_opcode.generic_opcode.len()}));
    if mode=="boot" {return Ok(())}
    if mode=="trace" || mode=="trace-input" {
        let generator=create_cairo_claim_generator(input,Arc::new(CAIRO_PROVER_PARAMS.preprocessed_trace.to_preprocessed_trace()));
        let (trace,claim,interaction)=generator.write_trace();
        save(&out.join("claim.json"),&claim);let flat=claim.flatten_claim();save(&out.join("flat-claim.json"),&json!({"component_log_sizes":flat.component_log_sizes,"component_enable_bits":flat.component_enable_bits}));
        println!("Trace generated: {} columns",trace.len());drop((trace,interaction));return Ok(())
    }
    assert_eq!(mode,"prove");let log:u32=a[2].parse()?;
    let (cfg,prep,circuit,proof_config)=configuration(log)?;
    save(&out.join("config.json"),&config_json(&circuit,log));
    let mut params=CAIRO_PROVER_PARAMS;params.pcs_config.lifting_log_size=Some(log+3);
    // Allocation policy only; proof geometry/security configuration is explicit above.
    params.store_polynomials_coefficients=false;
    let start=Instant::now();let cairo=prove_cairo::<Blake2sM31MerkleChannel>(input,params)?;
    let cairo_seconds=start.elapsed().as_secs_f64();save(&out.join("cairo-claim.json"),&cairo.claim);
    let FlatClaim{component_enable_bits,component_log_sizes,..}=cairo.claim.flatten_claim();
    let (proof,public)=prepare_cairo_proof_for_circuit_verifier(&cairo,&cfg.proof_config,&component_enable_bits);
    let (mut claim,_,_)=public.pack_into_u32s();claim.extend(component_log_sizes);
    let output=compute_privacy_bootloader_output(&preimage);
    let mut context=build_fixed_cairo_circuit(&cfg,proof,claim,vec![output]);
    assert!(context.is_circuit_valid(),"configured Cairo proof did not verify");
    add_zk_blinding(&mut context,cairo.extended_stark_proof.proof.commitments.0[1].0,circuit.config.fri_config.n_queries);
    finalize_context(&mut context);assert_eq!(PreprocessedCircuit::from_finalized_circuit(context.circuit()),prep);
    drop(cairo);
    let start=Instant::now();
    let proof=prove_circuit_assignment_with_channel::<Blake2sM31MerkleChannel>(context.values(),&prep,&BaseColumnPool::<SimdBackend>::new(),circuit.config)?;
    let circuit_seconds=start.elapsed().as_secs_f64();
    let (words,_)=prepare_circuit_proof_for_circuit_verifier(proof,&proof_config);
    let mut raw=Vec::new();words.serialize(&mut raw);
    let compressed=zstd::encode_all(raw.as_slice(),3)?;
    let proof_bytes:Vec<u8>=Version::current().serialize().into_iter().chain(compressed).collect();
    fs::write(out.join("research-proof.bin"),&proof_bytes)?;
    // Verify serialized proof, not retained prover witnesses.
    let decompressed=zstd::bulk::decompress(&proof_bytes[3..],4*1024*1024)?;
    let mut bytes=decompressed.as_slice();let decoded=deserialize_proof_with_config(&mut bytes,&proof_config)?;assert!(bytes.is_empty());
    let packed=pack_into_qm31s(output.into_iter());let hash=QM31::blake(&packed,packed.len()*16);
    let copy_config=||CircuitConfig{config:circuit.config,n_outputs:circuit.n_outputs,preprocessed_column_log_sizes:circuit.preprocessed_column_log_sizes.clone(),preprocessed_root:circuit.preprocessed_root};
    verify_circuit(copy_config(),decoded,CircuitPublicData{output_values:vec![hash.0,hash.1]})?;
    let check=|config:CircuitConfig,values:Vec<QM31>,raw:&[u8]| -> bool {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut bytes=raw;
            let Ok(decoded)=deserialize_proof_with_config(&mut bytes,&proof_config) else {return false};
            bytes.is_empty() && verify_circuit(config,decoded,CircuitPublicData{output_values:values}).is_ok()
        })).unwrap_or(false)
    };
    let mut wrong_root=copy_config();wrong_root.preprocessed_root.0+=QM31::from(1);
    let mut wrong_queries=copy_config();wrong_queries.config.fri_config.n_queries+=1;
    let mut trailing=decompressed.clone();trailing.push(0);
    let controls=[
        ("changed-output",check(copy_config(),vec![hash.0+QM31::from(1),hash.1],&decompressed)),
        ("wrong-trusted-root",check(wrong_root,vec![hash.0,hash.1],&decompressed)),
        ("wrong-query-config",check(wrong_queries,vec![hash.0,hash.1],&decompressed)),
        ("truncated",check(copy_config(),vec![hash.0,hash.1],&decompressed[..decompressed.len()-1])),
        ("trailing",check(copy_config(),vec![hash.0,hash.1],&trailing)),
    ];
    assert!(controls.iter().all(|(_,accepted)|!*accepted));
    save(&out.join("report.json"),&json!({"scope":"research enlarged final wrapper; not unchanged PROOF1 acceptance","cairo_seconds":cairo_seconds,"circuit_seconds":circuit_seconds,"proof_bytes":proof_bytes.len(),"configured_native_verifier":true,"negative_controls":controls,"original_verifier_accepts":null,"original_verifier_check":"Run separately with the preserved-dependency stock helper"}));
    Ok(())
}
