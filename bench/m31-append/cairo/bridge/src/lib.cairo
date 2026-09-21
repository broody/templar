//! Actual public M31 append proof verifier. No payment or privacy claim.
use core::num::traits::Zero;
use stwo_constraint_framework::{LookupElementsImpl};
use stwo_verifier_core::channel::{Channel,ChannelTrait};
use stwo_verifier_core::fields::qm31::{QM31,QM31Serde};
use stwo_verifier_core::fri::FriConfig;
use stwo_verifier_core::pcs::{PcsConfig,PcsConfigTrait};
use stwo_verifier_core::pcs::verifier::CommitmentSchemeVerifierImpl;
use stwo_verifier_core::vcs::{MerkleHasher};
use stwo_verifier_core::vcs::verifier::MerkleVerifier;
use stwo_verifier_core::verifier::{StarkProof,verify};
use air::{M31Air,TRACE_COLUMNS,INTERACTION_COLUMNS,public_boundary};
use statement::{Statement,validate,mix_statement,public_values};
pub mod statement;
pub mod air;
pub mod constants;
#[cfg(test)]
mod test;

#[derive(Drop,Serde)]
pub struct AppendProof {
    pub statement: Statement,
    pub interaction_pow: u64,
    pub claimed_sum: QM31,
    pub stark_proof: StarkProof,
}
#[derive(Drop,Serde)]
pub struct VerificationOutput { pub public_values: Span<felt252> }
pub fn config(log_size: u32) -> PcsConfig {
    PcsConfig { pow_bits:27,fri_config:FriConfig { log_blowup_factor:3,log_last_layer_degree_bound:0,n_queries:23,fold_step:4 },lifting_log_size:Some(log_size+3) }
}
pub fn verify_serialized(mut proof_data: Span<felt252>) -> VerificationOutput {
    let proof: AppendProof=Serde::deserialize(ref proof_data).expect('INVALID_APPEND_PROOF');
    assert(proof_data.is_empty(),'TRAILING_PROOF_DATA');
    let AppendProof {statement,interaction_pow,claimed_sum,stark_proof}=proof;
    let data=validate(statement);
    let log_size=data.log_size;
    let expected_config=config(log_size);
    assert(stark_proof.commitment_scheme_proof.config==expected_config,'PCS_CONFIG');
    let commitments=stark_proof.commitment_scheme_proof.commitments;
    assert(commitments.len()==4,'COMMITMENT_COUNT');
    let empty_root=MerkleHasher::hash_node(None,[].span());
    assert(*commitments.at(0)==empty_root,'PREPROCESSED_ROOT');
    let sampled=stark_proof.commitment_scheme_proof.sampled_values;
    assert(sampled.len()==4 && sampled.at(0).is_empty(),'PREPROCESSED_SAMPLES');
    assert(stark_proof.commitment_scheme_proof.queried_values.len()==4,'QUERIED_TREE_COUNT');
    assert(stark_proof.commitment_scheme_proof.queried_values.at(0).is_empty(),'PREPROCESSED_VALUES');
    assert(stark_proof.commitment_scheme_proof.decommitments.len()==4,'DECOMMITMENT_COUNT');
    assert(stark_proof.commitment_scheme_proof.decommitments.at(0).hash_witness.is_empty(),'PREPROCESSED_WITNESS');
    let mut channel: Channel=Default::default();
    mix_statement(statement,ref channel);
    expected_config.mix_into(ref channel);
    let mut pcs=CommitmentSchemeVerifierImpl::new();
    // Same root mix as normal commit; trusted empty preprocessing has actual height0.
    channel.mix_commitment(empty_root);
    pcs.trees.append(MerkleVerifier {root:empty_root,tree_height:0,column_log_deg_bounds:[].span()});
    channel.mix_u64(log_size.into());
    let mut trace_sizes=array![]; let mut interaction_sizes=array![];
    for _ in 0_usize..TRACE_COLUMNS { trace_sizes.append(log_size); };
    for _ in 0_usize..INTERACTION_COLUMNS { interaction_sizes.append(log_size); };
    pcs.commit(*commitments.at(1),trace_sizes.span(),ref channel,3);
    assert(channel.verify_pow_nonce(24,interaction_pow),'INTERACTION_POW');
    channel.mix_u64(interaction_pow);
    let lookup=LookupElementsImpl::draw(ref channel);
    assert((public_boundary(@data,@lookup)+claimed_sum).is_zero(),'PUBLIC_LOGUP_BOUNDARY');
    channel.mix_felts(array![claimed_sum].span());
    pcs.commit(*commitments.at(2),interaction_sizes.span(),ref channel,3);
    let output=VerificationOutput {public_values:public_values(statement)};
    let air=M31Air {log_size,claimed_sum,lookup};
    verify(stark_proof,air,log_size,*commitments.at(3),pcs,ref channel,96);
    output
}
#[executable]
fn main(proof_data: Span<felt252>) -> VerificationOutput { verify_serialized(proof_data) }
