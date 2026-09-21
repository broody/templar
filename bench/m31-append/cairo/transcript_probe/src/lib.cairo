//! Transcript differential only: returns the next8 words after a selected prefix.
use stwo_verifier_core::channel::{Channel,ChannelTrait};
use stwo_verifier_core::pcs::PcsConfigTrait;
use stwo_verifier_core::vcs::MerkleHasher;
use templar_m31_append_bridge::{config};
use templar_m31_append_bridge::statement::{Statement,validate,mix_statement};
#[executable]
fn main(stage: u32,mut statement_data: Span<felt252>) -> Span<u32> {
    assert(stage<=3,'CHECKPOINT_STAGE');
    let statement: Statement=Serde::deserialize(ref statement_data).expect('STATEMENT_ENCODING');
    assert(statement_data.is_empty(),'STATEMENT_TRAILING');
    let data=validate(statement);
    let mut channel: Channel=Default::default();
    mix_statement(statement,ref channel);
    if stage>=1 { config(data.log_size).mix_into(ref channel); }
    if stage>=2 { channel.mix_commitment(MerkleHasher::hash_node(None,[].span())); }
    if stage>=3 { channel.mix_u64(data.log_size.into()); }
    channel.draw_u32s()
}
