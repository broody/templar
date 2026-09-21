//! Bridge-local serializer for stwo-cairo commit 16700cc9's complete PCS config.
//! The pinned upstream Rust serializer omits lifting_log_size. Keep that implementation
//! unchanged, and explicitly write every top-level field here in Cairo declaration order.
use circuit_cairo_serialize::{CairoCircuitClaim, CairoCircuitInteractionClaim, CairoStarkProof};
use circuit_verifier::circuit_claim::column_log_sizes_per_tree;
use circuit_verifier::circuit_components::N_COMPONENTS;
use circuit_verifier::circuit_proof::CircuitProof;
use starknet_ff::FieldElement;
use stwo::core::pcs::PcsConfig;
use stwo::core::vcs::blake2_hash::Blake2sHash;
use stwo::core::vcs_lifted::merkle_hasher::MerkleHasherLifted;
use stwo_cairo_serialize::CairoSerialize;

pub fn serialize_config(config: &PcsConfig, output: &mut Vec<FieldElement>) {
    config.pow_bits.serialize(output);
    config.fri_config.serialize(output);
    config.lifting_log_size.serialize(output);
}

/// Returns the proof felts themselves. The executable's Span argument additionally requires
/// its length prefix; Starknet ABI encoding likewise wraps these felts as a span.
pub fn serialize_proof<H: MerkleHasherLifted<Hash = Blake2sHash>>(
    proof: CircuitProof<H>,
    component_log_sizes: &[u32; N_COMPONENTS],
) -> Vec<FieldElement> {
    let [trace, interaction] = column_log_sizes_per_tree(component_log_sizes);
    let stark = CairoStarkProof::<H>::from_stark_proof(
        proof.stark_proof.proof,
        &[trace.as_slice(), interaction.as_slice()],
    );
    let mut output = Vec::new();
    CairoCircuitClaim::new(&proof.claim).serialize(&mut output);
    proof.interaction_pow_nonce.serialize(&mut output);
    CairoCircuitInteractionClaim::from(&proof.interaction_claim).serialize(&mut output);
    serialize_config(&stark.config, &mut output);
    stark.commitments.serialize(&mut output);
    stark.sampled_values.serialize(&mut output);
    stark.decommitments.serialize(&mut output);
    stark.queried_values.serialize(&mut output);
    stark.proof_of_work.serialize(&mut output);
    stark.fri_proof.serialize(&mut output);
    proof.channel_salt.serialize(&mut output);
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use stwo::core::fri::FriConfig;

    #[test]
    fn full_config_transcript_fixture() {
        use stwo::core::channel::{Blake2sChannel, Channel};
        let config = PcsConfig {
            pow_bits: 26,
            fri_config: FriConfig::new(0, 2, 35, 4),
            lifting_log_size: Some(22),
        };
        let mut channel = Blake2sChannel::default();
        channel.mix_felts(&[0_u32.into()]);
        config.mix_into(&mut channel);
        assert_eq!(channel.draw_u32s(), vec![
            818514698, 2723699314, 2954886817, 683566987,
            692549507, 2611026274, 2469451579, 691634613,
        ]);
    }

    #[test]
    fn full_config_wire_schema() {
        let mut config = PcsConfig {
            pow_bits: 26,
            fri_config: FriConfig::new(0, 2, 35, 4),
            lifting_log_size: Some(22),
        };
        let mut output = Vec::new();
        serialize_config(&config, &mut output);
        assert_eq!(output, [26_u32, 2, 0, 35, 4, 0, 22].map(FieldElement::from));
        config.lifting_log_size = None;
        output.clear();
        serialize_config(&config, &mut output);
        assert_eq!(output, [26_u32, 2, 0, 35, 4, 1].map(FieldElement::from));
    }
}
