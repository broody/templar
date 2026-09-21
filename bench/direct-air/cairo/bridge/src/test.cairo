use stwo_verifier_core::fri::FriConfig;
use stwo_verifier_core::pcs::{PcsConfig, PcsConfigTrait};
use stwo_verifier_core::channel::{Channel, ChannelTrait};
use stwo_verifier_core::fields::m31::m31;
use stwo_verifier_core::fields::qm31::QM31Trait;

#[test]
fn full_pcs_config_transcript_fixture() {
    let mut input = [26, 2, 0, 35, 4, 0, 22].span();
    let config: PcsConfig = Serde::deserialize(ref input).unwrap();
    let mut channel: Channel = Default::default();
    channel.mix_felts([QM31Trait::from_fixed_array([m31(0); 4])].span());
    config.mix_into(ref channel);
    assert!(
        channel.draw_u32s() == [
            818514698, 2723699314, 2954886817, 683566987,
            692549507, 2611026274, 2469451579, 691634613,
        ].span(),
    );
}

#[test]
fn full_pcs_config_serde_some() {
    let config = PcsConfig {
        pow_bits: 26,
        fri_config: FriConfig {
            log_blowup_factor: 2, log_last_layer_degree_bound: 0, n_queries: 35, fold_step: 4,
        },
        lifting_log_size: Some(22),
    };
    let mut wire = array![];
    config.serialize(ref wire);
    assert!(wire.span() == [26, 2, 0, 35, 4, 0, 22].span());
    let mut input = wire.span();
    let decoded: PcsConfig = Serde::deserialize(ref input).unwrap();
    assert!(decoded == config);
    assert!(input.is_empty());
}

#[test]
fn full_pcs_config_serde_none() {
    let mut input = [26, 2, 0, 35, 4, 1].span();
    let decoded: PcsConfig = Serde::deserialize(ref input).unwrap();
    assert!(decoded.lifting_log_size == None);
    let mut wire = array![];
    decoded.serialize(ref wire);
    assert!(wire.span() == [26, 2, 0, 35, 4, 1].span());
    assert!(input.is_empty());
}

#[test]
fn full_pcs_config_rejects_bad_option() {
    let mut input = [26, 2, 0, 35, 4, 2, 22].span();
    let decoded: Option<PcsConfig> = Serde::deserialize(ref input);
    assert!(decoded.is_none());
}
