// Hand-written checks next to the generated KATs (test_kat.cairo).
use starknet::ContractAddress;
use templar_wallet_sig_snip12::{
    DOMAIN_NAME, DOMAIN_REVISION, STARKNET_DOMAIN_TYPE_HASH, TEMPLAR_KEY_DERIVATION_TYPE_HASH,
    TEMPLAR_SPEND_TYPE_HASH, derivation_message_hash, domain_hash, spend_message_hash,
};

const SN_SEPOLIA: felt252 = 'SN_SEPOLIA';

fn account() -> ContractAddress {
    0x0734b2c2.try_into().unwrap()
}
fn pool() -> ContractAddress {
    0x2da0011111111111111111111111111111111111111111111111111111137b9.try_into().unwrap()
}
fn zero() -> ContractAddress {
    0.try_into().unwrap()
}

fn fixed_spend(account: ContractAddress, salt: felt252, chain_id: felt252) -> felt252 {
    spend_message_hash(chain_id, account, pool(), 0x1234, salt, zero(), zero(), 0, 0, 16000000)
}

/// Pinned constants == sn_keccak(encodeType) computed by the Cairo compiler (independent of JS).
#[test]
fn pinned_type_hashes_equal_selector_of_encode_type() {
    assert_eq!(
        STARKNET_DOMAIN_TYPE_HASH,
        selector!(
            "\"StarknetDomain\"(\"name\":\"shortstring\",\"version\":\"shortstring\",\"chainId\":\"shortstring\",\"revision\":\"shortstring\")",
        ),
    );
    assert_eq!(
        TEMPLAR_SPEND_TYPE_HASH,
        selector!(
            "\"TemplarSpend\"(\"pool\":\"ContractAddress\",\"binding_commitment\":\"felt\",\"token_out\":\"ContractAddress\",\"withdrawal_recipient\":\"ContractAddress\",\"withdrawal_amount\":\"u128\",\"intent\":\"felt\",\"valid_until\":\"u128\")",
        ),
    );
    assert_eq!(
        TEMPLAR_KEY_DERIVATION_TYPE_HASH,
        selector!(
            "\"TemplarKeyDerivation\"(\"purpose\":\"shortstring\",\"chain\":\"shortstring\",\"account\":\"ContractAddress\")",
        ),
    );
}

/// Pitfall: an ASCII '1' (0x31) domain version does NOT match starknet.js. Value from kat.json
/// `pitfall_ascii_version_domain_hash_sn_sepolia`.
#[test]
fn ascii_version_is_a_different_domain() {
    let ascii = core::poseidon::poseidon_hash_span(
        [STARKNET_DOMAIN_TYPE_HASH, DOMAIN_NAME, '1', SN_SEPOLIA, DOMAIN_REVISION].span(),
    );
    assert_eq!(ascii, 0x76913d0d05d57447acf2d9c33da65cd2bc2fb88f06a833bd581a48db0ff6f83);
    assert_ne!(ascii, domain_hash(SN_SEPOLIA));
}

/// The envelope binds the signer account, the salt and the chain.
#[test]
fn spend_hash_binds_account_salt_chain() {
    let base = fixed_spend(account(), 0x5678, SN_SEPOLIA);
    assert_eq!(base, 0x2bf922f4a8ad28fd0054dc05d00ffe0a02894650e2ac1723fe3f81ac697be2c);
    assert_ne!(base, fixed_spend(0x0734b2c3.try_into().unwrap(), 0x5678, SN_SEPOLIA));
    assert_ne!(base, fixed_spend(account(), 0x5679, SN_SEPOLIA));
    assert_ne!(base, fixed_spend(account(), 0x5678, 'SN_MAIN'));
}

/// Spend and key-derivation messages never collide for the same account/domain (distinct type
/// hashes); spot check on the fixed inputs.
#[test]
fn spend_and_derivation_are_distinct() {
    let d = derivation_message_hash(SN_SEPOLIA, account(), 'TEMPLAR_SECRET_V1', SN_SEPOLIA);
    assert_eq!(d, 0x154aae51ddf2e6c317b04c1ea92e565b969534c2f252d39588072d465f16864);
    assert_ne!(d, fixed_spend(account(), 0x5678, SN_SEPOLIA));
}

/// Resource probe (not a timed benchmark): exactly one spend_message_hash call. Run with
/// `snforge test resource_probe --detailed-resources` to read steps / builtins.
#[test]
fn resource_probe_spend_message_hash() {
    let h = fixed_spend(account(), 0x5678, SN_SEPOLIA);
    assert(h != 0, 'zero');
}

/// Resource probe: exactly one derivation_message_hash call.
#[test]
fn resource_probe_derivation_message_hash() {
    let h = derivation_message_hash(SN_SEPOLIA, account(), 'TEMPLAR_SECRET_V1', SN_SEPOLIA);
    assert(h != 0, 'zero');
}
