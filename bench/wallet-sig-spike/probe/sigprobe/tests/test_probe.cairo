//! P0b spike (throwaway): SigProbe against real wallet account classes on a LOCAL fork of Sepolia
//! (snforge reads state from the local node; nothing is sent). Fresh random Stark keys only
//! (`KeyPairTrait::generate`); no existing key is used.
//!
//! Positive: a fresh instance of each class, deployed in the fork with a fresh key, signs `HASH`;
//! the probe's `__execute__` (as the OS calls it, caller 0) must emit exactly
//! `[probe_class, 'SPIKE_SIG_V1', target, HASH]`. Braavos cannot be deployed without its factory
//! flow, so the test overwrites the Stark signer slot of an existing Braavos 1.2.0 account in the
//! fork (`stark_signers`: its base slot holds the key that `get_public_key` returns, found by a
//! read-only storage scan of the account on the node).
//! Negative (fail closed): a signature over another hash, a random signature against real deployed
//! accounts, a target without `is_valid_signature`, and a nonzero caller. Argent 0.5.0 and Braavos
//! 1.2.0 panic on a bad signature (the probe catches it: SIG_CALL_FAILED); OpenZeppelin returns 0
//! (SIG_NOT_VALID); a missing entry point is caught too (SIG_CALL_FAILED).
//! Gas: `get_available_gas()` around the call (Sierra gas, snforge's accounting).
use core::testing::get_available_gas;
use snforge_std::signature::KeyPairTrait;
use snforge_std::signature::stark_curve::{StarkCurveKeyPairImpl, StarkCurveSignerImpl};
use snforge_std::{
    ContractClass, ContractClassTrait, DeclareResultTrait, MessageToL1, MessageToL1SpyAssertionsTrait,
    declare, spy_messages_to_l1, start_cheat_caller_address, start_cheat_resource_bounds_global,
    start_cheat_tip_global, store,
};
use starknet::ContractAddress;

#[starknet::interface]
trait ISigProbe<T> {
    fn __execute__(ref self: T, target: ContractAddress, hash: felt252, signature: Span<felt252>);
    fn __validate__(self: @T, target: ContractAddress, hash: felt252, signature: Span<felt252>) -> felt252;
}

#[starknet::interface]
trait ISrc6<T> {
    fn is_valid_signature(self: @T, hash: felt252, signature: Array<felt252>) -> felt252;
}

// Sepolia classes and accounts (recon.mjs, block 15,609,963).
const ARGENT_05: felt252 = 0x073414441639dcd11d1846f287650a00c60c416b9d3ba45d31c651672125b2c2;
const ARGENT_04: felt252 = 0x036078334509b514626504edc9fb252328d1a240e4e948bef8d0c08dff45927f;
const OZ_SNCAST: felt252 = 0x05b4b537eaa2399e3aa99c4e2e0208ebd6c71bc1467938cd52c798c601e43564;
// An existing Braavos 1.2.0 account (class 0x03957f9f...bf8a), a recent sender on Sepolia.
const BRAAVOS_120_ACCOUNT: felt252 = 0xe4f9cbf9be372aea2bf1fc3d5bab3e9c805c828a82dbaf12b0e2b498dc3715;
// Our relayer account-1 (Argent 0.5.0), used only as a target of a random signature.
const RELAYER: felt252 = 0x54f2b25070d70d49f1c1f7c10ef2639889fdac15894d3fba1a03caf5603eca3;
// Any fixed message hash (the probe does not interpret it).
const HASH: felt252 = 0x2b8a6c3f1e0d4b5a69788796a5b4c3d2e1f00112233445566778899aabbccdd;

fn addr(x: felt252) -> ContractAddress {
    x.try_into().unwrap()
}

fn deploy_probe() -> ContractAddress {
    let (a, _) = declare("SigProbe").unwrap().contract_class().deploy(@array![]).unwrap();
    a
}

fn deploy_class(class_hash: felt252, calldata: Array<felt252>) -> ContractAddress {
    let (a, _) = ContractClass { class_hash: class_hash.try_into().unwrap() }.deploy(@calldata).unwrap();
    a
}

/// Runs the probe as the OS does (caller 0); returns the Sierra gas of the `__execute__` call.
fn execute(probe: ContractAddress, target: ContractAddress, hash: felt252, sig: Span<felt252>) -> u128 {
    start_cheat_caller_address(probe, addr(0));
    let d = ISigProbeDispatcher { contract_address: probe };
    let g0 = get_available_gas();
    d.__execute__(target, hash, sig);
    g0 - get_available_gas()
}

fn ivs_gas(target: ContractAddress, hash: felt252, sig: Array<felt252>) -> (felt252, u128) {
    let g0 = get_available_gas();
    let r = ISrc6Dispatcher { contract_address: target }.is_valid_signature(hash, sig);
    (r, g0 - get_available_gas())
}

fn check_positive(label: ByteArray, target: ContractAddress, sig: Array<felt252>) {
    let probe = deploy_probe();
    let probe_class = starknet::syscalls::get_class_hash_at_syscall(probe).unwrap();
    let (r, g_ivs) = ivs_gas(target, HASH, sig.clone());
    assert!(r == 'VALID', "direct is_valid_signature");
    let mut spy = spy_messages_to_l1();
    let g = execute(probe, target, HASH, sig.span());
    let payload = array![probe_class.into(), 'SPIKE_SIG_V1', target.into(), HASH];
    spy.assert_sent(@array![(probe, MessageToL1 { to_address: 0_felt252.try_into().unwrap(), payload })]);
    println!("GAS {} sig_felts={} is_valid_signature={} probe_execute={}", label, sig.len(), g_ivs, g);
}

// ---------------------------------------------------------------- positive, per wallet class

#[test]
#[fork("SEPOLIA")]
fn argent_05_fresh_key_accepts() {
    let kp = KeyPairTrait::<felt252, felt252>::generate();
    // Argent 0.5.0: constructor(owner: Signer, guardian: Option<Signer>); Signer::Starknet = 0.
    let target = deploy_class(ARGENT_05, array![0, kp.public_key, 1]);
    let (r, s) = kp.sign(HASH).unwrap();
    check_positive("argent_0.5.0 [r,s]", target, array![r, s]);
    // The Argent signature-array form: [n, Signer::Starknet, pubkey, r, s].
    check_positive("argent_0.5.0 [1,0,pk,r,s]", target, array![1, 0, kp.public_key, r, s]);
}

#[test]
#[fork("SEPOLIA")]
fn argent_04_fresh_key_accepts() {
    let kp = KeyPairTrait::<felt252, felt252>::generate();
    let target = deploy_class(ARGENT_04, array![0, kp.public_key, 1]);
    let (r, s) = kp.sign(HASH).unwrap();
    check_positive("argent_0.4.0 [r,s]", target, array![r, s]);
}

#[test]
#[fork("SEPOLIA")]
fn openzeppelin_fresh_key_accepts() {
    let kp = KeyPairTrait::<felt252, felt252>::generate();
    let target = deploy_class(OZ_SNCAST, array![kp.public_key]);
    let (r, s) = kp.sign(HASH).unwrap();
    check_positive("openzeppelin_sncast [r,s]", target, array![r, s]);
}

#[test]
#[fork("SEPOLIA")]
fn braavos_120_fresh_key_accepts() {
    // Fork-local only: replace the Stark signer of an existing Braavos 1.2.0 account.
    let kp = KeyPairTrait::<felt252, felt252>::generate();
    let target = addr(BRAAVOS_120_ACCOUNT);
    store(target, selector!("stark_signers"), array![kp.public_key].span());
    let (r, s) = kp.sign(HASH).unwrap();
    check_positive("braavos_1.2.0 [r,s]", target, array![r, s]);
}

// ---------------------------------------------------------------- negative: fail closed

#[test]
#[fork("SEPOLIA")]
#[should_panic(expected: "SIG_CALL_FAILED")]
fn argent_05_other_hash_rejects() {
    let kp = KeyPairTrait::<felt252, felt252>::generate();
    let target = deploy_class(ARGENT_05, array![0, kp.public_key, 1]);
    let (r, s) = kp.sign(HASH + 1).unwrap();
    execute(deploy_probe(), target, HASH, array![r, s].span());
}

#[test]
#[fork("SEPOLIA")]
#[should_panic(expected: "SIG_NOT_VALID")]
fn openzeppelin_other_hash_rejects() {
    let kp = KeyPairTrait::<felt252, felt252>::generate();
    let target = deploy_class(OZ_SNCAST, array![kp.public_key]);
    let (r, s) = kp.sign(HASH + 1).unwrap();
    execute(deploy_probe(), target, HASH, array![r, s].span());
}

#[test]
#[fork("SEPOLIA")]
#[should_panic(expected: "SIG_CALL_FAILED")]
fn relayer_random_signature_rejects() {
    // A fresh key's signature against the real relayer account (Argent 0.5.0): not its owner.
    let kp = KeyPairTrait::<felt252, felt252>::generate();
    let (r, s) = kp.sign(HASH).unwrap();
    execute(deploy_probe(), addr(RELAYER), HASH, array![r, s].span());
}

#[test]
#[fork("SEPOLIA")]
#[should_panic(expected: "SIG_CALL_FAILED")]
fn braavos_random_signature_rejects() {
    let kp = KeyPairTrait::<felt252, felt252>::generate();
    let (r, s) = kp.sign(HASH).unwrap();
    execute(deploy_probe(), addr(BRAAVOS_120_ACCOUNT), HASH, array![r, s].span());
}

#[test]
#[fork("SEPOLIA")]
#[should_panic(expected: "SIG_CALL_FAILED")]
fn target_without_is_valid_signature_rejects() {
    // The probe itself has no is_valid_signature.
    let probe = deploy_probe();
    execute(probe, probe, HASH, array![1, 2].span());
}

#[test]
#[fork("SEPOLIA")]
#[should_panic(expected: "OS_ONLY")]
fn nonzero_caller_rejects() {
    let kp = KeyPairTrait::<felt252, felt252>::generate();
    let target = deploy_class(OZ_SNCAST, array![kp.public_key]);
    let (r, s) = kp.sign(HASH).unwrap();
    let probe = deploy_probe();
    start_cheat_caller_address(probe, addr(0x123));
    ISigProbeDispatcher { contract_address: probe }.__execute__(target, HASH, array![r, s].span());
}

fn zero_price_bounds() -> Span<starknet::ResourcesBounds> {
    array![
        starknet::ResourcesBounds { resource: 'L1_GAS', max_amount: 0, max_price_per_unit: 0 },
        starknet::ResourcesBounds { resource: 'L2_GAS', max_amount: 1000000000, max_price_per_unit: 0 },
        starknet::ResourcesBounds { resource: 'L1_DATA', max_amount: 0, max_price_per_unit: 0 },
    ]
        .span()
}

#[test]
fn validate_accepts_zero_fee() {
    // The prover server's transaction: zero prices, zero tip.
    let probe = deploy_probe();
    start_cheat_resource_bounds_global(zero_price_bounds());
    let v = ISigProbeDispatcher { contract_address: probe }.__validate__(addr(1), HASH, array![].span());
    assert!(v == 'VALID', "validate");
}

#[test]
#[should_panic(expected: "PROVE_ONLY")]
fn validate_rejects_nonzero_price() {
    // snforge's default transaction has nonzero prices.
    let probe = deploy_probe();
    ISigProbeDispatcher { contract_address: probe }.__validate__(addr(1), HASH, array![].span());
}

#[test]
#[should_panic(expected: "PROVE_ONLY")]
fn validate_rejects_tip() {
    let probe = deploy_probe();
    start_cheat_resource_bounds_global(zero_price_bounds());
    start_cheat_tip_global(1);
    ISigProbeDispatcher { contract_address: probe }.__validate__(addr(1), HASH, array![].span());
}
