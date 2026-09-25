//! Does an Argent 0.5.0 account with a guardian accept an owner-only signature in
//! is_valid_signature? Fresh keys, local fork only.
use snforge_std::signature::KeyPairTrait;
use snforge_std::signature::stark_curve::{StarkCurveKeyPairImpl, StarkCurveSignerImpl};
use snforge_std::{ContractClass, ContractClassTrait};

#[starknet::interface]
trait IValid<T> {
    fn is_valid_signature(self: @T, hash: felt252, signature: Array<felt252>) -> felt252;
}

const ARGENT_05: felt252 = 0x073414441639dcd11d1846f287650a00c60c416b9d3ba45d31c651672125b2c2;
const HASH: felt252 = 0x4d29dd987153f7c0163a924857f024e3f4afe971cc4ce2296fa0d61d1358667;

#[feature("safe_dispatcher")]
fn check(d: IValidSafeDispatcher, label: ByteArray, sig: Array<felt252>) {
    match d.is_valid_signature(HASH, sig) {
        Result::Ok(v) => println!("{label}: returned {v}"),
        Result::Err(e) => println!("{label}: panic {e:?}"),
    }
}

#[test]
#[fork("SEPOLIA")]
fn argent_05_with_guardian() {
    let owner = KeyPairTrait::<felt252, felt252>::generate();
    let guardian = KeyPairTrait::<felt252, felt252>::generate();
    // constructor(owner: Signer::Starknet(pk), guardian: Option::Some(Signer::Starknet(pk)))
    let (a, _) = ContractClass { class_hash: ARGENT_05.try_into().unwrap() }
        .deploy(@array![0, owner.public_key, 0, 0, guardian.public_key])
        .unwrap();
    let d = IValidSafeDispatcher { contract_address: a };
    let (r, s) = owner.sign(HASH).unwrap();
    let (gr, gs) = guardian.sign(HASH).unwrap();
    check(d, "owner only [r,s]", array![r, s]);
    check(d, "owner only [1,0,pk,r,s]", array![1, 0, owner.public_key, r, s]);
    check(d, "owner+guardian [r,s,gr,gs]", array![r, s, gr, gs]);
    check(d, "owner+guardian full", array![2, 0, owner.public_key, r, s, 0, guardian.public_key, gr, gs]);
}
