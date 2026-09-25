//! The R0 V5 statement account against real wallet accounts on a local fork of Sepolia (spec §15
//! P3, real-wallet signing of §5.3). Each wallet signed, through `cairo-r5/sign`, the exact spend
//! message for a real proof naming its account; the statement account, declared in the fork,
//! must accept that signature from the live account class and reject it under another salt.
//! Nothing is sent. Ignored by default: needs the local node and the `wallet-*` fixtures.
//! `snforge test --profile contract --include-ignored real_`.
use snforge_std::fs::{FileTrait, read_txt};
use snforge_std::{
    ContractClassTrait, DeclareResultTrait, MessageToL1, MessageToL1SpyAssertionsTrait, declare, spy_messages_to_l1,
    start_cheat_caller_address, start_cheat_chain_id_global,
};
use starknet::ContractAddress;
use templar_account_tests::{IStatementAccountDispatcher, IStatementAccountDispatcherTrait};

fn run(name: ByteArray, salt_delta: felt252) {
    let proof = read_txt(@FileTrait::new(format!("fixtures/{name}-proof.txt")));
    let c = read_txt(@FileTrait::new(format!("fixtures/{name}-constants.txt"))).span();
    let (salt, binding, chain, pool) = (*c.at(1), *c.at(4), *c.at(5), *c.at(6));
    let signature = c.slice(7, c.len() - 7);
    let class = declare("PaymentVerifierAccount").unwrap().contract_class();
    let (a, _) = class.deploy(@array![]).unwrap();
    let s = IStatementAccountDispatcher { contract_address: a };
    let mut spy = spy_messages_to_l1();
    start_cheat_chain_id_global(chain);
    let zero: ContractAddress = 0.try_into().unwrap();
    start_cheat_caller_address(a, zero);
    s.__execute__(proof.span(), salt + salt_delta, signature);
    let payload = array![(*class.class_hash).into(), 'TMPZR0_PAYMENT_V5', chain, pool, binding];
    spy.assert_sent(@array![(a, MessageToL1 { to_address: 0.try_into().unwrap(), payload })]);
}

#[test]
#[ignore]
#[fork("SEPOLIA")]
fn real_ready_accepts_its_signature() {
    run("wallet-argentx", 0);
}

#[test]
#[ignore]
#[fork("SEPOLIA")]
#[should_panic(expected: "SIG_CALL_FAILED")]
fn real_ready_rejects_another_salt() {
    run("wallet-argentx", 1);
}

#[test]
#[ignore]
#[fork("SEPOLIA")]
fn real_braavos_accepts_its_signature() {
    run("wallet-braavos", 0);
}

#[test]
#[ignore]
#[fork("SEPOLIA")]
#[should_panic(expected: "SIG_CALL_FAILED")]
fn real_braavos_rejects_another_salt() {
    run("wallet-braavos", 1);
}
