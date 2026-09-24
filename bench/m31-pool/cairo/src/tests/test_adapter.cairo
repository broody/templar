//! The PROOF2 adapter's binding and guard logic; facts are injected by snforge. Cryptographic
//! verification is Starknet's, exercised only by a live submission.
use core::poseidon::poseidon_hash_span;
use snforge_std::{
    ContractClassTrait, DeclareResultTrait, declare, start_cheat_block_number, start_cheat_caller_address,
    start_cheat_chain_id, start_cheat_proof_facts,
};
use starknet::{ContractAddress, SyscallResultTrait};
use m31_pool::spend::{IVerifierDispatcher, IVerifierDispatcherTrait};
use super::vectors::{
    REAL_BASE_BLOCK, REAL_BINDING, REAL_CHAIN, REAL_FACTS, REAL_POOL, REAL_STATEMENT, REAL_STATEMENT_CLASS,
};

const OS: felt252 = 0x53f6c9fcfd31d27279ff7d7e422b44623550a732b59fe193354a7316a96daa1;

fn setup(mutation: u32) -> (IVerifierDispatcher, Array<felt252>) {
    let pool: ContractAddress = 0x123.try_into().unwrap();
    let statement: felt252 = 0x456;
    let statement_class: felt252 = 0x789;
    let class = declare("Proof2Adapter").unwrap_syscall().contract_class();
    let (addr, _) = class.deploy(@array![pool.into(), statement, statement_class, OS, 20, 'TMPZR0_PAYMENT_V3']).unwrap_syscall();
    start_cheat_caller_address(addr, pool);
    start_cheat_chain_id(addr, 'SN_SEPOLIA');
    start_cheat_block_number(addr, 200);
    let public = array!['SN_SEPOLIA', pool.into(), 0xb1d];
    let mut message = array![statement, 0, 5, statement_class, 'TMPZR0_PAYMENT_V3'];
    message.append_span(public.span());
    let digest = poseidon_hash_span(message.span());
    let facts = array![
        if mutation == 1 { 'PROOF1' } else { 'PROOF2' }, 'VIRTUAL_SNOS', if mutation == 2 { 17 } else { OS },
        'VIRTUAL_SNOS0', if mutation == 3 { 179 } else if mutation == 4 { 200 } else { 199 }, 0, 0,
        if mutation == 5 { 2 } else { 1 }, if mutation == 6 { digest + 1 } else { digest },
    ];
    if mutation != 7 {
        start_cheat_proof_facts(addr, facts.span());
    }
    if mutation == 8 {
        start_cheat_caller_address(addr, 0x999.try_into().unwrap());
    }
    if mutation == 9 {
        start_cheat_chain_id(addr, 'SN_MAIN');
    }
    (IVerifierDispatcher { contract_address: addr }, public)
}

#[test]
fn adapter_accepts_matching_message() {
    let (v, p) = setup(0);
    assert(v.verify(array![].span(), p.span()), 'REJECTED');
}
#[test]
#[should_panic(expected: ('PROOF_VERSION',))]
fn adapter_rejects_proof1() { let (v, p) = setup(1); v.verify(array![].span(), p.span()); }
#[test]
#[should_panic(expected: ('OS_PROGRAM',))]
fn adapter_rejects_unapproved_os() { let (v, p) = setup(2); v.verify(array![].span(), p.span()); }
#[test]
#[should_panic(expected: ('PROOF_AGE',))]
fn adapter_rejects_stale_proof() { let (v, p) = setup(3); v.verify(array![].span(), p.span()); }
#[test]
#[should_panic(expected: ('PROOF_AGE',))]
fn adapter_rejects_unfinalized_base() { let (v, p) = setup(4); v.verify(array![].span(), p.span()); }
#[test]
#[should_panic(expected: ('MESSAGE_COUNT',))]
fn adapter_rejects_multiple_messages() { let (v, p) = setup(5); v.verify(array![].span(), p.span()); }
#[test]
#[should_panic(expected: ('PROOF_BINDING',))]
fn adapter_rejects_changed_message() { let (v, p) = setup(6); v.verify(array![].span(), p.span()); }
#[test]
#[should_panic(expected: ('PROOF_FACTS_LENGTH',))]
fn adapter_rejects_missing_facts() { let (v, p) = setup(7); v.verify(array![].span(), p.span()); }
#[test]
#[should_panic(expected: ('ONLY_POOL',))]
fn adapter_rejects_other_caller() { let (v, p) = setup(8); v.verify(array![].span(), p.span()); }
#[test]
#[should_panic(expected: ('WRONG_CHAIN',))]
fn adapter_rejects_other_chain() { let (v, p) = setup(9); v.verify(array![].span(), p.span()); }
#[test]
#[should_panic(expected: ('PROOF_IN_TX_ONLY',))]
fn adapter_rejects_calldata_proof() { let (v, p) = setup(0); v.verify(array![1].span(), p.span()); }

/// The adapter accepts the facts of a real PROOF2 (a virtual-OS run of the R0 statement account)
/// for exactly the binding its message carries, and rejects any other binding.
fn real_setup() -> IVerifierDispatcher {
    let pool: ContractAddress = REAL_POOL.try_into().unwrap();
    let class = declare("Proof2Adapter").unwrap_syscall().contract_class();
    let (addr, _) = class.deploy(@array![REAL_POOL, REAL_STATEMENT, REAL_STATEMENT_CLASS, OS, 100, 'TMPZR0_PAYMENT_V3']).unwrap_syscall();
    start_cheat_caller_address(addr, pool);
    start_cheat_chain_id(addr, REAL_CHAIN);
    start_cheat_block_number(addr, REAL_BASE_BLOCK + 20);
    start_cheat_proof_facts(addr, REAL_FACTS.span());
    IVerifierDispatcher { contract_address: addr }
}
#[test]
fn adapter_accepts_real_proof2_facts() {
    assert(real_setup().verify(array![].span(), array![REAL_CHAIN, REAL_POOL, REAL_BINDING].span()), 'REJECTED');
}
#[test]
#[should_panic(expected: ('PROOF_BINDING',))]
fn adapter_rejects_real_facts_for_other_binding() {
    real_setup().verify(array![].span(), array![REAL_CHAIN, REAL_POOL, REAL_BINDING + 1].span());
}

/// One adapter serves one relation: an adapter pinned to the P1 account tag rejects the facts of
/// a real R0 PROOF2, whose message carries `'TMPZR0_PAYMENT_V3'`.
#[test]
#[should_panic(expected: ('PROOF_BINDING',))]
fn policy_adapter_rejects_r0_facts() {
    let pool: ContractAddress = REAL_POOL.try_into().unwrap();
    let class = declare("Proof2Adapter").unwrap_syscall().contract_class();
    let (addr, _) = class.deploy(@array![REAL_POOL, REAL_STATEMENT, REAL_STATEMENT_CLASS, OS, 100, 'TMPZP1_POLICY_V1']).unwrap_syscall();
    start_cheat_caller_address(addr, pool);
    start_cheat_chain_id(addr, REAL_CHAIN);
    start_cheat_block_number(addr, REAL_BASE_BLOCK + 20);
    start_cheat_proof_facts(addr, REAL_FACTS.span());
    IVerifierDispatcher { contract_address: addr }.verify(array![].span(), array![REAL_CHAIN, REAL_POOL, REAL_BINDING].span());
}
