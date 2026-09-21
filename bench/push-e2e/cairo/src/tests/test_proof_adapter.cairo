//! Only tests the adapter's binding/guard logic; facts are injected by snforge.
//! Actual cryptographic verification is exercised separately on Sepolia.
use core::poseidon::poseidon_hash_span;
use starknet::{contract_address_const, ContractAddress, SyscallResultTrait};
use snforge_std::{declare, ContractClassTrait, DeclareResultTrait,
    start_cheat_caller_address, start_cheat_chain_id, start_cheat_block_number,
    start_cheat_proof_facts};
use pool::spend::{IVerifierDispatcher, IVerifierDispatcherTrait};

fn setup(mutation: u32) -> (IVerifierDispatcher, Array<felt252>) {
    let pool = contract_address_const::<0x123>();
    let statement: felt252 = 0x456;
    let statement_class: felt252 = 0x789;
    let class = declare("NativeProofVerifier").unwrap_syscall().contract_class();
    let (addr, _) = class.deploy(@array![pool.into(), statement, statement_class, 20]).unwrap_syscall();
    start_cheat_caller_address(addr, pool);
    start_cheat_chain_id(addr, 'SN_SEPOLIA');
    start_cheat_block_number(addr, 200);
    let public = array!['TEMPLAR_PUSH_POC2', 'SN_SEPOLIA', pool.into(), 0xabc, 0, 0, 0, 0xdef];
    let mut message = array![statement, 0, 9, statement_class];
    for x in public.span() { message.append(*x); };
    let digest = poseidon_hash_span(message.span());
    let facts = array![
        if mutation == 1 { 'PROOF2' } else { 'PROOF1' },
        'VIRTUAL_SNOS',
        if mutation == 2 { 17 } else { 0x53f6c9fcfd31d27279ff7d7e422b44623550a732b59fe193354a7316a96daa1 },
        'VIRTUAL_SNOS0',
        if mutation == 3 { 179 } else if mutation == 4 { 200 } else { 199 },
        0, 0, if mutation == 5 { 2 } else { 1 },
        if mutation == 6 { digest + 1 } else { digest },
    ];
    if mutation != 7 { start_cheat_proof_facts(addr, facts.span()); };
    if mutation == 8 { start_cheat_caller_address(addr, contract_address_const::<0x999>()); };
    if mutation == 9 { start_cheat_chain_id(addr, 'SN_MAIN'); };
    (IVerifierDispatcher { contract_address: addr }, public)
}

#[test]
fn native_adapter_accepts_matching_message() {
    let (v, p) = setup(0);
    assert(v.verify(array![].span(), p.span()), 'REJECTED');
}
#[test]
#[should_panic(expected: ('PROOF_VERSION',))]
fn native_adapter_rejects_other_proof_version() { let (v,p) = setup(1); v.verify(array![].span(),p.span()); }
#[test]
#[should_panic(expected: ('OS_PROGRAM',))]
fn native_adapter_rejects_unapproved_os() { let (v,p) = setup(2); v.verify(array![].span(),p.span()); }
#[test]
#[should_panic(expected: ('PROOF_AGE',))]
fn native_adapter_rejects_stale_proof() { let (v,p) = setup(3); v.verify(array![].span(),p.span()); }
#[test]
#[should_panic(expected: ('PROOF_AGE',))]
fn native_adapter_rejects_unfinalized_base() { let (v,p) = setup(4); v.verify(array![].span(),p.span()); }
#[test]
#[should_panic(expected: ('MESSAGE_COUNT',))]
fn native_adapter_rejects_multiple_messages() { let (v,p) = setup(5); v.verify(array![].span(),p.span()); }
#[test]
#[should_panic(expected: ('PROOF_BINDING',))]
fn native_adapter_rejects_changed_message() { let (v,p) = setup(6); v.verify(array![].span(),p.span()); }
#[test]
#[should_panic(expected: ('PROOF_FACTS_LENGTH',))]
fn native_adapter_rejects_missing_facts() { let (v,p) = setup(7); v.verify(array![].span(),p.span()); }
#[test]
#[should_panic(expected: ('ONLY_POOL',))]
fn native_adapter_rejects_other_caller() { let (v,p) = setup(8); v.verify(array![].span(),p.span()); }
#[test]
#[should_panic(expected: ('WRONG_CHAIN',))]
fn native_adapter_rejects_other_chain() { let (v,p) = setup(9); v.verify(array![].span(),p.span()); }
#[test]
#[should_panic(expected: ('PROOF_IN_TX_ONLY',))]
fn native_adapter_rejects_calldata_proof() { let (v,p) = setup(0); v.verify(array![1].span(),p.span()); }
