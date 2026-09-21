//! Settlement tests use an explicit mock verifier; native proof checks are separate.
use starknet::{ContractAddress, contract_address_const, get_tx_info, SyscallResultTrait};
use starknet::syscalls::call_contract_syscall;
use snforge_std::{declare, ContractClassTrait, DeclareResultTrait, test_address, start_cheat_block_number};
use core::poseidon::poseidon_hash_span;
use pool::pool::{IPoolDispatcher, IPoolDispatcherTrait, IPoolSafeDispatcher, IPoolSafeDispatcherTrait};
use pool::spend::{Spend, Withdrawal, Output, PROTOCOL_VERSION, compute_binding, IERC20Dispatcher, IERC20DispatcherTrait};
use pool::return_note::{ReturnNote, ExecutionIntent, hash_intent, return_digest, IBalanceDispatcher, IBalanceDispatcherTrait};
use pool::tree::{ITreeDispatcher, ITreeDispatcherTrait};

pub fn deploy(name: ByteArray, data: Array<felt252>) -> ContractAddress {
    let (address, _) = declare(name).unwrap_syscall().contract_class().deploy(@data).unwrap_syscall(); address
}
pub fn payload() -> Span<felt252> { array![1,2,3,4,5,6,7,8,9,10].span() }
pub fn balance(token: ContractAddress, who: ContractAddress) -> u256 {
    IBalanceDispatcher { contract_address: token }.balance_of(who)
}
pub fn authorize(ref s: Spend, i: @ExecutionIntent) { s.intent=hash_intent(@s,i); s.binding=compute_binding(@s); }
pub fn setup() -> (IPoolDispatcher, Spend, ExecutionIntent) {
    let verifier=deploy("MockVerifier",array![1]);
    let pool=deploy("Pool",array![test_address().into(),verifier.into()]);
    let a=deploy("E2EToken",array![test_address().into(),10000,0]);
    let b=deploy("E2EToken",array![test_address().into(),10000,0]);
    let adapter=deploy("TestAdapter",array![]);
    let p=IPoolDispatcher { contract_address: pool }; start_cheat_block_number(pool,1);
    IERC20Dispatcher { contract_address: a }.approve(pool,1000);
    p.deposit(a,1000,contract_address_const::<0>(),0,0xbeef,payload());
    IERC20Dispatcher { contract_address: b }.transfer(adapter,500);
    let mut s=Spend { version: PROTOCOL_VERSION, chain: get_tx_info().unbox().chain_id,pool,
        root: ITreeDispatcher { contract_address: pool }.get_root(),token:a,binding:0,
        controller:contract_address_const::<0>(),deadline:0,nonce:0,transition:0,sig_r:0,sig_s:0,intent:0,
        nullifiers:array![123].span(),outputs:array![].span(),
        withdrawals:array![Withdrawal { recipient:adapter,amount:100 }].span() };
    let i=ExecutionIntent { adapter,amount:100,expiry:1000,calldata:array![17,b.into()].span(),
        notes:array![ReturnNote { note_id:17,token:b,minimum:70,inner:0xface,ciphertext:payload() }].span() };
    authorize(ref s,@i); (p,s,i)
}
fn mode(i: @ExecutionIntent, value: felt252) {
    call_contract_syscall(*i.adapter,selector!("configure"),array![value].span()).unwrap_syscall();
}
#[feature("safe_dispatcher")]
fn rejected(p: IPoolDispatcher,s: Spend,i: ExecutionIntent,reason: felt252) {
    let t=ITreeDispatcher { contract_address:p.contract_address }; let root=t.get_root(); let count=t.get_leaf_count();
    let a=s.token; let b=*i.notes.at(0).token; let adapter=i.adapter;
    let before=(balance(a,p.contract_address),balance(b,p.contract_address),balance(a,adapter),balance(b,adapter));
    let nfs=s.nullifiers;
    let error=IPoolSafeDispatcher { contract_address:p.contract_address }.execute_returns(s,i,array![].span()).expect_err('ACCEPTED');
    let mut found=false; for x in error.span() { if *x==reason { found=true; }; };
    assert(found,'WRONG_REASON'); assert_eq!(t.get_root(),root); assert_eq!(t.get_leaf_count(),count);
    for nf in nfs { assert(!p.get_nullifier_spent(*nf),'NULLIFIER_CHANGED'); };
    assert_eq!((balance(a,p.contract_address),balance(b,p.contract_address),balance(a,adapter),balance(b,adapter)),before);
}
#[test]
fn funded_return_is_an_ordinary_leaf() {
    let (p,s,i)=setup(); let b=*i.notes.at(0).token; p.execute_returns(s,i,array![].span());
    let t=ITreeDispatcher { contract_address:p.contract_address }; assert_eq!(t.get_leaf_count(),2);
    assert(p.get_nullifier_spent(123),'NOT_SPENT'); assert_eq!(balance(b,p.contract_address),77);
    let cm=poseidon_hash_span(array!['RTN_NOTE_V1',get_tx_info().unbox().chain_id,p.contract_address.into(),b.into(),77,0,0,0xface].span());
    assert_eq!(t.get_node(0,1),cm); assert_eq!(p.get_delivery_digest(1),return_digest(payload(),77));
}
#[test]
fn return_redirection_is_bound() {
    let (p,s,mut i)=setup(); let b=*i.notes.at(0).token;
    i.notes=array![ReturnNote { note_id:17,token:b,minimum:70,inner:99,ciphertext:payload() }].span();
    rejected(p,s,i,'EXECUTION_INTENT');
}
#[test]
fn external_calldata_is_bound() { let (p,s,mut i)=setup(); i.calldata=array![42].span(); rejected(p,s,i,'EXECUTION_INTENT'); }
#[test]
fn executor_is_bound() { let (p,s,mut i)=setup(); i.adapter=test_address(); rejected(p,s,i,'EXECUTION_INTENT'); }
#[test]
fn expiry_is_enforced() { let (p,s,i)=setup(); start_cheat_block_number(p.contract_address,1001); rejected(p,s,i,'EXECUTION_EXPIRED'); }
#[test]
fn withdrawal_budget_is_exact() {
    let (p,mut s,i)=setup(); s.withdrawals=array![Withdrawal { recipient:i.adapter,amount:101 }].span();
    authorize(ref s,@i); rejected(p,s,i,'EXECUTION_BUDGET');
}
#[test]
fn adapter_reentry_reverts_everything() { let (p,s,i)=setup(); mode(@i,1); rejected(p,s,i,'REENTRANCY'); }
#[test]
fn missing_return_reverts_everything() { let (p,s,i)=setup(); mode(@i,2); rejected(p,s,i,'RETURN_ENCODING'); }
#[test]
fn unfunded_return_reverts_everything() { let (p,s,i)=setup(); mode(@i,3); rejected(p,s,i,'INSUFFICIENT_ALLOWANCE'); }
#[test]
fn unknown_return_id_rejected() { let (p,s,i)=setup(); mode(@i,4); rejected(p,s,i,'RETURN_ID'); }
#[test]
fn wrong_return_token_rejected() { let (p,s,i)=setup(); mode(@i,5); rejected(p,s,i,'RETURN_TOKEN'); }
#[test]
fn minimum_output_enforced_by_pool() { let (p,s,i)=setup(); mode(@i,6); rejected(p,s,i,'RETURN_MINIMUM'); }
#[test]
fn extra_return_rejected() { let (p,s,i)=setup(); mode(@i,7); rejected(p,s,i,'RETURN_ENCODING'); }
fn two_notes(token: ContractAddress, second_id: felt252) -> Span<ReturnNote> {
    array![ReturnNote { note_id:17,token,minimum:70,inner:0xface,ciphertext:payload() },
           ReturnNote { note_id:second_id,token,minimum:30,inner:0xbeef,ciphertext:payload() }].span()
}
#[test]
fn repeated_token_outputs_are_funded_individually() {
    let (p,mut s,mut i)=setup(); let b=*i.notes.at(0).token; mode(@i,7); i.notes=two_notes(b,18); authorize(ref s,@i);
    p.execute_returns(s,i,array![].span()); assert_eq!(balance(b,p.contract_address),110);
    assert_eq!(ITreeDispatcher { contract_address:p.contract_address }.get_leaf_count(),3);
}
#[test]
fn duplicate_destination_id_rejected() {
    let (p,mut s,mut i)=setup(); i.notes=two_notes(*i.notes.at(0).token,17); authorize(ref s,@i);
    rejected(p,s,i,'DUPLICATE_RETURN_ID');
}
#[test]
fn duplicate_adapter_return_rolls_back_prior_funding() {
    let (p,mut s,mut i)=setup(); mode(@i,8); i.notes=two_notes(*i.notes.at(0).token,18); authorize(ref s,@i);
    rejected(p,s,i,'RETURN_ID');
}
#[test]
fn same_input_token_refund_uses_post_spend_balance() {
    let (p,mut s,mut i)=setup(); i.notes=array![ReturnNote { note_id:17,token:s.token,minimum:70,inner:0xface,ciphertext:payload() }].span();
    i.calldata=array![17,s.token.into()].span(); authorize(ref s,@i);
    let a=s.token; p.execute_returns(s,i,array![].span()); assert_eq!(balance(a,p.contract_address),977);
}
#[test]
fn total_output_cap_includes_returns_and_change() {
    let (p,mut s,i)=setup();
    s.outputs=array![Output { commitment:1,ciphertext:payload() },Output { commitment:2,ciphertext:payload() },
        Output { commitment:3,ciphertext:payload() },Output { commitment:4,ciphertext:payload() }].span();
    authorize(ref s,@i); rejected(p,s,i,'TOTAL_OUTPUT_COUNT');
}
#[test]
fn malformed_span_count_is_rejected() {
    let (p,mut s,mut i)=setup(); i.adapter=deploy("MalformedAdapter",array![]);
    s.withdrawals=array![Withdrawal { recipient:i.adapter,amount:100 }].span(); authorize(ref s,@i);
    rejected(p,s,i,'RETURN_COUNT');
}
#[test]
fn false_proof_cannot_fund_return() {
    let (p,s,i)=setup(); p.set_verifier(deploy("MockVerifier",array![0])); rejected(p,s,i,'PROOF_REJECTED');
}
#[test]
#[feature("safe_dispatcher")]
fn execution_cannot_be_submitted_as_plain_withdrawal() {
    let (p,s,_)=setup(); let t=ITreeDispatcher { contract_address:p.contract_address }; let root=t.get_root();
    let err=IPoolSafeDispatcher { contract_address:p.contract_address }.apply_spend(s,array![].span()).unwrap_err();
    assert_eq!(*err.at(0),'EXECUTION_REQUIRED'); assert_eq!(t.get_root(),root); assert(!p.get_nullifier_spent(123),'SPENT');
}


#[test]
fn upstream_vesu_round_trip() { super::test_vesu::exercise_vault(); }
