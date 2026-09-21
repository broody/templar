//! Integration driver, NOT a PROOF1 verifier. The parent harness must first run the
//! unchanged original native verifier and create ../fixtures/verified-facts.txt from
//! its accepted outputs. Missing input is a hard test failure; no mock success exists.
//! snforge only supplies those externally verified facts to this contract execution.
use super::{Root,Transition,EMPTY_ROOT,IAppendPoolDispatcher,IAppendPoolDispatcherTrait,IAppendPoolSafeDispatcher,IAppendPoolSafeDispatcherTrait};
use starknet::ContractAddress;
use snforge_std::{declare,ContractClassTrait,DeclareResultTrait,start_cheat_proof_facts,start_cheat_block_number,start_cheat_chain_id};
use snforge_std::fs::{FileTrait,read_txt};
#[derive(Copy,Drop,Serde)]
struct VerifiedCase { name: felt252,facts: Span<felt252>,transition: Transition }
#[derive(Copy,Drop,Serde)]
struct Fixture {
    schema: felt252,
    chain_id: felt252,
    pool: ContractAddress,
    statement: ContractAddress,
    statement_class: felt252,
    current_block: u64,
    max_age: u64,
    queue: Span<felt252>,
    cases: Span<VerifiedCase>,
}
fn fixture() -> Fixture {
    let file=FileTrait::new("../fixtures/verified-facts.txt");
    let values=read_txt(@file);
    let mut values=values.span();
    let fixture: Fixture=Serde::deserialize(ref values).expect('VERIFIED_FIXTURE_REQUIRED');
    assert(values.is_empty(),'FIXTURE_TRAILING');
    assert(fixture.schema=='M31_VERIFIED_FACTS_V1','FIXTURE_SCHEMA');
    assert(fixture.queue.len()>=3 && fixture.cases.len()==5,'FIXTURE_CASES');
    fixture
}
fn case(fixture: Fixture,name: felt252) -> VerifiedCase {
    let mut found: Option<VerifiedCase>=None;
    for entry in fixture.cases {
        if *entry.name==name { assert(found.is_none(),'DUPLICATE_CASE'); found=Some(*entry); }
    };
    found.expect('MISSING_CASE')
}
fn setup(fixture: Fixture,address: ContractAddress,statement: ContractAddress,statement_class: felt252) -> IAppendPoolDispatcher {
    let mut constructor=array![];
    EMPTY_ROOT.serialize(ref constructor); 0_u64.serialize(ref constructor);
    fixture.queue.serialize(ref constructor); statement.serialize(ref constructor);
    statement_class.serialize(ref constructor); fixture.max_age.serialize(ref constructor);
    let class=declare("PublicAppendPool").unwrap().contract_class();
    let (deployed,_)=class.deploy_at(@constructor,address).unwrap();
    assert(deployed==address,'POOL_ADDRESS');
    start_cheat_chain_id(address,fixture.chain_id);
    start_cheat_block_number(address,fixture.current_block);
    IAppendPoolDispatcher {contract_address:address}
}
fn fresh(fixture: Fixture) -> IAppendPoolDispatcher { setup(fixture,fixture.pool,fixture.statement,fixture.statement_class) }
fn apply(pool: IAppendPoolDispatcher,entry: VerifiedCase) {
    start_cheat_proof_facts(pool.contract_address,entry.facts);
    pool.apply_append(entry.transition);
    assert_eq!(pool.state(),(entry.transition.new_root,entry.transition.new_count));
    let mut index=entry.transition.old_count;
    for _ in entry.transition.commitments { assert_eq!(pool.queued(index),0); index+=1; };
}
#[feature("safe_dispatcher")]
fn rejected(pool: IAppendPoolDispatcher,fixture: Fixture,entry: VerifiedCase,reason: felt252) {
    let state=pool.state();
    let mut queue=array![];
    for index in 0_u32..fixture.queue.len() { queue.append(pool.queued(index.into())); };
    start_cheat_proof_facts(pool.contract_address,entry.facts);
    let error=IAppendPoolSafeDispatcher {contract_address:pool.contract_address}.apply_append(entry.transition).expect_err('UNEXPECTED_ACCEPT');
    let mut found=false;
    for value in error.span() { if *value==reason { found=true; } };
    assert(found,'WRONG_REJECTION');
    assert_eq!(pool.state(),state);
    for index in 0_u32..fixture.queue.len() { assert_eq!(pool.queued(index.into()),*queue.at(index)); };
}
fn changed_fact(entry: VerifiedCase,index: usize,value: felt252) -> VerifiedCase {
    let mut facts=array![];
    for i in 0_usize..entry.facts.len() { facts.append(if i==index { value } else { *entry.facts.at(i) }); };
    VerifiedCase {name:entry.name,facts:facts.span(),transition:entry.transition}
}
#[test]
fn verified_single_applies() { let f=fixture(); apply(fresh(f),case(f,'single')); }
#[test]
fn verified_batch_applies() { let f=fixture(); apply(fresh(f),case(f,'batch')); }
#[test]
fn verified_replay_preserves_state() {
    let f=fixture(); let p=fresh(f); let entry=case(f,'single'); apply(p,entry); rejected(p,f,entry,'STALE_ROOT');
}
#[test]
fn verified_competing_branch_and_refreshed_success() {
    let f=fixture(); let p=fresh(f);
    apply(p,case(f,'single')); apply(p,case(f,'branch12'));
    rejected(p,f,case(f,'branch13'),'STALE_ROOT');
    apply(p,case(f,'refresh123'));
}
#[test]
fn verified_changed_new_root_rejected() {
    let f=fixture(); let mut entry=case(f,'batch');
    entry.transition.new_root=Root {low:entry.transition.new_root.low,high:((entry.transition.new_root.high.try_into().unwrap()+1_u64)%0x7fffffff).into()};
    rejected(fresh(f),f,entry,'PROOF_BINDING');
}
#[test]
fn verified_changed_new_count_rejected() {
    let f=fixture(); let mut entry=case(f,'batch'); entry.transition.new_count+=1;
    rejected(fresh(f),f,entry,'NEW_COUNT');
}
#[test]
fn verified_reordered_commitments_rejected() {
    let f=fixture(); let mut entry=case(f,'batch'); let leaves=entry.transition.commitments;
    assert(leaves.len()==2 && *leaves.at(0)!=*leaves.at(1),'BATCH_FIXTURE');
    entry.transition.commitments=array![*leaves.at(1),*leaves.at(0)].span();
    rejected(fresh(f),f,entry,'ORDERED_COMMITMENT');
}
#[test]
fn verified_wrong_chain_rejected() {
    let f=fixture(); let p=fresh(f); start_cheat_chain_id(p.contract_address,f.chain_id+1);
    rejected(p,f,case(f,'batch'),'PROOF_BINDING');
}
#[test]
fn verified_wrong_pool_rejected() {
    let f=fixture(); let address: ContractAddress=if f.pool.into()==0x123456 { 0x123457.try_into().unwrap() } else { 0x123456.try_into().unwrap() };
    rejected(setup(f,address,f.statement,f.statement_class),f,case(f,'batch'),'PROOF_BINDING');
}
#[test]
fn verified_wrong_account_rejected() {
    let f=fixture(); let address: ContractAddress=if f.statement.into()==0x123456 { 0x123457.try_into().unwrap() } else { 0x123456.try_into().unwrap() };
    rejected(setup(f,f.pool,address,f.statement_class),f,case(f,'batch'),'PROOF_BINDING');
}
#[test]
fn verified_wrong_class_rejected() {
    let f=fixture(); rejected(setup(f,f.pool,f.statement,f.statement_class+1),f,case(f,'batch'),'PROOF_BINDING');
}
#[test]
fn verified_wrong_program_rejected() {
    let f=fixture(); rejected(fresh(f),f,changed_fact(case(f,'batch'),2,1),'OS_PROGRAM');
}
#[test]
fn verified_wrong_message_rejected() {
    let f=fixture(); let entry=case(f,'batch'); rejected(fresh(f),f,changed_fact(entry,8,*entry.facts.at(8)+1),'PROOF_BINDING');
}
#[test]
fn verified_missing_facts_rejected() {
    let f=fixture(); let mut entry=case(f,'batch'); entry.facts=[].span(); rejected(fresh(f),f,entry,'PROOF_FACTS_LENGTH');
}
