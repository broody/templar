use starknet::{ContractAddress,SyscallResultTrait,get_tx_info};
use snforge_std::{declare,ContractClassTrait,DeclareResultTrait,test_address};
use desktop::pool::{IBenchPoolDispatcher,IBenchPoolDispatcherTrait,IERC20Dispatcher,IERC20DispatcherTrait};
fn deploy<T,+Serde<T>>(name:ByteArray,args:@T)->ContractAddress {
    let class=declare(name).unwrap_syscall().contract_class();let mut data=array![];Serde::serialize(args,ref data);
    let (address,_)=class.deploy(@data).unwrap_syscall();address
}
fn setup()->(ContractAddress,ContractAddress){
    let token=deploy("MockERC20",@(test_address(),1100_u256));
    let verifier=deploy("UltraKeccakZKHonkVerifier",@());
    let pool=deploy("BenchPool",@(token,verifier));
    (token,pool)
}
#[test]
fn export_context(){
    let (token,pool)=setup();
    let t:felt252=token.into();let p:felt252=pool.into();let r:felt252=test_address().into();
    println!("BENCH_CONTEXT {} {} {} {}",get_tx_info().unbox().chain_id,p,t,r);
}

use desktop::flow_data::*;
use snforge_std::fs::{FileTrait,read_txt};
fn funded()->(IERC20Dispatcher,IBenchPoolDispatcher){
    let (token,pool)=setup();
    assert_eq!(token,EXPECTED_TOKEN.try_into().unwrap());assert_eq!(pool,EXPECTED_POOL.try_into().unwrap());
    let t=IERC20Dispatcher{contract_address:token};let p=IBenchPoolDispatcher{contract_address:pool};
    assert!(t.approve(pool,1100));
    p.deposit(700,INNER_0);p.deposit(400,INNER_1);
    assert_eq!(p.get_root(),ALICE_ROOT);
    (t,p)
}
fn alice_pay(p:IBenchPoolDispatcher){
    let proof=read_txt(@FileTrait::new("tests/alice.txt"));
    p.spend(ALICE_ROOT,ALICE_NULLIFIERS.span(),ALICE_OUTPUTS.span(),40,test_address(),proof.span());
}
#[test]
fn funded_baseline(){let (_,p)=funded();assert_eq!(p.get_root(),ALICE_ROOT);}
#[test]
#[fork(url: "https://api.zan.top/public/starknet-sepolia/rpc/v0_10", block_number: 15348508)]
fn alice_payment(){
    let (t,p)=funded();alice_pay(p);
    assert_eq!(p.get_root(),BOB_ROOT);assert_eq!(t.balance_of(test_address()),40);
    assert!(p.get_spent(*ALICE_NULLIFIERS.span().at(0)));
}
#[test]
#[fork(url: "https://api.zan.top/public/starknet-sepolia/rpc/v0_10", block_number: 15348508)]
fn deposit_payment_withdrawal(){
    let (t,p)=funded();alice_pay(p);
    let proof=read_txt(@FileTrait::new("tests/bob.txt"));
    p.spend(BOB_ROOT,BOB_NULLIFIERS.span(),BOB_OUTPUTS.span(),600,test_address(),proof.span());
    assert_eq!(t.balance_of(test_address()),640);assert_eq!(t.balance_of(p.contract_address),460);
    assert!(p.get_spent(*BOB_NULLIFIERS.span().at(0)));
}
#[test]
#[should_panic(expected: ('DOUBLE_SPEND',))]
#[fork(url: "https://api.zan.top/public/starknet-sepolia/rpc/v0_10", block_number: 15348508)]
fn replay_rejected(){let (_,p)=funded();alice_pay(p);alice_pay(p);}
#[test]
#[should_panic]
#[fork(url: "https://api.zan.top/public/starknet-sepolia/rpc/v0_10", block_number: 15348508)]
fn redirected_withdrawal_rejected(){
    let (_,p)=funded();let proof=read_txt(@FileTrait::new("tests/alice.txt"));
    p.spend(ALICE_ROOT,ALICE_NULLIFIERS.span(),ALICE_OUTPUTS.span(),40,0xdead.try_into().unwrap(),proof.span());
}
