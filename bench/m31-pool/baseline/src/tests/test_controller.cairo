use starknet::{ContractAddress,contract_address_const,get_tx_info,SyscallResultTrait};
use snforge_std::{declare,ContractClassTrait,DeclareResultTrait,test_address,start_cheat_block_number};
use pool::spend::{IControllerDispatcher,IControllerDispatcherTrait,Spend,Output,Withdrawal,PROTOCOL_VERSION,compute_binding,IERC20Dispatcher,IERC20DispatcherTrait};
use pool::pool::{IPoolDispatcher,IPoolDispatcherTrait};
use pool::tree::{ITreeDispatcher,ITreeDispatcherTrait};
fn deploy(name: ByteArray,data: Array<felt252>) -> ContractAddress {
 let (a,_)=declare(name).unwrap_syscall().contract_class().deploy(@data).unwrap_syscall(); a
}
fn ctrl() -> IControllerDispatcher { IControllerDispatcher { contract_address: deploy("SignatureController",array![883045738439352841478194533192765345509759306772397516907181243450667673002]) } }
#[test]
fn real_stark_signature_verifies() { assert(ctrl().verify_transition(42,943845806731730586427059082188914871482648255572201933581675116123518658886,1481546451119593496920184491193457775891110567537411821121912711656311985636),'SIGNATURE'); }
#[test]
fn wrong_key_signature_fails() { assert(!ctrl().verify_transition(42,2586454569898190831603383492599903359954710491414079180596881754989243808804,3598193957391010199371527204481738361951388074972816622439351264942528111159),'WRONG_KEY'); }
#[test]
fn changed_transition_fails() { assert(!ctrl().verify_transition(43,943845806731730586427059082188914871482648255572201933581675116123518658886,1481546451119593496920184491193457775891110567537411821121912711656311985636),'CHANGED'); }
#[test]
fn zero_signature_fails() { assert(!ctrl().verify_transition(42,0,0),'ZERO'); }
#[test]
fn out_of_order_scalar_fails() { assert(!ctrl().verify_transition(42,943845806731730586427059082188914871482648255572201933581675116123518658886,core::ec::stark_curve::ORDER),'ORDER'); }
#[test]
fn canonical_message_mask_matches_signer() { assert(ctrl().verify_transition(42+0x800000000000000000000000000000000000000000000000000000000000000,943845806731730586427059082188914871482648255572201933581675116123518658886,1481546451119593496920184491193457775891110567537411821121912711656311985636),'MASK'); }
fn setup(deadline: u64,r: felt252,sig: felt252) -> (IPoolDispatcher,Spend) {
 let controller=ctrl().contract_address;
 let verifier=deploy("MockVerifier",array![1]);
 let p=IPoolDispatcher { contract_address: deploy("Pool",array![test_address().into(),verifier.into()]) };
 let t=IERC20Dispatcher { contract_address: deploy("E2EToken",array![test_address().into(),10000,0]) };
 t.approve(p.contract_address,10000);
 p.deposit(t.contract_address,100,controller,77,99,array![1,2,3,4,5,6,7,8,9,10].span());
 let mut spend=Spend { version: PROTOCOL_VERSION,chain: get_tx_info().unbox().chain_id,pool: p.contract_address,
 root: ITreeDispatcher { contract_address: p.contract_address }.get_root(),token: t.contract_address,binding: 0,
 controller,deadline,nonce: 1,transition: 42,sig_r: r,sig_s: sig,nullifiers: array![123].span(),
 outputs: array![Output { commitment: 456,ciphertext: array![1,2,3,4,5,6,7,8,9,10].span() }].span(),
 withdrawals: array![Withdrawal { recipient: contract_address_const::<0xb0b>(),amount: 40 }].span() };
 spend.binding=compute_binding(@spend); start_cheat_block_number(p.contract_address,10); (p,spend)
}
#[test]
fn real_controller_signature_gates_mock_proof_pool() { let (p,s)=setup(10,943845806731730586427059082188914871482648255572201933581675116123518658886,1481546451119593496920184491193457775891110567537411821121912711656311985636); p.apply_spend(s,array![].span()); assert(p.get_nullifier_spent(123),'NF'); }
#[test]
#[should_panic(expected: ('CONTROL_SIGNATURE',))]
fn pool_rejects_missing_signature() { let (p,s)=setup(10,0,0); p.apply_spend(s,array![].span()); }
#[test]
#[should_panic(expected: ('CONTROL_SIGNATURE',))]
fn pool_rejects_wrong_signer() { let (p,s)=setup(10,2586454569898190831603383492599903359954710491414079180596881754989243808804,3598193957391010199371527204481738361951388074972816622439351264942528111159); p.apply_spend(s,array![].span()); }
#[test]
#[should_panic(expected: ('CONTROL_EXPIRED',))]
fn pool_rejects_expired_approval() { let (p,s)=setup(9,943845806731730586427059082188914871482648255572201933581675116123518658886,1481546451119593496920184491193457775891110567537411821121912711656311985636); p.apply_spend(s,array![].span()); }
