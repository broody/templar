"""Public synthetic regression vectors; never loads runtime keys or witnesses."""
from pathlib import Path
import copy,json
from test_controlled import fixture
from protocol import signature_message
from authorization import private_to_stark_key,message_signature
base=Path(__file__).parent/'cairo/src/tests'
a,b,l,ins,outs,c=fixture()
valid={'controlled':c,'ordinary':fixture(False)[-1],'maximum_controlled':fixture(maximum=True)[-1]}
lines=['//! Generated public fixture vectors from generate_vectors.py.','use pool::statement::verify_spend;']
for name,case in valid.items():
 chunks=[]
 for i,start in enumerate(range(0,len(case['witness']),20)):
  chunk=f'{name}_chunk_{i}';chunks.append(chunk)
  lines.append(f"#[inline(never)]\nfn {chunk}() -> Array<felt252> {{ array![{','.join(map(str,case['witness'][start:start+20]))}] }}")
 construction=' '.join(f'for x in {chunk}().span() {{ w.append(*x); }};' for chunk in chunks)
 lines.append(f"#[test]\nfn valid_{name}() {{ let mut w=array![]; {construction} assert_eq!(verify_spend(w.span()),array![{','.join(map(str,case['public']))}]); }}")
invalid={}
def bad(name,offset,value,reason):
 w=list(c['witness']);w[offset]=value;invalid[name]=(w,reason)
bad('wrong_owner',13,1234,'MEMBERSHIP')
bad('viewer_not_owner',13,a.full_view.nullifier_secret,'MEMBERSHIP')
bad('wrong_policy',17,999,'MEMBERSHIP')
bad('wrong_input_controller',16,0,'CONTROLLER')
bad('wrong_output_controller',52+3,0,'CONTROLLER')
bad('wrong_output_policy',52+4,999,'OUTPUT')
bad('wrong_nullifier',18,c['witness'][18]+1,'NULLIFIER')
bad('index_overflow',19,2**32,'INDEX_RANGE')
bad('amount_overflow',15,2**128,'AMOUNT_RANGE')
bad('zero_amount',15,0,'ZERO_AMOUNT')
bad('wrong_transition',9,c['witness'][9]+1,'TRANSITION')
bad('wrong_binding',5,c['witness'][5]+1,'BINDING')
bad('changed_destination',59,c['witness'][59]+1,'TRANSITION')
bad('changed_delivery',58,c['witness'][58]+1,'TRANSITION')
bad('old_version',0,int.from_bytes(b'TEMPLAR_PUSH_POC2','big'),'VERSION')
bad('expired_format',7,2**64,'DEADLINE_RANGE')
w=list(c['witness']);w[6:10]=[0,0,0,0];w[16]=0;w[17]=0;invalid['forged_ordinary_input']=(w,'MEMBERSHIP')
w=list(valid['ordinary']['witness']);w[7]=1;invalid['ordinary_authorization']=(w,'ORDINARY_AUTH')
lines.append(f"#[inline(never)]\nfn controlled_witness() -> Array<felt252> {{ array![{','.join(map(str,c['witness']))}] }}")
for name,(w,reason) in invalid.items():
 if len(w)==len(c['witness']):
  changes=[(i,v) for i,v in enumerate(w) if v!=c['witness'][i]]
  expr='*v'
  for i,value in reversed(changes): expr=f'if i == {i} {{ {value} }} else {{ {expr} }}'
  setup=f'let base=controlled_witness(); let mut w=array![]; let mut i=0; for v in base.span() {{ w.append({expr}); i+=1; }};'
 else: setup=f"let w=array![{','.join(map(str,w))}];"
 lines.append(f"#[test]\n#[should_panic(expected: ('{reason}',))]\nfn rejects_{name}() {{ {setup} verify_spend(w.span()); }}")
(base/'golden.cairo').write_text('\n\n'.join(lines)+'\n')
# Existing transport tests remain ordinary regressions with the new ABI.
p=base/'test_push.cairo';s=p.read_text().replace('p.deposit(token,100,0xbeef,payload())','p.deposit(token,100,contract_address_const::<0>(),0,0xbeef,payload())')
s=s.replace('token: *t.contract_address, binding: 0, nullifiers:', 'token: *t.contract_address, binding: 0, controller: contract_address_const::<0>(), deadline: 0, nonce: 0, transition: 0, sig_r: 0, sig_s: 0, nullifiers:')
p.write_text(s)
pub=private_to_stark_key(1234);r,s=message_signature(42,1234);wr,ws=message_signature(42,999)
ctrl=f'''use starknet::{{ContractAddress,contract_address_const,get_tx_info,SyscallResultTrait}};
use snforge_std::{{declare,ContractClassTrait,DeclareResultTrait,test_address,start_cheat_block_number}};
use pool::spend::{{IControllerDispatcher,IControllerDispatcherTrait,Spend,Output,Withdrawal,PROTOCOL_VERSION,compute_binding,IERC20Dispatcher,IERC20DispatcherTrait}};
use pool::pool::{{IPoolDispatcher,IPoolDispatcherTrait}};
use pool::tree::{{ITreeDispatcher,ITreeDispatcherTrait}};
fn deploy(name: ByteArray,data: Array<felt252>) -> ContractAddress {{
 let (a,_)=declare(name).unwrap_syscall().contract_class().deploy(@data).unwrap_syscall(); a
}}
fn ctrl() -> IControllerDispatcher {{ IControllerDispatcher {{ contract_address: deploy("SignatureController",array![{pub}]) }} }}
#[test]
fn real_stark_signature_verifies() {{ assert(ctrl().verify_transition(42,{r},{s}),'SIGNATURE'); }}
#[test]
fn wrong_key_signature_fails() {{ assert(!ctrl().verify_transition(42,{wr},{ws}),'WRONG_KEY'); }}
#[test]
fn changed_transition_fails() {{ assert(!ctrl().verify_transition(43,{r},{s}),'CHANGED'); }}
#[test]
fn zero_signature_fails() {{ assert(!ctrl().verify_transition(42,0,0),'ZERO'); }}
#[test]
fn out_of_order_scalar_fails() {{ assert(!ctrl().verify_transition(42,{r},core::ec::stark_curve::ORDER),'ORDER'); }}
#[test]
fn canonical_message_mask_matches_signer() {{ assert(ctrl().verify_transition(42+0x800000000000000000000000000000000000000000000000000000000000000,{r},{s}),'MASK'); }}
fn setup(deadline: u64,r: felt252,sig: felt252) -> (IPoolDispatcher,Spend) {{
 let controller=ctrl().contract_address;
 let verifier=deploy("MockVerifier",array![1]);
 let p=IPoolDispatcher {{ contract_address: deploy("Pool",array![test_address().into(),verifier.into()]) }};
 let t=IERC20Dispatcher {{ contract_address: deploy("E2EToken",array![test_address().into(),10000,0]) }};
 t.approve(p.contract_address,10000);
 p.deposit(t.contract_address,100,controller,77,99,array![1,2,3,4,5,6,7,8,9,10].span());
 let mut spend=Spend {{ version: PROTOCOL_VERSION,chain: get_tx_info().unbox().chain_id,pool: p.contract_address,
 root: ITreeDispatcher {{ contract_address: p.contract_address }}.get_root(),token: t.contract_address,binding: 0,
 controller,deadline,nonce: 1,transition: 42,sig_r: r,sig_s: sig,nullifiers: array![123].span(),
 outputs: array![Output {{ commitment: 456,ciphertext: array![1,2,3,4,5,6,7,8,9,10].span() }}].span(),
 withdrawals: array![Withdrawal {{ recipient: contract_address_const::<0xb0b>(),amount: 40 }}].span() }};
 spend.binding=compute_binding(@spend); start_cheat_block_number(p.contract_address,10); (p,spend)
}}
#[test]
fn real_controller_signature_gates_mock_proof_pool() {{ let (p,s)=setup(10,{r},{s}); p.apply_spend(s,array![].span()); assert(p.get_nullifier_spent(123),'NF'); }}
#[test]
#[should_panic(expected: ('CONTROL_SIGNATURE',))]
fn pool_rejects_missing_signature() {{ let (p,s)=setup(10,0,0); p.apply_spend(s,array![].span()); }}
#[test]
#[should_panic(expected: ('CONTROL_SIGNATURE',))]
fn pool_rejects_wrong_signer() {{ let (p,s)=setup(10,{wr},{ws}); p.apply_spend(s,array![].span()); }}
#[test]
#[should_panic(expected: ('CONTROL_EXPIRED',))]
fn pool_rejects_expired_approval() {{ let (p,s)=setup(9,{r},{s}); p.apply_spend(s,array![].span()); }}
'''
(base/'test_controller.cairo').write_text(ctrl)
p=base.parent/'tests.cairo';s=p.read_text()
if 'mod test_controller;' not in s:p.write_text(s+'\nmod test_controller;\n')
print(f'{len(valid)} valid, {len(invalid)} rejected statement vectors and real ECDSA controller guards generated')
