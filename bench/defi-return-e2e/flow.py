"""Ordinary-note native proofs, adversarial rollback, real Ekubo, and fresh recovery."""
from common import *
from protocol import *
from encoding import encode_spend,encode_swap,encode_deposit
from proving import prove_case
from sync import canonical_checkpoint
from dataclasses import asdict
import secrets

D=json.loads((RUN/'deployment.json').read_text())
A=int(D['token_a'],16);B=int(D['token_b'],16);POOL=int(D['pool'],16)
progress_file=RUN/'private-progress.json'
if progress_file.exists():progress=json.loads(progress_file.read_text())
else:
 progress={'stage':0,'negative_tests':[]}
 for who in ['alice','bob']:
  folder=RUN/'backups'/who;folder.mkdir(parents=True,exist_ok=True)
  seed=secrets.token_bytes(32);(folder/'seed.txt').write_text(seed.hex()+'\n')
  os.chmod(folder/'seed.txt',0o600)
  w=Wallet.restore(seed,CHAIN,POOL);a=w.address
  save(folder/'address.json',dict(chain=a.chain,pool=a.pool,receiver=a.receiver,encryption_key=a.encryption_key.hex()))
  save(folder/'full-view.json',w.full_view.export())
 save(progress_file,progress)

def checkpoint(stage=None):
 if stage is not None:progress['stage']=stage
 save(progress_file,progress)
def wallet(who):return Wallet.restore(bytes.fromhex((RUN/'backups'/who/'seed.txt').read_text().strip()),CHAIN,POOL)
def events(c):return [Event(x['commitment'],bytes.fromhex(x['ciphertext']),x['digest']) for x in c['events']]
def read_intent(c):
 i=dict(c['swap']);i['ciphertext']=bytes.fromhex(i['ciphertext']);return i
def snapshot():
 block=rpc('starknet_getBlockWithTxHashes',{'block_id':'latest'});bid={'block_hash':block['block_hash']}
 jobs=[('root',D['pool'],'get_root',[]),('leaf_count',D['pool'],'get_leaf_count',[])]
 for token in ['token_a','token_b']:
  for owner in ['pool','mock','adapter','relayer']:
   jobs.append((token+'_'+owner,D[token],'balance_of',[D[owner]]))
 for token in ['token_a','token_b']:
  jobs.append((token+'_core',D[token],'balance_of',[D['ekubo']['core']['address']]))
 def read(j):
  name,address,method,data=j;v=call(address,method,data,block=bid)
  return name,v[0]+((v[1]<<128) if len(v)==2 else 0)
 with ThreadPoolExecutor(4) as executor:v=dict(executor.map(read,jobs))
 return v
def restore(who,label,view=False):
 folder=RUN/'backups'/who
 args=['python3',str(HERE/'restore.py'),'--label',label,'--address-file',str(folder/'address.json')]
 args+=['--view-file',str(folder/'full-view.json')] if view else ['--seed-file',str(folder/'seed.txt')]
 subprocess.run(args,cwd=HERE,env=ENV,check=True)
 dest=RUN/'wallets'/label
 summary=json.loads((dest/'summary.json').read_text())
 save(RUN/'results'/('recovery-'+label+'.json'),{'summary':summary,'sync':json.loads((dest/'sync.json').read_text())})
 return json.loads((dest/'private-recovered.json').read_text()),summary
def new_case(name,token,outputs,withdrawals=None,swap=None,restored=None,input_indices=None):
 path=RUN/'cases'/name/'private-case.json'
 if path.exists():return json.loads(path.read_text())
 w=wallet('alice')
 if restored is None:
  report,_,_,meta=canonical_checkpoint(D,w.full_view)
  assert report.history_complete
  notes,spent,tree=report.notes,report.spent_indices,report.tree
  save(RUN/'results'/('sync-'+name+'.json'),meta)
 else:
  notes={int(i):Note(**n) for i,n in restored['notes'].items()};spent=restored['spent_indices'];tree=Tree()
  for cm in restored['commitments']:tree.insert(cm)
 ins=[(n,w.spend_key,i) for i,n in sorted(notes.items()) if i not in spent and n.token==token and (input_indices is None or i in input_indices)]
 assert ins and all(n.controller==0 for n,_,_ in ins)
 outs=[send(wallet(to).address,token,amt) for to,amt in outputs]
 if swap:
  inner,cipher=prepare_return(w.address,swap['out_token'])
  swap=dict(swap,inner=inner,policy=0,ciphertext=cipher,expiry=rpc('starknet_blockNumber',{})+1800)
  intent=swap_hash(CHAIN,POOL,token,0,**swap)
  withdrawals=[(swap['adapter'],swap['amount'])]
 else:intent=0
 c=make_case(ins,outs,withdrawals or [],tree,intent=intent)
 validate_case(c);c['name']=name;c['input_indices']=[i for _,_,i in ins]
 c['events']=[dict(commitment=e.commitment,ciphertext=e.ciphertext.hex(),digest=e.digest) for _,e in outs]
 c['calldata']=encode_swap(c,[e for _,e in outs],swap) if swap else encode_spend(c,[e for _,e in outs])
 c['method']='execute_swap' if swap else 'apply_spend'
 if swap:c['swap']=dict(swap,ciphertext=swap['ciphertext'].hex())
 save(path,c)
 save(path.parent/'public-call.json',{'calldata':[hex(x) for x in c['calldata']],'method':c['method'],
      'shape':[len(ins),len(outs),len(withdrawals or [])],'public_values':[hex(x) for x in c['public']]})
 return c
def prove(c):return prove_case(c['name'],c['witness'],c['public'],D)
def submit(c):return proof_invoke(c['name'],D,c['calldata'],RUN/'cases'/c['name'],method=c['method'])
def negative(name,c,calldata,reason,*,method='execute_swap',spent=False):
 if name in progress['negative_tests']:return
 before=snapshot()
 proof_invoke(name,D,calldata,RUN/'cases'/c['name'],expected='REVERTED',reason=reason,method=method)
 after=snapshot();assert before==after,(name,'state changed')
 assert [call(D['pool'],'get_nullifier_spent',[nf])[0] for nf in c['nullifiers']]==[int(spent)]*len(c['nullifiers'])
 save(RUN/'results'/('negative-'+name+'.json'),{'reason':reason,'unchanged_pool_and_token_state':True,'nullifiers_checked':True,'before':before,'after':after})
 progress['negative_tests'].append(name);checkpoint()

if progress['stage']==0:
 p=RUN/'private-deposit.json'
 if not p.exists():
  n,e=send(wallet('alice').address,A,5000);save(p,{'calldata':encode_deposit(n,e)})
 invoke('deposit-alice',D['pool'],'deposit',json.loads(p.read_text())['calldata'])
 checkpoint(1)
if progress['stage']==1:
 c=new_case('mock-swap',A,[('alice',4000)],swap=dict(adapter=int(D['mock'],16),out_token=B,amount=1000,minimum=900,route=[42]))
 prove(c)
 bad=list(c['witness']);bad[10]+=1
 prove_case('tampered-intent-statement',bad,c['public'],D,expect_error='BINDING')
 negative('isolated-withdrawal',c,encode_spend(c,events(c)),'SWAP_ENTRY_REQUIRED',method='apply_spend')
 stripped=copy.deepcopy(c);stripped['intent']=0
 stripped['public'][7]=binding(CHAIN,POOL,c['public'][3],A,c['nullifiers'],
     [tuple(x) for x in c['outputs']],[tuple(x) for x in c['withdrawals']],intent=0)
 negative('stripped-intent-proof',c,encode_spend(stripped,events(c)),'PROOF_BINDING',method='apply_spend')
 for name,field,value in [('redirected-return','inner',123),('changed-minimum','minimum',1),('changed-token','out_token',A),('changed-route','route',[43])]:
  i=read_intent(c);i[field]=value
  negative(name,c,encode_swap(c,events(c),i),'SWAP_INTENT')
 if 'slippage-rollback' not in progress['negative_tests']:
  invoke('mock-low-fill',D['mock'],'configure',[899,0])
  negative('slippage-rollback',c,c['calldata'],'MOCK_SLIPPAGE')
 if 'reentrant-rollback' not in progress['negative_tests']:
  invoke('mock-reentrant',D['mock'],'configure',[977,1])
  negative('reentrant-rollback',c,c['calldata'],'REENTRANCY')
 if 'unfunded-rollback' not in progress['negative_tests']:
  invoke('mock-unfunded',D['mock'],'configure',[977,2])
  negative('unfunded-rollback',c,c['calldata'],'INSUFFICIENT_ALLOWANCE')
 invoke('mock-final-fill',D['mock'],'configure',[977,0])
 submit(c)
 negative('replay-swap',c,c['calldata'],'NULLIFIER_USED',spent=True)
 data,summary=restore('alice','after-mock')
 assert summary['balances']=={hex(A):4000,hex(B):977},summary['balances']
 _,watch=restore('alice','watch-after-mock',view=True);assert watch['balances']==summary['balances']
 save(RUN/'results/state-after-mock.json',snapshot());checkpoint(2)
if progress['stage']==2:
 data=json.loads((RUN/'wallets/after-mock/private-recovered.json').read_text())
 c=new_case('restored-return-payment',B,[('bob',900),('alice',77)],restored=data)
 prove(c);submit(c)
 _,bob=restore('bob','bob-received');assert bob['balances']=={hex(B):900}
 checkpoint(3)
if progress['stage']==3:
 c=new_case('ekubo-swap',A,[('alice',3000)],swap=dict(adapter=int(D['adapter'],16),out_token=B,amount=1000,minimum=900,route=D['route']))
 prove(c);submit(c)
 data,summary=restore('alice','after-ekubo')
 returned=[(int(i),n) for i,n in data['notes'].items() if n['token']==B and int(i) not in data['spent_indices'] and n['amount']!=77]
 assert len(returned)==1 and returned[0][1]['amount']>=900
 progress['ekubo_return_index']=returned[0][0];progress['ekubo_return_amount']=returned[0][1]['amount']
 save(RUN/'results/state-after-ekubo.json',snapshot());checkpoint(4)
if progress['stage']==4:
 data=json.loads((RUN/'wallets/after-ekubo/private-recovered.json').read_text())
 amount=progress['ekubo_return_amount']
 c=new_case('restored-ekubo-withdrawal',B,[],withdrawals=[(int(ACCOUNT,16),amount)],restored=data,input_indices=[progress['ekubo_return_index']])
 prove(c);submit(c)
 _,alice=restore('alice','final-alice');assert alice['balances']=={hex(A):3000,hex(B):77}
 state=snapshot();assert state['token_a_pool']==3000 and state['token_b_pool']==977
 save(RUN/'results/state-final.json',state);checkpoint(5)

summary={'status':'PASS','ordinary_notes_only':True,'stage':progress['stage'],'deployment':D,
 'negative_tests':progress['negative_tests'],'ekubo_return_amount':progress['ekubo_return_amount'],
 'mock_fill_before_proving':950,'mock_fill_at_settlement':977,
 'final_state':json.loads((RUN/'results/state-final.json').read_text()),'proofs':{},'transactions':{}}
names=['mock-swap','restored-return-payment','ekubo-swap','restored-ekubo-withdrawal']
for name in names:summary['proofs'][name]=json.loads((RUN/'cases'/name/'benchmark.json').read_text())
for name in ['deposit-alice',*names,*progress['negative_tests']]:
 r=json.loads((RUN/'results'/name/'receipt.json').read_text())
 summary['transactions'][name]={k:r.get(k) for k in ['transaction_hash','execution_status','block_number','actual_fee','execution_resources','revert_reason']}
save(RUN/'results/summary.json',summary)
print('ORDINARY NOTE / ATOMIC SWAP / REAL EKUBO / SEED RECOVERY PASS',flush=True)
