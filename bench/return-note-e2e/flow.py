"""Native proof -> unmodified upstream adapter -> fresh recovery -> private payment."""
from common import *
from protocol import *
from encoding import encode_spend,encode_execution,encode_deposit
from proving import prove_case
from sync import canonical_checkpoint
import secrets

D=json.loads((RUN/'deployment.json').read_text())
A=int(D['token_a'],16);B=int(D['token_b'],16);POOL=int(D['pool'],16)
progress_file=RUN/'private-progress.json'
if progress_file.exists(): progress=json.loads(progress_file.read_text())
else:
 progress={'stage':0,'negative_tests':[]}
 for who in ['alice','bob']:
  folder=RUN/'backups'/who;folder.mkdir(parents=True,exist_ok=True)
  seed=secrets.token_bytes(32);(folder/'seed.txt').write_text(seed.hex()+'\n');os.chmod(folder/'seed.txt',0o600)
  w=Wallet.restore(seed,CHAIN,POOL);a=w.address
  save(folder/'address.json',dict(chain=a.chain,pool=a.pool,receiver=a.receiver,encryption_key=a.encryption_key.hex()))
  save(folder/'full-view.json',w.full_view.export())
 save(progress_file,progress)

def checkpoint(stage=None):
 if stage is not None: progress['stage']=stage
 save(progress_file,progress)
def wallet(who):return Wallet.restore(bytes.fromhex((RUN/'backups'/who/'seed.txt').read_text().strip()),CHAIN,POOL)
def events(c):return [Event(x['commitment'],bytes.fromhex(x['ciphertext']),x['digest']) for x in c['events']]
def read_intent(c):
 i=copy.deepcopy(c['execution'])
 for n in i['notes']:n['ciphertext']=bytes.fromhex(n['ciphertext'])
 return i
def snapshot():
 block=rpc('starknet_getBlockWithTxHashes',{'block_id':'latest'});bid={'block_hash':block['block_hash']}
 jobs=[('root',D['pool'],'get_root',[]),('leaf_count',D['pool'],'get_leaf_count',[])]
 for token in ['token_a','token_b']:
  for owner in ['pool','adapter','relayer']:
   jobs.append((token+'_'+owner,D[token],'balance_of',[D[owner]]))
  jobs.append((token+'_core',D[token],'balance_of',[D['ekubo']['core']['address']]))
 def read(j):
  name,address,method,data=j;v=call(address,method,data,block=bid)
  return name,v[0]+((v[1]<<128) if len(v)==2 else 0)
 with ThreadPoolExecutor(4) as executor:return dict(executor.map(read,jobs))
def restore(who,label,view=False):
 folder=RUN/'backups'/who
 args=['python3',str(HERE/'restore.py'),'--label',label,'--address-file',str(folder/'address.json')]
 args+=['--view-file',str(folder/'full-view.json')] if view else ['--seed-file',str(folder/'seed.txt')]
 subprocess.run(args,cwd=HERE,env=ENV,check=True)
 dest=RUN/'wallets'/label;summary=json.loads((dest/'summary.json').read_text())
 save(RUN/'results'/('recovery-'+label+'.json'),{'summary':summary,'sync':json.loads((dest/'sync.json').read_text())})
 return json.loads((dest/'private-recovered.json').read_text()),summary
def new_case(name,token,outputs,*,execution=False,restored=None):
 path=RUN/'cases'/name/'private-case.json'
 if path.exists():return json.loads(path.read_text())
 w=wallet('alice')
 if restored is None:
  report,_,_,meta=canonical_checkpoint(D,w.full_view);assert report.history_complete
  notes,spent,tree=report.notes,report.spent_indices,report.tree
  save(RUN/'results'/('sync-'+name+'.json'),meta)
 else:
  notes={int(i):Note(**n) for i,n in restored['notes'].items()};spent=restored['spent_indices'];tree=Tree()
  for cm in restored['commitments']:tree.insert(cm)
 ins=[(n,w.spend_key,i) for i,n in sorted(notes.items()) if i not in spent and n.token==token]
 outs=[send(wallet(to).address,token,amount) for to,amount in outputs]
 withdrawals=[];intent_hash=0
 if execution:
  inner,cipher=prepare_return(w.address,B);note_id=scalar()
  # Exact upstream ABI: router, TokenAmount {token, i129 {mag, sign}}, PoolKey,
  # minimum_received:u256, skip_ahead:u128, note_id.
  calldata=[int(D['ekubo']['router']['address'],16),A,1000,0,*D['pool_key'],900,0,0,note_id]
  intent=dict(adapter=int(D['adapter'],16),amount=1000,expiry=rpc('starknet_blockNumber',{})+1800,
              calldata=calldata,notes=[dict(note_id=note_id,token=B,minimum=900,inner=inner,ciphertext=cipher)])
  intent_hash=execution_hash(CHAIN,POOL,token,**intent);withdrawals=[(intent['adapter'],intent['amount'])]
 c=make_case(ins,outs,withdrawals,tree,intent=intent_hash);validate_case(c);c['name']=name
 c['events']=[dict(commitment=e.commitment,ciphertext=e.ciphertext.hex(),digest=e.digest) for _,e in outs]
 c['calldata']=encode_execution(c,[e for _,e in outs],intent) if execution else encode_spend(c,[e for _,e in outs])
 c['method']='execute_returns' if execution else 'apply_spend'
 if execution:
  c['execution']=copy.deepcopy(intent)
  for n in c['execution']['notes']:n['ciphertext']=n['ciphertext'].hex()
 save(path,c)
 save(path.parent/'public-call.json',{'calldata':[hex(x) for x in c['calldata']],'method':c['method'],
      'shape':[len(ins),len(outs),len(withdrawals)],'public_values':[hex(x) for x in c['public']]})
 return c
def negative(name,c,calldata,reason,*,method='execute_returns',spent=False):
 if name in progress['negative_tests']:return
 before=snapshot()
 proof_invoke(name,D,calldata,RUN/'cases'/c['name'],expected='REVERTED',reason=reason,method=method)
 after=snapshot();assert before==after,(name,'state changed')
 assert [call(D['pool'],'get_nullifier_spent',[nf])[0] for nf in c['nullifiers']]==[int(spent)]*len(c['nullifiers'])
 save(RUN/'results'/('negative-'+name+'.json'),{'reason':reason,'unchanged_pool_and_token_state':True,
      'nullifiers_checked':True,'before':before,'after':after})
 progress['negative_tests'].append(name);checkpoint()

if progress['stage']==0:
 p=RUN/'private-deposit.json'
 if not p.exists():
  n,e=send(wallet('alice').address,A,5000);save(p,{'calldata':encode_deposit(n,e)})
 invoke('deposit-alice',D['pool'],'deposit',json.loads(p.read_text())['calldata']);checkpoint(1)
if progress['stage']==1:
 c=new_case('upstream-ekubo-swap',A,[('alice',4000)],execution=True)
 prove_case(c['name'],c['witness'],c['public'],D)
 bad=list(c['witness']);bad[10]+=1
 prove_case('tampered-intent-statement',bad,c['public'],D,expect_error='BINDING')
 negative('isolated-withdrawal',c,encode_spend(c,events(c)),'EXECUTION_REQUIRED',method='apply_spend')
 stripped=copy.deepcopy(c);stripped['intent']=0
 stripped['public'][7]=binding(CHAIN,POOL,c['public'][3],A,c['nullifiers'],
     [tuple(x) for x in c['outputs']],[tuple(x) for x in c['withdrawals']],intent=0)
 negative('stripped-intent-proof',c,encode_spend(stripped,events(c)),'PROOF_BINDING',method='apply_spend')
 for name,change in [('redirected-return',lambda i:i['notes'][0].update(inner=123)),
                     ('changed-call',lambda i:i['calldata'].__setitem__(9,1)),
                     ('changed-return-id',lambda i:i['notes'][0].update(note_id=123))]:
  i=read_intent(c);change(i);negative(name,c,encode_execution(c,events(c),i),'EXECUTION_INTENT')
 proof_invoke(c['name'],D,c['calldata'],RUN/'cases'/c['name'],method=c['method'])
 negative('replay-swap',c,c['calldata'],'NULLIFIER_USED',spent=True)
 data,summary=restore('alice','after-swap')
 returned=[(int(i),n) for i,n in data['notes'].items() if n['token']==B and int(i) not in data['spent_indices']]
 assert len(returned)==1 and returned[0][1]['amount']>=900
 progress['return_amount']=returned[0][1]['amount']
 assert summary['balances']=={hex(A):4000,hex(B):progress['return_amount']}
 _,watch=restore('alice','view-after-swap',view=True);assert watch['balances']==summary['balances']
 save(RUN/'results/state-after-swap.json',snapshot());checkpoint(2)
if progress['stage']==2:
 data=json.loads((RUN/'wallets/after-swap/private-recovered.json').read_text())
 c=new_case('restored-return-payment',B,[('bob',900),('alice',progress['return_amount']-900)],restored=data)
 prove_case(c['name'],c['witness'],c['public'],D)
 proof_invoke(c['name'],D,c['calldata'],RUN/'cases'/c['name'],method=c['method'])
 _,bob=restore('bob','bob-received');assert bob['balances']=={hex(B):900}
 _,alice=restore('alice','final-alice');assert alice['balances']=={hex(A):4000,hex(B):progress['return_amount']-900}
 state=snapshot();assert state['token_a_pool']==4000 and state['token_b_pool']==progress['return_amount']
 assert state['token_a_adapter']==0 and state['token_b_adapter']==0 and state['leaf_count']==5
 save(RUN/'results/state-final.json',state);checkpoint(3)

summary={'status':'PASS','ordinary_notes_only':True,'stage':progress['stage'],'deployment':D,
 'negative_tests':progress['negative_tests'],'return_amount':progress['return_amount'],
 'final_state':json.loads((RUN/'results/state-final.json').read_text()),'proofs':{},'transactions':{}}
names=['upstream-ekubo-swap','restored-return-payment']
for name in names:summary['proofs'][name]=json.loads((RUN/'cases'/name/'benchmark.json').read_text())
for name in ['deposit-alice',*names,*progress['negative_tests']]:
 r=json.loads((RUN/'results'/name/'receipt.json').read_text())
 summary['transactions'][name]={k:r.get(k) for k in ['transaction_hash','execution_status','block_number','actual_fee','execution_resources','revert_reason']}
save(RUN/'results/summary.json',summary)
print('UNCHANGED UPSTREAM EKUBO / RETURN NOTE / FRESH RECOVERY / PRIVATE PAYMENT PASS',flush=True)
