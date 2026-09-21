"""Actual pool: funded deposit -> payment -> recipient respend -> withdrawal."""
from common import *
from witnesses import *
from proving import prove_case

D=json.loads((RUN/'deployment.json').read_text());TOKEN=int(D['token'],16)
checkpoint=RUN/'private-progress.json'
if checkpoint.exists():progress=json.loads(checkpoint.read_text())
else:
 alice=fresh_note(TOKEN,1000);bob=fresh_note(TOKEN,600);change=fresh_note(TOKEN,400,alice['owner']);next_bob=fresh_note(TOKEN,500,bob['owner'])
 progress={'stage':0,'notes':{'alice_deposit':alice,'bob_payment':bob,'alice_change':change,'bob_respend':next_bob},'tree_leaves':[],'negative_tests':[]};save(checkpoint,progress)
notes=progress['notes'];tree=ref.SparseTree()
for leaf in progress['tree_leaves']:tree.insert(leaf)

def commit_progress(stage=None):
 if stage is not None:progress['stage']=stage
 save(checkpoint,progress)
def append_note(name):
 n=notes[name];n['index']=tree.insert(n['leaf']);progress['tree_leaves'].append(n['leaf'])
def case(name,ins,outs,wds):
 path=RUN/'cases'/name/'private-case.json'
 if path.exists():return json.loads(path.read_text())
 return build_case(name,D,[notes[n] for n in ins],[invoice(notes[n]) for n in outs],wds,tree)
def prove(c,expected=None):return prove_case(c['name'],c['private'],c['public'],D,expected)
def state(label):
 s=snapshot(D,notes);save(RUN/'results'/f'state-{label}.json',s);return s
def verify_events(receipt,c):
 pool=int(D['pool'],16);events=[e for e in receipt['events'] if int(e['from_address'],16)==pool]
 def data(name):return [[int(x,16) for x in e['data']] for e in events if int(e['keys'][0],16)==int(selector(name),16)]
 assert data('NullifierSpent')==[[n['nullifier'],0] for n in c['inputs']]
 expected_leaves=[[n['note_id'],notes[name]['index'],n['leaf'],0] for n in c['outputs'] for name in notes if notes[name]['leaf']==n['leaf']]
 assert data('NoteCommitted')==expected_leaves,(data('NoteCommitted'),expected_leaves)
 assert data('Withdrawal')==[[w['to'],TOKEN,w['amount'],0] for w in c['withdrawals']]
 save(RUN/'results'/f"events-{c['name']}.json",{'nullifier_events_match':True,'commitment_events_match':True,'withdrawal_events_match':True})
def negative(name,c,calldata,reason):
 if name in progress['negative_tests']:return
 before=state(name+'-before');proof_invoke(name,D,calldata,RUN/'cases'/c['name'],expected='REVERTED',reason=reason);after=state(name+'-after');state_equal(before,after)
 save(RUN/'results'/f'negative-{name}.json',{'expected_revert':reason,'pool_state_unchanged':True,'balances_unchanged':True,'nullifiers_unchanged':True});progress['negative_tests'].append(name);commit_progress()

def assert_balances(s,relayer,pool,bob,collector):
 for k,v in [('balance_relayer',relayer),('balance_pool',pool),('balance_bob',bob),('balance_collector',collector)]:assert s[k]==v,(k,s[k],v)
 assert s['root']==tree.root() and s['leaf_count']==tree.count
 assert sum(s[k] for k in ['balance_relayer','balance_pool','balance_bob','balance_collector'])==10000

if progress['stage']==0:
 print('Funded deposit',flush=True)
 n=notes['alice_deposit'];invoke('deposit-alice',D['pool'],'deposit',[TOKEN,1000,0,0,n['inner'],n['note_id']]);append_note('alice_deposit')
 s=state('deposit');assert_balances(s,9000,1000,0,0);assert s['spent_alice_deposit']==0;commit_progress(1)

if progress['stage']==1:
 print('Alice pays Bob, with change',flush=True)
 c=case('payment',['alice_deposit'],['bob_payment','alice_change'],[])
 invalid=copy.deepcopy(c);invalid['name']='invalid-owner';invalid['private'][15]=(invalid['private'][15]+1)%ref.P;prove(invalid,'BAD_MEMBERSHIP')
 prove(c)
 altered=list(c['calldata']);altered[-1]+=1;negative('tampered-actions',c,altered,'BAD_BINDING')
 actions=list(c['actions']);actions[-1]+=1;ref.POOL=int(D['pool'],16);ref.ACTIONS_HASH=ref.hash_span(actions);binding=ref.statement_binding(c['reference_root'],[n['nullifier'] for n in c['inputs']],[n['leaf'] for n in c['outputs']],[],0,0,0);altered[c['pi_length']-1]=binding
 negative('forged-public-binding',c,altered,'PROOF_BINDING')
 r=proof_invoke('payment',D,c['calldata'],RUN/'cases/payment');append_note('bob_payment');append_note('alice_change');verify_events(r,c)
 s=state('payment');assert_balances(s,8995,1000,0,5);assert s['spent_alice_deposit']==1 and s['spent_bob_payment']==0 and s['spent_alice_change']==0;commit_progress(2)

if progress['stage']==2:
 c=json.loads((RUN/'cases/payment/private-case.json').read_text());negative('replay-payment',c,c['calldata'],'NULLIFIER_USED')
 print('Bob spends the received note',flush=True)
 c=case('recipient-respend',['bob_payment'],['bob_respend'],[{'amount':100,'to':int(D['bob_withdrawal_address'],16)}]);prove(c)
 r=proof_invoke('recipient-respend',D,c['calldata'],RUN/'cases/recipient-respend');append_note('bob_respend');verify_events(r,c)
 s=state('recipient-respend');assert_balances(s,8990,900,100,10);assert s['spent_bob_payment']==1 and s['spent_bob_respend']==0;commit_progress(3)

if progress['stage']==3:
 print('Withdrawal rollback and final withdrawal',flush=True)
 bad=case('zero-recipient',['bob_respend'],[],[{'amount':500,'to':0}]);prove(bad);negative('zero-recipient',bad,bad['calldata'],'ZERO_RECIPIENT')
 c=case('withdrawal',['bob_respend'],[],[{'amount':500,'to':int(D['bob_withdrawal_address'],16)}])
 invalid=copy.deepcopy(c);invalid['name']='invalid-conservation';invalid['private'][-1]+=1;prove(invalid,'NOT_CONSERVED')
 prove(c);r=proof_invoke('withdrawal',D,c['calldata'],RUN/'cases/withdrawal');verify_events(r,c)
 s=state('withdrawal');assert_balances(s,8985,400,600,15);assert s['spent_bob_respend']==1 and s['spent_alice_change']==0;commit_progress(4)

summary={'status':'PASS','starknet_version':'0.14.4','deployment':D,'stage':progress['stage'],'final_state':json.loads((RUN/'results/state-withdrawal.json').read_text()),'negative_tests':progress['negative_tests'],'ordinary_flow':'Deposit 1000; Alice pays Bob 600 + 400 change; Bob respends 600 into 500 change + 100 withdrawal; Bob withdraws remaining 500. Three fees of 5 paid by relayer outside private balance.','proofs':{},'transactions':{},'limitations':['Synthetic test-token units and note keys; account-1 relays all transactions.','Controller signature verification is not implemented or exercised.','Wallet encryption, discovery and GUI are not exercised.','Physical 16 GiB desktop and mainnet remain unqualified.']}
for name in ['payment','recipient-respend','withdrawal','zero-recipient']:
 summary['proofs'][name]=json.loads((RUN/'cases'/name/'benchmark.json').read_text())
for name in ['payment','recipient-respend','withdrawal',*progress['negative_tests']]:
 r=json.loads((RUN/'results'/name/'receipt.json').read_text());summary['transactions'][name]={k:r.get(k) for k in ['transaction_hash','execution_status','block_number','actual_fee','execution_resources','revert_reason']}
save(RUN/'results/summary.json',summary);print('END-TO-END PASS',json.dumps({'final_balances':{k:v for k,v in summary['final_state'].items() if k.startswith('balance_')},'negative_tests':progress['negative_tests']}),flush=True)
