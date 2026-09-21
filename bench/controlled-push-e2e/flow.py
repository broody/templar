"""Live controlled push lifecycle with real native proofs and real controller signatures."""
from common import *
from protocol import *
from encoding import encode_deposit,encode_spend
from proving import prove_case
from sync import canonical_checkpoint
from authorization import approve,message_signature,private_to_stark_key
from dataclasses import replace
import secrets,shutil
D=json.loads((RUN/'deployment.json').read_text());TOKEN=int(D['token'],16);POOL=int(D['pool'],16);CTRL=int(D['controller'],16)
DEST=int(D['bob_withdrawal_address'],16)
POLICY=H([tag('CTRL_POLICY_FIXTURE'),CHAIN,POOL,TOKEN,CTRL,DEST,500])
KEY=json.loads((RUN/'controller-key.json').read_text())
progress_file=RUN/'private-progress.json'
if progress_file.exists():progress=json.loads(progress_file.read_text())
else:
    progress={'stage':0,'negative_tests':[]}
    for name in ['alice','bob','carol','dave']:
        seed=secrets.token_bytes(32);folder=RUN/'backups'/name;folder.mkdir(parents=True)
        (folder/'seed.txt').write_text(seed.hex()+'\n')
        w=Wallet.restore(seed,CHAIN,POOL);a=w.address
        save(folder/'address.json',dict(chain=a.chain,pool=a.pool,receiver=a.receiver,encryption_key=a.encryption_key.hex()))
        if name=='bob':save(folder/'full-view.json',w.full_view.export())
    save(progress_file,progress)
def wallet(name):return Wallet.restore(bytes.fromhex((RUN/'backups'/name/'seed.txt').read_text().strip()),CHAIN,POOL)
def address(name):
    a=json.loads((RUN/'backups'/name/'address.json').read_text())
    return Address(a['chain'],a['pool'],a['receiver'],bytes.fromhex(a['encryption_key']))
def checkpoint(stage=None):
    if stage is not None:progress['stage']=stage
    save(progress_file,progress)
def snapshot():
    block=rpc('starknet_getBlockWithTxHashes',{'block_id':'latest'});bid={'block_hash':block['block_hash']}
    result={'root':call(D['pool'],'get_root',block=bid)[0],'leaf_count':call(D['pool'],'get_leaf_count',block=bid)[0]}
    for k,addr in [('relayer',ACCOUNT),('pool',D['pool']),('bob',D['bob_withdrawal_address']),('collector',D['fee_collector'])]:
        v=call(D['token'],'balance_of',[addr],block=bid);result[k]=v[0]+(v[1]<<128)
    result.update(block_number=block['block_number'],block_hash=block['block_hash']);return result
def verify_balances(label,relayer,pool,bob,collector):
    state=snapshot()
    for k,v in [('relayer',relayer),('pool',pool),('bob',bob),('collector',collector)]:assert state[k]==v,(k,state[k],v)
    assert sum(state[k] for k in ['relayer','pool','bob','collector'])==10000
    save(RUN/'results'/('state-'+label+'.json'),state);return state
def restored(label,view=False,minimum=0):
    folder=RUN/'backups/bob'
    args=['python3',str(HERE/'restore.py'),'--label',label,'--address-file',str(folder/'address.json'),'--minimum-block',str(minimum)]
    args+=['--view-file',str(folder/'full-view.json')] if view else ['--seed-file',str(folder/'seed.txt')]
    subprocess.run(args,cwd=HERE,env=ENV,check=True)
    data=RUN/'wallets'/label
    summary=json.loads((data/'summary.json').read_text())
    save(RUN/'results'/('recovery-report-'+label+'.json'),{'summary':summary,'sync':json.loads((data/'sync.json').read_text())})
    return summary,json.loads((data/'private-recovered.json').read_text())
def policy_config():
    return dict(chain=CHAIN,pool=POOL,token=TOKEN,controller=CTRL,policy_id=POLICY,withdrawal_recipient=DEST,max_withdrawal=500)
def persist_case(name,c,events,input_indices):
    validate_case(c);c['name']=name
    c['events']=[dict(commitment=e.commitment,digest=e.digest,ciphertext=e.ciphertext.hex()) for e in events]
    c['calldata']=encode_spend(c,events);c['input_indices']=input_indices
    save(RUN/'cases'/name/'private-case.json',c)
    # Public only: ciphertexts and signatures are already transaction calldata.
    save(RUN/'cases'/name/'public-call.json',{'public_values':[hex(x) for x in c['public']],
         'calldata':[hex(x) for x in c['calldata']],'shape':[len(c['nullifiers']),len(events),len(c['withdrawals'])]})
    return c
def case(name,owner,recipient_amounts,withdrawals,*,controlled=True,restored_data=None):
    path=RUN/'cases'/name/'private-case.json'
    if path.exists():return json.loads(path.read_text())
    w=wallet(owner)
    if restored_data is None:
        report,_,_,meta=canonical_checkpoint(D,w.full_view);assert report.history_complete
        tree=report.tree;notes=report.notes;spent=report.spent_indices
        save(RUN/'results'/('sync-'+name+'.json'),meta)
    else:
        tree=Tree()
        for cm in restored_data['commitments']:tree.insert(cm)
        notes={int(i):Note(**n) for i,n in restored_data['notes'].items()};spent=restored_data['spent_indices']
    ins=[(n,w.spend_key,i) for i,n in sorted(notes.items()) if i not in spent]
    ctrl=CTRL if controlled else 0;policy=POLICY if controlled else 0
    assert all(n.controller==ctrl for n,_,_ in ins)
    outs=[send(address(to),TOKEN,amt,controller=ctrl,policy=policy) for to,amt in recipient_amounts]
    height=rpc('starknet_blockNumber',{})
    c=make_case(ins,outs,withdrawals,tree,deadline=height+1800 if controlled else 0,nonce=secrets.randbelow(2**128)+1 if controlled else 0)
    if controlled:
        save(RUN/'cases'/name/'private-controller-request.json',c['transition_request'])
        # Only the scoped request and policy reach this function; no owner keys or membership paths.
        c['signature']=approve(c['transition_request'],policy_config(),KEY['private_key'],current_block=height)
    return persist_case(name,c,[e for _,e in outs],[i for _,_,i in ins])
def variant(name,base,*,destination=None,expired=False):
    path=RUN/'cases'/name/'private-case.json'
    if path.exists():return json.loads(path.read_text())
    c=copy.deepcopy(base);r=c['transition_request'];w=c['witness']
    c['withdrawals']=[list(x) for x in c['withdrawals']]
    r['withdrawals']=[list(x) for x in r['withdrawals']]
    if destination is not None:
        c['withdrawals'][0][0]=destination;r['withdrawals'][0][0]=destination
        w[-2*len(c['withdrawals'])]=destination
    if expired:
        r['deadline']=rpc('starknet_blockNumber',{})-1;w[7]=r['deadline'];c['public'][5]=r['deadline']
    transition=transition_hash(**r);w[9]=transition;c['public'][6]=transition
    b=binding(CHAIN,POOL,c['public'][3],TOKEN,c['nullifiers'],c['outputs'],c['withdrawals'],CTRL,r['deadline'],c['nonce'],transition)
    w[5]=b;c['public'][7]=b
    if expired:
        # Deliberately valid cryptography over an expired request to test the pool's clock check.
        c['signature']=list(message_signature(signature_message(transition),KEY['private_key']))
    else:
        # Owner can build a valid new proof, but controller refuses this changed destination.
        try:approve(r,policy_config(),KEY['private_key'],current_block=rpc('starknet_blockNumber',{}))
        except ValueError as e:assert 'policy withdrawal' in str(e)
        else:raise AssertionError('policy unexpectedly approved redirected withdrawal')
        c['signature']=base['signature']
    events=[Event(e['commitment'],bytes.fromhex(e['ciphertext']),e['digest']) for e in c['events']]
    return persist_case(name,c,events,c['input_indices'])
def prove(c):return prove_case(c['name'],c['witness'],c['public'],D)
def negative(name,c,calldata,reason,spent=False):
    if name in progress['negative_tests']:return
    before=snapshot();proof_invoke(name,D,calldata,RUN/'cases'/c['name'],expected='REVERTED',reason=reason);after=snapshot()
    assert {k:v for k,v in before.items() if not k.startswith('block_')}=={k:v for k,v in after.items() if not k.startswith('block_')}
    assert [call(D['pool'],'get_nullifier_spent',[nf])[0] for nf in c['nullifiers']]==[int(spent)]*len(c['nullifiers'])
    save(RUN/'results'/('negative-'+name+'.json'),{'expected_revert':reason,'state_and_balances_unchanged':True,'nullifiers_checked':True})
    progress['negative_tests'].append(name);checkpoint()

if progress['stage']==0:
    for who,amount,ctrl,policy in [('alice',1000,CTRL,POLICY),('carol',300,0,0)]:
        f=RUN/('private-deposit-'+who+'.json')
        if not f.exists():
            n,e=send(address(who),TOKEN,amount,controller=ctrl,policy=policy);save(f,{'calldata':encode_deposit(n,e)})
        invoke('deposit-'+who,D['pool'],'deposit',json.loads(f.read_text())['calldata'])
    verify_balances('funded',8700,1300,0,0);checkpoint(1)
if progress['stage']==1:
    print('Controlled Alice -> offline Bob',flush=True)
    c=case('controlled-payment','alice',[('bob',600),('alice',400)],[]);prove(c)
    missing=list(c['calldata']);missing[10:12]=[0,0];negative('missing-approval',c,missing,'CONTROL_SIGNATURE')
    wrong=list(c['calldata']);wrong[10:12]=list(message_signature(signature_message(c['public'][6]),1234));negative('wrong-signer',c,wrong,'CONTROL_SIGNATURE')
    expired=variant('expired-proof',c,expired=True);prove(expired);negative('expired-approval',expired,expired['calldata'],'CONTROL_EXPIRED')
    proof_invoke(c['name'],D,c['calldata'],RUN/'cases'/c['name'])
    state=verify_balances('controlled-payment',8695,1300,0,5)
    negative('replay-payment',c,c['calldata'],'NULLIFIER_USED',spent=True)
    summary,_=restored('bob-watch-received',view=True,minimum=state['block_number']);assert summary['balances']=={hex(TOKEN):600}
    summary,_=restored('bob-restored',minimum=state['block_number']);assert summary['balances']=={hex(TOKEN):600}
    checkpoint(2)
if progress['stage']==2:
    print('Restored Bob pays Dave and withdraws with controller approval',flush=True)
    data=None if (RUN/'cases/controlled-respend/private-case.json').exists() else json.loads((RUN/'wallets/bob-restored/private-recovered.json').read_text())
    c=case('controlled-respend','bob',[('dave',500),('bob',60)],[(DEST,40)],restored_data=data)
    bad=list(c['witness']);bad[13]=KEY['private_key']
    prove_case('controller-cannot-spend',bad,c['public'],D,'MEMBERSHIP')
    bad=list(c['witness']);bad[6:10]=[0,0,0,0];bad[16:18]=[0,0]
    prove_case('controller-cannot-be-stripped',bad,c['public'],D,'MEMBERSHIP')
    changed=variant('redirected-proof',c,destination=DEST+1);prove(changed)
    negative('redirected-withdrawal',changed,changed['calldata'],'CONTROL_SIGNATURE')
    prove(c);proof_invoke(c['name'],D,c['calldata'],RUN/'cases'/c['name'])
    state=verify_balances('controlled-respend',8690,1260,40,10)
    summary,_=restored('bob-watch-after-spend',view=True,minimum=state['block_number']);assert summary['balances']=={hex(TOKEN):60}
    if (RUN/'wallets/bob-restored').exists():shutil.rmtree(RUN/'wallets/bob-restored')
    summary,_=restored('bob-restored-again',minimum=state['block_number']);assert summary['balances']=={hex(TOKEN):60}
    checkpoint(3)
if progress['stage']==3:
    data=json.loads((RUN/'wallets/bob-restored-again/private-recovered.json').read_text())
    c=case('controlled-withdrawal','bob',[],[(DEST,60)],restored_data=data);prove(c)
    proof_invoke(c['name'],D,c['calldata'],RUN/'cases'/c['name'])
    state=verify_balances('controlled-withdrawal',8685,1200,100,15)
    summary,_=restored('bob-watch-final',view=True,minimum=state['block_number']);assert summary['balances']=={hex(TOKEN):0}
    checkpoint(4)
if progress['stage']==4:
    print('Ordinary push payment remains valid without controller approval',flush=True)
    c=case('ordinary-payment','carol',[('dave',100),('carol',200)],[],controlled=False);prove(c)
    proof_invoke(c['name'],D,c['calldata'],RUN/'cases'/c['name'])
    verify_balances('final',8680,1200,100,20);checkpoint(5)
summary={'status':'PASS','stage':progress['stage'],'deployment':D,'policy_commitment':hex(POLICY),
 'negative_tests':progress['negative_tests'],'final_state':json.loads((RUN/'results/state-final.json').read_text()),'proofs':{},'transactions':{}}
for name in ['controlled-payment','controlled-respend','controlled-withdrawal','ordinary-payment','expired-proof','redirected-proof']:
 summary['proofs'][name]=json.loads((RUN/'cases'/name/'benchmark.json').read_text())
for name in ['deposit-alice','deposit-carol','controlled-payment','controlled-respend','controlled-withdrawal','ordinary-payment',*progress['negative_tests']]:
 r=json.loads((RUN/'results'/name/'receipt.json').read_text());summary['transactions'][name]={k:r.get(k) for k in ['transaction_hash','execution_status','block_number','actual_fee','execution_resources','revert_reason']}
save(RUN/'results/summary.json',summary)
print('CONTROLLED PUSH + REAL SIGNATURE + RECOVERY PASS',flush=True)
