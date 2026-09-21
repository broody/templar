"""Live: fund -> two offline push receipts -> watch -> restore/spend -> restore/withdraw."""
from common import *
from protocol import Wallet,Address,Note,Event,CHAIN,FullView,Tree,send,make_case,validate_case,binding,ciphertext_hash
from encoding import encode_deposit,encode_spend
from proving import prove_case
from sync import canonical_checkpoint
from dataclasses import asdict,replace
import secrets,shutil

D=json.loads((RUN/'deployment.json').read_text());TOKEN=int(D['token'],16);POOL=int(D['pool'],16)
progress_file=RUN/'private-progress.json'
if progress_file.exists():progress=json.loads(progress_file.read_text())
else:
    progress={'stage':0,'negative_tests':[]}
    for name in ['alice','bob','carol','dave']:
        seed=secrets.token_bytes(32);folder=RUN/'backups'/name;folder.mkdir(parents=True)
        (folder/'seed.txt').write_text(seed.hex()+'\n')
        wallet=Wallet.restore(seed,CHAIN,POOL);a=wallet.address
        save(folder/'address.json',dict(chain=a.chain,pool=a.pool,receiver=a.receiver,encryption_key=a.encryption_key.hex()))
        if name=='bob':save(folder/'full-view.json',wallet.full_view.export())
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
    result['block_number']=block['block_number'];result['block_hash']=block['block_hash'];return result
def verify_balances(label,relayer,pool,bob,collector):
    state=snapshot()
    for k,v in [('relayer',relayer),('pool',pool),('bob',bob),('collector',collector)]:assert state[k]==v,(k,state[k],v)
    assert sum(state[k] for k in ['relayer','pool','bob','collector'])==10000
    save(RUN/'results'/('state-'+label+'.json'),state);return state
def restored(label,view=False,minimum=0):
    backup=RUN/'backups/bob'
    command=['python3',str(HERE/'restore.py'),'--label',label,'--address-file',str(backup/'address.json'),
             '--minimum-block',str(minimum)]
    command+=['--view-file',str(backup/'full-view.json')] if view else ['--seed-file',str(backup/'seed.txt')]
    subprocess.run(command,cwd=HERE,env=ENV,check=True)
    folder=RUN/'wallets'/label
    save(RUN/'results'/('recovery-report-'+label+'.json'),{
        'summary':json.loads((folder/'summary.json').read_text()),
        'sync':json.loads((folder/'sync.json').read_text())})
    return json.loads((folder/'summary.json').read_text()),json.loads((folder/'private-recovered.json').read_text())
def case(name,owner,recipient_amounts,withdrawals,restored_data=None):
    path=RUN/'cases'/name/'private-case.json'
    if path.exists():return json.loads(path.read_text())
    w=wallet(owner)
    if restored_data is None:
        report,_,_,meta=canonical_checkpoint(D,w.full_view)
        assert report.history_complete
        tree=report.tree;notes=report.notes;spent=report.spent_indices
        save(RUN/'results'/('sync-'+name+'.json'),meta)
    else:
        tree=Tree()
        for cm in restored_data['commitments']:tree.insert(cm)
        notes={int(i):Note(**n) for i,n in restored_data['notes'].items()};spent=restored_data['spent_indices']
    ins=[(n,w.spend_key,i) for i,n in sorted(notes.items()) if i not in spent]
    outs=[send(address(to),TOKEN,amount) for to,amount in recipient_amounts]
    c=make_case(ins,outs,withdrawals,tree);validate_case(c)
    c['name']=name;c['events']=[dict(commitment=e.commitment,digest=e.digest,ciphertext=e.ciphertext.hex()) for _,e in outs]
    c['calldata']=encode_spend(c,[e for _,e in outs]);c['input_indices']=[i for _,_,i in ins]
    save(path,c)
    save(RUN/'cases'/name/'public-call.json',{'public_values':[hex(x) for x in c['public']],
         'calldata':[hex(x) for x in c['calldata']],'shape':[len(ins),len(outs),len(withdrawals)]})
    return c
def prove(c):return prove_case(c['name'],c['witness'],c['public'],D)
def negative(name,c,calldata,reason):
    if name in progress['negative_tests']:return
    before=snapshot();proof_invoke(name,D,calldata,RUN/'cases'/c['name'],expected='REVERTED',reason=reason);after=snapshot()
    assert {k:v for k,v in before.items() if not k.startswith('block_')}=={k:v for k,v in after.items() if not k.startswith('block_')}
    assert [call(D['pool'],'get_nullifier_spent',[nf])[0] for nf in c['nullifiers']]==([1]*len(c['nullifiers']) if name=='replay-alice' else [0]*len(c['nullifiers']))
    save(RUN/'results'/('negative-'+name+'.json'),{'expected_revert':reason,'pool_state_and_token_balances_unchanged':True,'nullifiers_checked':True})
    progress['negative_tests'].append(name);checkpoint()

if progress['stage']==0:
    for who,amount in [('alice',1000),('carol',500)]:
        f=RUN/('private-deposit-'+who+'.json')
        if not f.exists():
            n,e=send(address(who),TOKEN,amount);save(f,{'calldata':encode_deposit(n,e)})
        invoke('deposit-'+who,D['pool'],'deposit',json.loads(f.read_text())['calldata'])
    verify_balances('funded',8500,1500,0,0);checkpoint(1)

if progress['stage']==1:
    print('Alice pays offline Bob 600',flush=True)
    c=case('alice-payment','alice',[('bob',600),('alice',400)],[]);prove(c)
    events=[Event(e['commitment'],bytes.fromhex(e['ciphertext']),e['digest']) for e in c['events']]
    changed=bytearray(events[0].ciphertext);changed[-1]^=1
    events[0]=replace(events[0],ciphertext=bytes(changed),digest=ciphertext_hash(bytes(changed)))
    bad=encode_spend(c,events);negative('altered-ciphertext',c,bad,'BAD_BINDING')
    bad[5]=binding(CHAIN,POOL,c['public'][3],TOKEN,c['nullifiers'],[(e.commitment,e.digest) for e in events],[])
    negative('rebound-ciphertext',c,bad,'PROOF_BINDING')
    proof_invoke(c['name'],D,c['calldata'],RUN/'cases'/c['name'])
    verify_balances('alice-payment',8495,1500,0,5);checkpoint(2)

if progress['stage']==2:
    c=json.loads((RUN/'cases/alice-payment/private-case.json').read_text())
    negative('replay-alice',c,c['calldata'],'NULLIFIER_USED')
    print('Carol independently pays offline Bob 250',flush=True)
    c=case('carol-payment','carol',[('bob',250),('carol',250)],[]);prove(c)
    proof_invoke(c['name'],D,c['calldata'],RUN/'cases'/c['name'])
    s=verify_balances('carol-payment',8490,1500,0,10)
    summary,_=restored('bob-watch-incoming',view=True,minimum=s['block_number'])
    assert summary['balances']=={hex(TOKEN):850}
    summary,data=restored('bob-restored',minimum=s['block_number'])
    assert summary['balances']=={hex(TOKEN):850};checkpoint(3)

if progress['stage']==3:
    print('Bob spends only freshly recovered notes',flush=True)
    if not (RUN/'wallets/bob-restored/private-recovered.json').exists():
        restored('bob-restored')
    data=json.loads((RUN/'wallets/bob-restored/private-recovered.json').read_text())
    c=case('bob-spend','bob',[('dave',500),('bob',310)],[(int(D['bob_withdrawal_address'],16),40)],data)
    invalid=list(c['witness']);invalid[9]=wallet('bob').full_view.nullifier_secret
    prove_case('view-key-cannot-spend',invalid,c['public'],D,'MEMBERSHIP')
    prove(c);proof_invoke(c['name'],D,c['calldata'],RUN/'cases'/c['name'])
    s=verify_balances('bob-spend',8485,1460,40,15)
    summary,_=restored('bob-watch-after-spend',view=True,minimum=s['block_number'])
    assert summary['received_totals']=={hex(TOKEN):1160} and summary['balances']=={hex(TOKEN):310}
    # Remove this experiment's wallet cache; the next process has only its seed
    # backup and public chain metadata, and cannot consult old note witnesses.
    shutil.rmtree(RUN/'wallets/bob-restored')
    summary,_=restored('bob-restored-again',minimum=s['block_number'])
    assert summary['balances']=={hex(TOKEN):310};checkpoint(4)

if progress['stage']==4:
    data=json.loads((RUN/'wallets/bob-restored-again/private-recovered.json').read_text())
    c=case('restored-withdrawal','bob',[],[(int(D['bob_withdrawal_address'],16),310)],data);prove(c)
    proof_invoke(c['name'],D,c['calldata'],RUN/'cases'/c['name'])
    s=verify_balances('final',8480,1150,350,20)
    summary,_=restored('bob-watch-final',view=True,minimum=s['block_number'])
    assert summary['balances']=={hex(TOKEN):0} and summary['history_complete'];checkpoint(5)

summary={'status':'PASS','stage':progress['stage'],'deployment':D,'negative_tests':progress['negative_tests'],
         'final_state':json.loads((RUN/'results/state-final.json').read_text()),'proofs':{},'transactions':{},
         'limitations':['Two RPC providers are trusted; consensus/state proofs are not verified.',
                        'Ordinary POC2 notes only; no legacy migration or controlled notes.',
                        'Synthetic token; no production or physical desktop qualification.']}
for name in ['alice-payment','carol-payment','bob-spend','restored-withdrawal']:
    summary['proofs'][name]=json.loads((RUN/'cases'/name/'benchmark.json').read_text())
for name in ['deposit-alice','deposit-carol','alice-payment','carol-payment','bob-spend','restored-withdrawal',*progress['negative_tests']]:
    r=json.loads((RUN/'results'/name/'receipt.json').read_text());summary['transactions'][name]={k:r.get(k) for k in ['transaction_hash','execution_status','block_number','actual_fee','execution_resources','revert_reason']}
save(RUN/'results/summary.json',summary)
print('PUSH + WATCH + RECOVERY PASS',flush=True)
