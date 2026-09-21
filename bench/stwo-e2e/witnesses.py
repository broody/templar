"""Reference encoding shared by the real-pool lifecycle and negative cases."""
from common import *
import reference as ref
import secrets

def fresh_note(token,amount,owner=None):
 n=ref.note(token,amount,owner=owner or secrets.randbelow(ref.P-1)+1,salt=secrets.randbits(128));n['inner']=ref.inner(n['secret']);n['note_id']=ref.hash_span([ref.TAGS['NOTE_ID'],n['secret']]);return n

def build_case(name,deploy,inputs,outputs,withdrawals,tree):
 """outputs are recipient invoices: inner/amount/policy, never recipient keys."""
 pool=int(deploy['pool'],16);token=int(deploy['token'],16);block=rpc('starknet_getBlockWithTxHashes',{'block_id':'latest'});bid={'block_number':block['block_number']}
 root=call(pool,'get_root',block=bid)[0];assert root==tree.root();assert call(pool,'get_leaf_count',block=bid)==[tree.count]
 def path_item(arg):
  index,level=arg;return call(pool,'get_node',[level,(index>>level)^1],block=bid)[0]
 # Empty nodes return zero hashes from the real pool view.
 with ThreadPoolExecutor(max_workers=4) as executor:flat=list(executor.map(path_item,[(n['index'],level) for n in inputs for level in range(32)]))
 paths=[flat[i*32:(i+1)*32] for i in range(len(inputs))]
 for note,path in zip(inputs,paths):assert path==tree.path(note['index'])
 nfs=[n['nullifier'] for n in inputs];cms=[n['leaf'] for n in outputs];wds=[(token,w['amount']) for w in withdrawals]
 actions=[]
 for n in inputs:actions += [0,n['nullifier']]
 for n in outputs:actions += [1,n['leaf'],n['note_id']]
 for w in withdrawals:actions += [2,token,w['amount'],0,w['to']]
 actions_hash=ref.hash_span(actions);ref.POOL=pool;ref.ACTIONS_HASH=actions_hash;binding=ref.statement_binding(root,nfs,cms,wds,0,0,0)
 public=[ref.VERSION,ref.CHAIN,pool,root,0,0,0,binding]
 private=public+[actions_hash,token,0,len(inputs),len(outputs),len(withdrawals)]
 for n,path in zip(inputs,paths):private += [n['salt'],n['owner'],n['amount'],0,0,n['nullifier'],n['index'],*path]
 for n in outputs:private += [n['inner'],n['amount'],0,0,n['leaf']]
 private += [w['amount'] for w in withdrawals]
 pi=[ref.VERSION,ref.CHAIN,pool,root,len(nfs),*nfs,len(cms),*cms,len(wds)]
 for t,a in wds:pi += [t,a,0]
 pi += [0,0,0,binding]
 calldata=pi+[0,len(inputs)+len(outputs)+len(withdrawals),*actions]
 v={'name':name,'public':public,'private':private,'calldata':calldata,'pi_length':len(pi),'actions':actions,'inputs':inputs,'outputs':outputs,'withdrawals':withdrawals,'reference_root':root,'path_source_block':block['block_number']}
 save(RUN/'cases'/name/'private-case.json',v);save(RUN/'cases'/name/'public-call.json',{'public_values':[hex(x) for x in public],'calldata':[hex(x) for x in calldata],'shape':[len(inputs),len(outputs),len(withdrawals)],'root':hex(root)});return v

def invoice(n):return {k:n[k] for k in ['inner','amount','leaf','note_id']}

def snapshot(deploy,notes):
 pool=int(deploy['pool'],16);token=int(deploy['token'],16);block=rpc('starknet_getBlockWithTxHashes',{'block_id':'latest'});bid={'block_number':block['block_number']}
 jobs={'root':(pool,'get_root',[]),'leaf_count':(pool,'get_leaf_count',[])}
 for name,address in [('relayer',ACCOUNT),('pool',pool),('bob',deploy['bob_withdrawal_address']),('collector',deploy['fee_collector'])]:jobs['balance_'+name]=(token,'balance_of',[address])
 for name,n in notes.items():jobs['spent_'+name]=(pool,'get_nullifier_spent',[n['nullifier']])
 with ThreadPoolExecutor(max_workers=4) as executor:values=list(executor.map(lambda j:call(*j,block=bid),jobs.values()))
 result={name:v[0]+(v[1]<<128 if len(v)==2 else 0) for name,v in zip(jobs,values)};result['block']=block['block_number'];return result

def state_equal(a,b):assert {k:v for k,v in a.items() if k!='block'}=={k:v for k,v in b.items() if k!='block'},(a,b)
