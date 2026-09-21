"""Read-only final wallet and pool reconciliation; prints synthetic aggregates only."""
from common import *
from protocol import Wallet,CHAIN
from sync import canonical_checkpoint
D=json.loads((RUN/'deployment.json').read_text())
summary=json.loads((RUN/'results/summary.json').read_text());assert summary['status']=='PASS' and summary['stage']==5
final=summary['final_state'];token=int(D['token'],16);ctrl=int(D['controller'],16);policy=int(summary['policy_commitment'],16)
expected={'alice':{ctrl:400},'bob':{},'carol':{0:200},'dave':{ctrl:500,0:100}}
def check(name):
 w=Wallet.restore(bytes.fromhex((RUN/'backups'/name/'seed.txt').read_text().strip()),CHAIN,int(D['pool'],16))
 report,_,_,meta=canonical_checkpoint(D,w.full_view,minimum_block=final['block_number'])
 assert report.history_complete and report.tree.root()==final['root'] and report.tree.count==final['leaf_count']
 balances={}
 for i,n in report.notes.items():
  assert n.token==token and n.policy==(policy if n.controller else 0)
  if i not in report.spent_indices:balances[n.controller]=balances.get(n.controller,0)+n.amount
 assert balances==expected[name],(name,balances)
 return name,{'unspent_by_controller':{hex(k):v for k,v in balances.items()},'summary':report.summary(),'sync_seconds':meta['seconds']}
with ThreadPoolExecutor(max_workers=4) as executor:wallets=dict(executor.map(check,expected))
total=sum(sum(v['unspent_by_controller'].values()) for v in wallets.values());assert total==final['pool']==1200
save(RUN/'results/final-reconciliation.json',{'status':'PASS','wallets':wallets,'total_unspent':total,'pool_tokens':final['pool'],'controller_and_policy_preserved':True})
print('Final controlled/ordinary wallet balances reconcile to 1200 pool tokens.')
