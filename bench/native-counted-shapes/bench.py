"""Synthetic controlled statement capacity, without submitting synthetic spends."""
from common import *
from protocol import *
from proving import prove_case
from encoding import encode_spend
import hashlib
D=json.loads((RUN/'deployment.json').read_text());pool=int(D['pool'],16);token=int(D['token'],16);ctrl=int(D['controller'],16)
a=Wallet.restore(hashlib.sha256(b'PUBLIC synthetic shape Alice').digest(),CHAIN,pool)
b=Wallet.restore(hashlib.sha256(b'PUBLIC synthetic shape Bob').digest(),CHAIN,pool)
shapes=[(1,2,0),(4,4,2),(8,8,4),(16,16,8),(32,32,16),(64,64,32),(32,2,0),(1,32,0)]
def fixture(shape):
 ni,no,nw=shape;tree=Tree();ins=[];amount=2**20
 for i in range(ni):
  n,_=send(a.address,token,amount,rho=10+i,controller=ctrl,policy=777);index=tree.insert(n.commitment);ins.append((n,a.spend_key,index))
 total=ni*amount;wd_total=total//2 if nw else 0
 outs=[send(b.address,token,(total-wd_total)//no,rho=1000+i,controller=ctrl,policy=777) for i in range(no)]
 wds=[(0xb0b+i,wd_total//nw) for i in range(nw)]
 c=make_case(ins,outs,wds,tree,deadline=rpc('starknet_blockNumber',{})+2000,nonce=1);validate_case(c)
 c['calldata_felts']=len(encode_spend(c,[e for _,e in outs]));return c
results=[]
for shape in shapes:
 name='shape-'+'-'.join(map(str,shape));folder=RUN/'cases'/name;path=folder/'private-case.json'
 c=json.loads(path.read_text()) if path.exists() else fixture(shape)
 save(path,c);print('Proving synthetic controlled shape',shape,flush=True)
 try:
  result=prove_case(name,c['witness'],c['public'],D)
  result={**result,'status':'PASS','shape':shape,'private_calldata_felts':len(c['witness'])+1,'public_spend_calldata_felts':c['calldata_felts'],'ciphertext_bytes':304*shape[1]}
  save(folder/'benchmark.json',result)
 except Exception as e:
  result={'case':name,'shape':shape,'status':'FAILED','error':str(e)[:1200],'memory_cap_gib':16,'cores':4}
  save(folder/'failure.json',result);print('Bounded benchmark failure:',name,type(e).__name__,flush=True)
 results.append(result);save(RUN/'results/summary.json',{'scope':'synthetic statements; no funded pool settlement; not physical-desktop qualification','maximum_shape':[64,64,32],'results':results})
# Capacity expansion must retain explicit bounds and version separation.
c=json.loads((RUN/'cases/shape-1-2-0/private-case.json').read_text())
w=list(c['witness']);w[10]=65;prove_case('reject-over-cap',w,c['public'],D,'SHAPE')
w=list(c['witness']);w[0]=int.from_bytes(b'TEMPLAR_CONTROL_POC1','big');prove_case('reject-old-version',w,c['public'],D,'VERSION')
print('Synthetic shape sweep finished.',flush=True)
