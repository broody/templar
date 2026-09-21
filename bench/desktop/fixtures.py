"""Independent wallet fixtures. Sender receives invoice fields, never recipient secrets."""
from pathlib import Path
import json
from native_reference import h as native_hash
import sys
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT.parents[1]/'packages/circuit'))
from gen_fixture import hash_span
TAG={x:int.from_bytes(t.encode(),'big') for x,t in [('NS','NOTE_SECRET_TAG:V3'),('NI','NOTE_INNER_TAG:V3'),('NF','NULLIFIER_TAG:V3'),('CM','COMMITMENT_TAG:V3'),('BIND','TX_BIND_TAG:V2'),('VERSION','TEMPLAR_DESKTOP1')]}
class Tree:
 def __init__(self,h):
  self.h=h;self.nodes={};self.count=0;self.zeros=[0]
  for _ in range(32):self.zeros.append(h([self.zeros[-1],self.zeros[-1]]))
 def insert(self,leaf):
  index=self.count;self.nodes[0,index]=leaf;cur=index
  for level in range(32):
   a=self.nodes.get((level,cur&~1),self.zeros[level]);b=self.nodes.get((level,cur|1),self.zeros[level])
   cur//=2;self.nodes[level+1,cur]=self.h([a,b])
  self.count+=1;return index
 def root(self):return self.nodes.get((32,0),self.zeros[32])
 def path(self,index):return [self.nodes.get((level,(index>>level)^1),self.zeros[level]) for level in range(32)]
def note(h,token,amount,owner,salt):
 secret=h([TAG['NS'],salt,owner]);inner=h([TAG['NI'],secret]);cm=h([TAG['CM'],token,amount,0,0,inner])
 return dict(salt=salt,owner=owner,amount=amount,secret=secret,inner=inner,cm=cm,nf=h([TAG['NF'],secret]))
def prover(chain,pool,token,tree,ins,outs,wd,to):
 return dict(chain=str(chain),pool=str(pool),token=str(token),root=str(tree.root()),n_in=len(ins),n_out=len(outs),withdrawal=str(wd),recipient=str(to),
  inputs=[dict(salt=str(n['salt']),owner=str(n['owner']),amount=str(n['amount']),index=n['index'],path=list(map(str,tree.path(n['index'])))) for n in ins]+[dict(salt='0',owner='0',amount='0',index=0,path=['0']*32)]*(2-len(ins)),
  outputs=[dict(inner=str(n['inner']),amount=str(n['amount'])) for n in outs]+[dict(inner='0',amount='0')]*(2-len(outs)))
def toml(data):
 lines=[]
 for k,v in data.items():
  if k not in ['inputs','outputs']:lines.append(f'{k} = {json.dumps(v)}')
 for group in ['inputs','outputs']:
  for row in data[group]:
   lines.append(f'[[{group}]]')
   lines.extend(f'{k} = {json.dumps(v)}' for k,v in row.items())
 return '\n'.join(lines)+'\n'
def make(family,chain=1,pool=2,token=3,recipient=4):
 h=native_hash if family=='native' else hash_span
 tree=Tree(h)
 alice=[note(h,token,700,0x321,0x5678),note(h,token,400,0x321,0x111)]
 for n in alice:n['index']=tree.insert(n['cm'])
 bob=note(h,token,600,0x777,0x9999);change=note(h,token,460,0x321,0xaaaa)
 pay=prover(chain,pool,token,tree,alice,[bob,change],40,recipient)
 for n in [bob,change]:n['index']=tree.insert(n['cm'])
 withdraw=prover(chain,pool,token,tree,[bob],[],600,recipient)
 d=ROOT/f'statement-{family}';(d/'fixtures').mkdir(exist_ok=True)
 (d/'Prover.toml').write_text(toml(pay))
 (d/'fixtures/alice-pay.toml').write_text(toml(pay))
 (d/'fixtures/bob-withdraw.toml').write_text(toml(withdraw))
 public={'chain':chain,'pool':pool,'token':token,'recipient':recipient,'deposits':[{'amount':n['amount'],'inner':n['inner'],'cm':n['cm']} for n in alice],
  'alice':{'root':int(pay['root']),'nullifiers':[n['nf'] for n in alice],'outputs':[bob['cm'],change['cm']],'withdrawal':40},
  'bob':{'root':int(withdraw['root']),'nullifiers':[bob['nf']],'outputs':[],'withdrawal':600}}
 (d/'fixtures/public.json').write_text(json.dumps(public,indent=2)+'\n')
 assert str(bob['owner']) not in [v['owner'] for v in pay['inputs']]
 return public
if __name__=='__main__':
 for f in ['native','felt']:make(f)
