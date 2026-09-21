"""Export deltas relative to the reviewed Cairo-memory source copies."""
from pathlib import Path
import difflib, json
H=Path(__file__).resolve().parent
E=json.loads((H/'environment.json').read_text());W=Path(E['work']);OLD=Path(E['previous_work'])
def export(items,name):
 chunks=[]
 for old,new,label in items:
  before=old.read_text().splitlines(True) if old.exists() else []
  chunks.extend(difflib.unified_diff(before,new.read_text().splitlines(True),fromfile='a/'+label,tofile='b/'+label))
 (H/name).write_text(''.join(chunks))
export([(OLD/p,W/p,p) for p in ['proving-utils/crates/privacy_prove/src/low_memory.rs','sequencer/crates/starknet_transaction_prover/src/proving/prover.rs']], 'integration.patch')
for directory,base in [('stwo',OLD/'stwo'),('stwo-cairo',OLD/'stwo-cairo'),('stwo-circuits',Path(E['stwo_circuits_original']))]:
 items=[]
 for new in sorted((W/directory).rglob('*.rs')):
  rel=new.relative_to(W/directory)
  if 'target' in rel.parts:continue
  old=base/rel
  if not old.exists() or old.read_bytes()!=new.read_bytes():items.append((old,new,str(rel)))
 export(items,directory+'.patch')
print('Exported bounded-memory experiment patches.')
