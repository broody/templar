#!/usr/bin/env python3
from pathlib import Path
import copy,json,shutil,tomllib
from bench import stage
from fixtures import toml
ROOT=Path(__file__).resolve().parent;project=ROOT/'statement-native'
base=tomllib.loads((project/'fixtures/alice-pay.toml').read_text())
# The payer's witness contains only its own input secrets and recipients' invoices.
assert all(set(row)=={'inner','amount'} for row in base['outputs'])
assert all(row['owner']==str(0x321) for row in base['inputs'])
cases={}
d=copy.deepcopy(base);d['inputs'][0]['owner']=str(0x999);cases['wrong-owner']=d
d=copy.deepcopy(base);d['outputs'][0]['amount']=str(int(d['outputs'][0]['amount'])+1);cases['inflation']=d
d=copy.deepcopy(base);d['inputs'][1]=copy.deepcopy(d['inputs'][0]);d['outputs'][1]['amount']='760';cases['duplicate-input']=d
# Keep conservation valid for duplicate input: 700+700=600+760+40.
d=copy.deepcopy(base);d['inputs'][0]['path'][0]='0';cases['bad-path']=d
rows=[]
for name,data in cases.items():
 path=project/f'negative-{name}.toml';path.write_text(toml(data))
 result=stage(project,f'negative-{name}',[shutil.which('nargo'),'execute','-p',path.stem])
 rows.append(result)
 log=(project/'results'/f'negative-{name}.log').read_text()
 assert result['exit_code']!=0 and ('assert' in log.lower() or 'constraint' in log.lower()),name
(ROOT/'results/adversarial.json').write_text(json.dumps(rows,indent=2)+'\n')
print('All four invalid witnesses rejected; payer witness contains no recipient secrets.')
