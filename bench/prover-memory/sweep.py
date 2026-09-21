"""Sequential measurements: no overlapping provers or builds on benchmark cores."""
from pathlib import Path
import json,subprocess,sys
H=Path(__file__).resolve().parent

def run(name,fixture,variant,cap=12,block=None,requests=1,extra=()):
 args=[sys.executable,str(H/'run.py'),'--name',name,'--fixture',fixture,'--variant',variant,'--cap',str(cap),'--requests',str(requests),*extra]
 if block:args+=['--block',str(block)]
 with (H/'results'/f'{name}-driver.log').open('w') as log:
  p=subprocess.run(args,stdout=log,stderr=subprocess.STDOUT)
 s=json.loads((H/'results'/name/'summary.json').read_text())
 print(json.dumps({'name':name,'status':s.get('status'),'rss_gib':s.get('peak_rss_gib'),'heap_gib':s.get('peak_requested_gib'),'request_seconds':[r['request_seconds'] for r in s['requests']],'error':s.get('error')}),flush=True)
 return s

block=15391165
run('ordinary-one-thread','ordinary','staged',block=block,extra=('--threads','1'))
run('ordinary-staged-repeat','ordinary','staged',block=block,requests=3,extra=('--trace-spans',))
run('ordinary-staged-8-cap','ordinary','staged',cap=8,block=block)
for fixture in ['controlled','8-8-4','return']:
 baseline=run(f'{fixture}-stock',''+fixture,'stock',16)
 if baseline.get('status')!='PASS':raise RuntimeError('Baseline failed')
 result=run(f'{fixture}-staged-repeat',fixture,'staged',block=baseline['base_block'],requests=3)
 if result.get('status')!='PASS':raise RuntimeError('Staged regression')
run('invalid-intent-staged','invalid-intent','staged')
