"""Validate uninstrumented native release mode using captured public state."""
from pathlib import Path
import json,subprocess,sys
H=Path(__file__).resolve().parent
for fixture,source in [('ordinary','ordinary-staged-repeat'),('controlled','controlled-stock'),('8-8-4','8-8-4-stock'),('return','return-stock')]:
 old=json.loads((H/'results'/source/'summary.json').read_text())
 name=fixture+'-release-repeat'
 with (H/'results'/f'{name}-driver.log').open('w') as log:
  result=subprocess.run([sys.executable,str(H/'run.py'),'--variant','staged-release','--fixture',fixture,'--block',str(old['base_block']),'--cap','12','--requests','3','--name',name],stdout=log,stderr=subprocess.STDOUT)
 s=json.loads((H/'results'/name/'summary.json').read_text())
 print(json.dumps({'name':name,'status':s.get('status'),'rss_gib':s.get('peak_rss_gib'),'request_seconds':[r['request_seconds'] for r in s['requests']],'error':s.get('error')}),flush=True)
 if result.returncode:raise SystemExit(result.returncode)
