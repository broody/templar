"""Qualification after the long-lived release process exceeded its cap."""
from pathlib import Path
import json,subprocess,sys
H=Path(__file__).resolve().parent
cases=[('8-8-4-release-native-allocator','8-8-4','8-8-4-stock',3,['--native-allocator']),('8-8-4-release-fresh-a','8-8-4','8-8-4-stock',1,[]),('8-8-4-release-fresh-b','8-8-4','8-8-4-stock',1,[]),('8-8-4-release-fresh-c','8-8-4','8-8-4-stock',1,[]),('return-release-repeat','return','return-stock',3,[])]
for name,fixture,source,count,extra in cases:
 old=json.loads((H/'results'/source/'summary.json').read_text())
 with (H/'results'/f'{name}-driver.log').open('w') as log:
  p=subprocess.run([sys.executable,str(H/'run.py'),'--variant','staged-release','--fixture',fixture,'--block',str(old['base_block']),'--cap','12','--requests',str(count),'--name',name,*extra],stdout=log,stderr=subprocess.STDOUT)
 s=json.loads((H/'results'/name/'summary.json').read_text())
 print(json.dumps({'name':name,'status':s.get('status'),'rss_gib':s.get('peak_rss_gib'),'request_seconds':[r['request_seconds'] for r in s['requests']],'error':s.get('error')}),flush=True)
