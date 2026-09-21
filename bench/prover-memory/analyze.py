"""Summarize retained public measurements; never opens private fixture files."""
from pathlib import Path
import csv,datetime,hashlib,json,re,statistics
H=Path(__file__).resolve().parent;R=H/'results'
def ms(line):
 try:return datetime.datetime.fromisoformat(line.split()[0].replace('Z','+00:00')).timestamp()*1000
 except (ValueError,IndexError):return None
rows=[]
for path in sorted(R.glob('*/summary.json')):
 d=path.parent;s=json.loads(path.read_text());text=re.sub(r'\x1b\[[0-9;]*m','',(d/'prover.log').read_text())
 s['name']=d.name
 s['proving_seconds']=[int(t)/1000 for t in re.findall(r'Proving completed prove_duration_ms=(\d+)',text)]
 s['virtual_os_seconds']=[int(t)/1000 for t in re.findall(r'OS execution completed os_duration_ms=(\d+)',text)]
 if (d/'heap.csv').exists():
  heap=list(csv.DictReader((d/'heap.csv').open()));samples=json.loads((d/'resources.json').read_text());phases=[]
  needles=['Generate the cairo proof','Cairo stage tree and buffer pool released','Prepare the cairo proof for the cairo-circuit verifier','Prove the cairo-circuit verifier','Recursive stage tree and buffer pool released','Proving completed']
  for line in text.splitlines():
   t=ms(line)
   if t is None or not any(n in line for n in needles) or not heap:continue
   h=min(heap,key=lambda h:abs(int(h['unix_ms'])-t));p=min(samples,key=lambda p:abs(p['unix_ms']-t))
   phases.append({'stage':line.split(': ')[-1],'unix_ms':t,'live_requested_gib':int(h['live_requested_bytes'])/2**30,'peak_requested_gib':int(h['peak_requested_bytes'])/2**30,'rss_gib':p.get('VmRSS_KiB',0)/2**20,'rss_high_water_gib':p.get('VmHWM_KiB',0)/2**20})
  s['phase_snapshots']=phases
  if samples:s['final_rss_gib']=samples[-1].get('VmRSS_KiB',0)/2**20
 # Histogram contains one entry per size per proof. Keep first Cairo proof only.
 hist={}
 for line in text.splitlines():
  if 'prove_cairo' in line:
   m=re.search(r'Log size (\d+): (\d+)',line)
   if m:
    k=int(m[1])
    if k in hist:break
    hist[k]=int(m[2])
 if hist:s['cairo_committed_evaluations']={'columns_by_log_size':hist,'gib':sum(4*(1<<k)*v for k,v in hist.items())/2**30}
 rows.append(s)
# Compare deterministic outputs only for exactly matching witness/block requests.
comparisons=[]
for i,a in enumerate(rows):
 if a.get('status')!='PASS':continue
 for b in rows[i+1:]:
  if b.get('status')!='PASS' or a['private_request_sha256']!=b['private_request_sha256']:continue
  identical=a['requests'][0]['proof_sha256']==b['requests'][0]['proof_sha256']
  comparisons.append({'a':a['name'],'b':b['name'],'byte_identical':identical})
  assert identical,(a['name'],b['name'])
for s in rows:
 if s.get('status')=='PASS':
  assert s['swap_peak_bytes']==0 and s['oom_kill']==0
  assert all(r['verification_and_three_mutation_rejections'] and r['public_binding_matches'] for r in s['requests'])
report={'results':rows,'same_request_comparisons':comparisons,'verified_proof_count':sum(len(s['requests']) for s in rows),'scope':'Local verification of replays; no live submission or physical desktop/browser qualification.'}
(R/'summary.json').write_text(json.dumps(report,indent=2)+'\n')
lines=['# Native PROOF1 memory measurements','', '| Run | Result | RSS peak GiB | Rust requested peak GiB | Proving seconds | Requests |', '| --- | --- | ---: | ---: | --- | ---: |']
for s in rows:
 times=', '.join(f'{t:.2f}' for t in s['proving_seconds']);heap=s.get('peak_requested_gib');rss=f"{s['peak_rss_gib']:.2f}" if s.get('peak_rss_gib') is not None else '—'
 lines.append(f"| {s['name']} | {s.get('status','RUNNING')} | {rss} | {heap:.2f} | {times} | {len(s['requests'])} |" if heap is not None else f"| {s['name']} | {s.get('status','RUNNING')} | {rss} | — | {times} | {len(s['requests'])} |")
(R/'measurements.md').write_text('\n'.join(lines)+'\n')
print('\n'.join(lines));print('Verified proofs:',report['verified_proof_count'])
