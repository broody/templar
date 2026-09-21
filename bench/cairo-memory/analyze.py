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
 samples=json.loads((d/'resources.json').read_text()) if (d/'resources.json').exists() else []
 stage_peaks={}
 for label,begin,end in [('cairo','Prepare only the Cairo stage','Cairo stage tree and buffer pool released'),('recursive','Prepare only the recursive circuit stage','Recursive stage tree and buffer pool released')]:
  intervals=[];started=None
  for line in text.splitlines():
   t=ms(line)
   if t is None:continue
   if begin in line:started=t
   if end in line and started is not None:
    intervals.append((started,t));started=None
  if started is not None:intervals.append((started,float('inf')))
  values=[p.get('VmRSS_KiB',0)/2**20 for p in samples if any(a<=p['unix_ms']<=b for a,b in intervals)]
  if values:stage_peaks[label]=max(values)
 if stage_peaks:s['sampled_stage_peak_rss_gib']=stage_peaks
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
previous=json.loads((H.parent/'prover-memory/results/summary.json').read_text())['results']
previous_comparisons=[]
for s in rows:
 for record in s['requests']:
  assert record['proof_sha256']==s['requests'][0]['proof_sha256'],s['name']
 if not s['requests']:continue
 matches=[p for p in previous if p['requests'] and p['private_request_sha256']==s['private_request_sha256']]
 assert matches, f"No archived baseline for {s['name']}"
 p=matches[0]
 assert s['requests'][0]['proof_sha256']==p['requests'][0]['proof_sha256'],s['name']
 previous_comparisons.append({'run':s['name'],'previous_experiment_run':p['name'],'byte_identical':True,'requests':len(s['requests'])})
for s in rows:
 if s.get('status')=='PASS':
  assert s['swap_peak_bytes']==0 and s['oom_kill']==0
  assert all(r['verification_and_three_mutation_rejections'] and r['public_binding_matches'] for r in s['requests'])
report={'results':rows,'same_request_comparisons':comparisons,'previous_experiment_comparisons':previous_comparisons,'verified_proof_count':sum(len(s['requests']) for s in rows),'scope':'Local verification of replays; no live submission or physical desktop/browser qualification.'}
(R/'summary.json').write_text(json.dumps(report,indent=2)+'\n')
lines=['# Native PROOF1 memory measurements','', '| Run | Result | RSS peak GiB | Rust requested peak GiB | Proving seconds | Requests |', '| --- | --- | ---: | ---: | --- | ---: |']
for s in rows:
 times=', '.join(f'{t:.2f}' for t in s['proving_seconds']);heap=s.get('peak_requested_gib');rss=f"{s['peak_rss_gib']:.2f}" if s.get('peak_rss_gib') is not None else '—'
 lines.append(f"| {s['name']} | {s.get('status','RUNNING')} | {rss} | {heap:.2f} | {times} | {len(s['requests'])} |" if heap is not None else f"| {s['name']} | {s.get('status','RUNNING')} | {rss} | — | {times} | {len(s['requests'])} |")
(R/'measurements.md').write_text('\n'.join(lines)+'\n')
print('\n'.join(lines));print('Verified proofs:',report['verified_proof_count'])
