#!/usr/bin/env python3
"""Summarize persisted measurements without extrapolating failed runs."""
from pathlib import Path
import hashlib,json,re,statistics
ROOT=Path(__file__).resolve().parent
rows=[]
for d in [*sorted((ROOT/'cases').glob('*')),ROOT/'statement-felt',ROOT/'statement-native',ROOT/'statement-native-wide']:
 p=d/'results/summary.json'
 if not p.exists():continue
 data=json.loads(p.read_text());stages=data['stages'];proof=[r for r in stages if r['stage'].startswith('prove-') and r['exit_code']==0]
 row={'case':d.name,'complete':bool(data.get('completed')),'gates':data.get('gates',{}).get('functions',[{}])[0].get('circuit_size'),
      'prove_median_s':statistics.median(r['wall_seconds'] for r in proof) if proof else None,
      'prove_max_rss_mib':max(r['max_rss_kib'] for r in proof)/1024 if proof else None,
      'proof_bytes':data.get('files',{}).get('proof',{}).get('bytes')}
 for name in ['compile','witness']:
  match=next((r for r in stages if r['stage']==name),{})
  row[name+'_s']=match.get('wall_seconds');row[name+'_rss_mib']=(match['max_rss_kib']/1024 if match.get('max_rss_kib') else None)
  if match and match.get('exit_code')!=0:row['failure']=match
 rows.append(row)
flow=(ROOT/'results/flow-tests.log').read_text()
gas={name:int(g) for name,g in re.findall(r'\[PASS\] desktop::flow_tests::(\w+) \(l1_gas: ~\d+, l1_data_gas: ~\d+, l2_gas: ~(\d+)\)',flow)}
assert 'Tests: 6 passed, 0 failed' in flow
deltas={'two_deposits':gas['funded_baseline']-gas['export_context'],
        'alice_payment':gas['alice_payment']-gas['funded_baseline'],
        'bob_withdrawal':gas['deposit_payment_withdrawal']-gas['alice_payment']}
artifacts={}
for who in ['alice','bob']:
 folder=ROOT/'statement-native/results'/who
 artifacts[who]={n:{'bytes':(folder/n).stat().st_size,'sha256':hashlib.sha256((folder/n).read_bytes()).hexdigest()} for n in ['proof','public_inputs','proof_calldata.txt']}
 artifacts[who]['calldata_felts']=len((folder/'proof_calldata.txt').read_text().split())
 assert (ROOT/f'cairo/tests/{who}.txt').read_bytes()==(folder/'proof_calldata.txt').read_bytes()
report={'cases':rows,'flow_gas_raw':gas,'flow_gas_deltas':deltas,'flow_artifacts':artifacts,
        'limitations':['Native CLI on a constrained i9, not a consumer-machine or browser measurement.',
                       'Sweep stages overlapped a separate compiler experiment; indicative timings.',
                       'Fork test gas deltas exclude account validation, transaction calldata pricing and production fee market.',
                       'Experimental ordinary pool only; production migration, controllers and audit remain outstanding.']}
(ROOT/'results/report.json').write_text(json.dumps(report,indent=2)+'\n')
for row in rows:print(row)
print(deltas)
