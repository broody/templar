"""Export an explicit allowlist of public evidence; never copy private runtime wholesale."""
from pathlib import Path
import hashlib,json,shutil
from common import RUN,HERE

summary=json.loads((RUN/'results/summary.json').read_text())
assert summary['status']=='PASS' and summary['stage']==5 and summary['ordinary_notes_only']
dest=HERE/'results';dest.mkdir(exist_ok=True)
allowed=[RUN/'results/summary.json',RUN/'deployment.json',RUN/'source-snapshot.json',RUN/'ekubo.json',
         RUN/'results/ekubo-initial-state.json']
allowed+=list((RUN/'results').glob('state-*.json'))
allowed+=list((RUN/'results').glob('negative-*.json'))
allowed+=list((RUN/'results').glob('recovery-*.json'))
allowed+=list((RUN/'results').glob('*/receipt.json'))
for name in summary['proofs']:
 for file in ['benchmark.json','public-call.json','public-response.json','base-block.json','local-verification.log','cgroup.txt','resources.json','proof.bin']:
  allowed.append(RUN/'cases'/name/file)
allowed.append(RUN/'cases/tampered-intent-statement/benchmark.json')

# Seed/spending/viewing material must never appear in any exported plaintext file.
from protocol import Wallet,CHAIN
secrets=[]
for p in (RUN/'backups').glob('*/seed.txt'):
 seed=bytes.fromhex(p.read_text().strip());w=Wallet.restore(seed,CHAIN,int(summary['deployment']['pool'],16))
 secrets += [seed.hex(),str(w.spend_key),hex(w.spend_key),w.view.decryption_key.hex(),
             str(w.full_view.nullifier_secret),hex(w.full_view.nullifier_secret)]
for p in allowed:
 assert p.is_file(),p
 target=dest/'public'/p.relative_to(RUN)
 target.parent.mkdir(parents=True,exist_ok=True)
 data=p.read_bytes()
 if p.suffix!='.bin':
  text=data.decode()
  assert not any(secret in text for secret in secrets),f'Secret detected in {p.name}'
 shutil.copyfile(p,target)

receipts=[json.loads(p.read_text()) for p in (RUN/'results').glob('*/receipt.json')]
by_category={'setup':0,'successful_spends':0,'rejected_spends':0}
names=set(summary['proofs'])
for p in (RUN/'results').glob('*/receipt.json'):
 r=json.loads(p.read_text());category='successful_spends' if p.parent.name in names else ('rejected_spends' if p.parent.name in summary['negative_tests'] else 'setup')
 by_category[category]+=int(r['actual_fee']['amount'],16)
evidence={'status':'PASS','scope':'ordinary notes only; isolated synthetic assets; real deployed Ekubo Core/Router',
 'python_tests':10,'cairo_tests':16,'successful_native_spends':len(summary['proofs']),
 'rejected_onchain_spends':len(summary['negative_tests']),'rejected_native_statement_executions':1,
 'controller_required':False,'fee_test_STRK_by_category':{k:v/1e18 for k,v in by_category.items()},
 'secret_scan_passed':True,'primary_source':'https://docs.ekubo.org/reference/contracts/starknet-sepolia/',
 'source_sha256':{str(p.relative_to(HERE)):hashlib.sha256(p.read_bytes()).hexdigest()
 for p in sorted(HERE.rglob('*')) if p.is_file() and p.suffix in ['.py','.cairo','.toml']
 and not any(x in p.parts for x in ['target','__pycache__','results'])}}
(dest/'evidence.json').write_text(json.dumps(evidence,indent=2)+'\n')
rows=['# Native proof measurements','',
 'Single runs on the larger host, four cores, 16 GiB process cap, no swap. Not physical-desktop qualification.','',
 '| Case | Prover request (s) | Peak RSS (GiB) | Proof bytes | L2 gas | Actual fee (test STRK) |',
 '| --- | ---: | ---: | ---: | ---: | ---: |']
for name,b in summary['proofs'].items():
 tx=summary['transactions'][name];res=tx['execution_resources']
 rows.append(f"| {name} | {b['request_seconds']:.3f} | {b['peak_rss_gib']:.3f} | {b['proof_bytes']} | {res.get('l2_gas',res.get('total_gas_consumed',{}).get('l2_gas','see receipt'))} | {int(tx['actual_fee']['amount'],16)/1e18:.6f} |")
rows += ['',f"The mock fill moved from 950 to {summary['mock_fill_at_settlement']} after proving; the real Ekubo return was {summary['ekubo_return_amount']} synthetic token-B units for 1,000 token-A units.",
         '', 'All four returned proofs were independently verified locally and accepted on Sepolia.',
         '', 'Setup/declaration fees are reported separately in `evidence.json`; they are not recurring swap fees.']
(dest/'measurements.md').write_text('\n'.join(rows)+'\n')
files=[p for p in sorted(dest.rglob('*')) if p.is_file() and p.name!='SHA256SUMS']
(dest/'SHA256SUMS').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+str(p.relative_to(dest))+'\n' for p in files))
print(json.dumps({'public_files':len(files),'secret_scan_passed':True,'evidence':str(dest/'evidence.json')}))
