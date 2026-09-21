"""Archive explicitly allowlisted public evidence from the synthetic live test."""
from common import *
import shutil,hashlib,decimal,re
summary=json.loads((RUN/'results/summary.json').read_text())
assert summary['status']=='PASS' and summary['stage']==5
out=HERE/'results';out.mkdir(exist_ok=True)
def copy_file(source,destination):
 destination.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(source,destination)
for name in ['deployment.json','source-snapshot.json']:copy_file(RUN/name,out/name)
for pattern in ['summary.json','resume-check.json','final-reconciliation.json','state-*.json','negative-*.json','sync-*.json','recovery-report-*.json']:
 for p in (RUN/'results').glob(pattern):copy_file(p,out/p.name)
for folder in (RUN/'wallets').iterdir():
 for name in ['summary.json','sync.json']:
  if (folder/name).exists():copy_file(folder/name,out/'wallets'/folder.name/name)
cases=['controlled-payment','controlled-respend','controlled-withdrawal','ordinary-payment','expired-proof','redirected-proof']
for name in cases:
 source=RUN/'cases'/name
 for file in ['benchmark.json','base-block.json','cgroup.txt','proof.bin','proof-facts.txt','public-call.json','local-verification.log','prover.log']:
  copy_file(source/file,out/'cases'/name/file)
 b=json.loads((source/'benchmark.json').read_text());assert b['local_verification_passed'] and b['public_binding_matches']
 assert hashlib.sha256((source/'proof.bin').read_bytes()).hexdigest()==b['proof_sha256']
for name in ['controller-cannot-spend','controller-cannot-be-stripped']:
 copy_file(RUN/'cases'/name/'benchmark.json',out/'cases'/name/'benchmark.json')
for p in (RUN/'results').glob('*/receipt.json'):copy_file(p,out/'transactions'/p.parent.name/'receipt.json')
assert not any(any(k in p.name for k in ['private','signed','request','seed','full-view']) for p in out.rglob('*') if p.is_file())
rows=[]
for name in cases[:4]:
 p=summary['proofs'][name];tx=summary['transactions'][name];fee=decimal.Decimal(int(tx['actual_fee']['amount'],16))/decimal.Decimal(10**18)
 rows.append(f"| {name} | {p['request_seconds']:.3f} s | {p['peak_rss_gib']:.2f} GiB | {p['proof_bytes']:,} | {tx['execution_resources']['l2_gas']:,} | {tx['execution_resources']['l1_data_gas']:,} | {fee:.6f} |")
(out/'measurements.md').write_text('| Step | Prover request | Peak RSS | Proof bytes | L2 gas | L1 data gas | Actual test-STRK fee |\n|---|---:|---:|---:|---:|---:|---:|\n'+'\n'.join(rows)+'\n')
snap=json.loads((RUN/'source-snapshot.json').read_text())
for name,expected in snap['source_hashes'].items():assert hashlib.sha256((HERE/name).read_bytes()).hexdigest()==expected,name
tests=(out/'python-tests.log').read_text();cairo=(out/'cairo-tests.log').read_text()
assert tests.rstrip().endswith('OK') and 'Tests: 68 passed, 0 failed' in cairo
save(out/'evidence.json',{'status':'PASS','python_tests':int(re.search(r'Ran (\d+) tests',tests)[1]),'cairo_tests':68,
 'successful_native_spends':4,'native_proofs_verified':6,'native_statement_rejections':2,'onchain_rejections':summary['negative_tests'],
 'source_hashes':{str(p.relative_to(HERE)):hashlib.sha256(p.read_bytes()).hexdigest() for p in [*HERE.glob('*.py'),HERE/'README.md',HERE/'REVIEW.md',HERE/'cairo/Scarb.toml',HERE/'cairo/Scarb.lock',*sorted((HERE/'cairo/src').rglob('*.cairo'))]},'public_archive_only':True})
files=sorted(p for p in out.rglob('*') if p.is_file() and p.name!='SHA256SUMS')
(out/'SHA256SUMS').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+str(p.relative_to(out))+'\n' for p in files))
print((out/'measurements.md').read_text());print('Archived',len(files),'public evidence files.')
