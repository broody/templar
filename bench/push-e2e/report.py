"""Archive allowlisted public evidence, excluding witnesses, keys and signatures."""
from common import *
import shutil,hashlib,decimal,re

summary=json.loads((RUN/'results/summary.json').read_text())
assert summary['status']=='PASS' and summary['stage']==5
out=HERE/'results';out.mkdir(exist_ok=True)
def copy_file(source,destination):
    destination.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(source,destination)
for name in ['deployment.json','source-snapshot.json']:
    copy_file(RUN/name,out/name)
copy_file(RUN/'results/summary.json',out/'summary.json')
copy_file(RUN/'results/recovery-drills.json',out/'recovery-drills.json')
copy_file(RUN/'results/resume-check.json',out/'resume-check.json')
for assessment in (RUN/'results/preflight-failures').glob('*/assessment.json'):
    copy_file(assessment,out/'preflight-failures'/assessment.parent.name/'assessment.json')
for pattern in ['state-*.json','negative-*.json','sync-*.json','recovery-report-*.json']:
    for p in (RUN/'results').glob(pattern):copy_file(p,out/p.name)
for folder in (RUN/'wallets').iterdir():
    for name in ['summary.json','sync.json']:
        if (folder/name).exists():copy_file(folder/name,out/'wallets'/folder.name/name)
cases=['alice-payment','carol-payment','bob-spend','restored-withdrawal']
for name in cases:
    source=RUN/'cases'/name
    for file in ['benchmark.json','base-block.json','cgroup.txt','proof.bin','proof-facts.txt','public-call.json','local-verification.log','prover.log']:
        copy_file(source/file,out/'cases'/name/file)
    benchmark=json.loads((source/'benchmark.json').read_text())
    assert benchmark['local_verification_passed'] and benchmark['public_binding_matches']
    assert hashlib.sha256((source/'proof.bin').read_bytes()).hexdigest()==benchmark['proof_sha256']
copy_file(RUN/'cases/view-key-cannot-spend/benchmark.json',out/'cases/view-key-cannot-spend/benchmark.json')
for receipt in (RUN/'results').glob('*/receipt.json'):
    copy_file(receipt,out/'transactions'/receipt.parent.name/'receipt.json')
assert not any(any(k in p.name for k in ['private','signed','request','seed','full-view']) for p in out.rglob('*') if p.is_file())
rows=[]
for name in cases:
    p=summary['proofs'][name];tx=summary['transactions'][name]
    fee=decimal.Decimal(int(tx['actual_fee']['amount'],16))/decimal.Decimal(10**18)
    rows.append(f"| {name} | {p['request_seconds']:.3f} s | {p['peak_rss_gib']:.2f} GiB | {p['proof_bytes']:,} | {tx['execution_resources']['l2_gas']:,} | {tx['execution_resources']['l1_data_gas']:,} | {fee:.6f} |")
(out/'measurements.md').write_text('| Step | Prover request | Peak RSS | Proof bytes | L2 gas | L1 data gas | Actual test-STRK fee |\n|---|---:|---:|---:|---:|---:|---:|\n'+'\n'.join(rows)+'\n')
snap=json.loads((RUN/'source-snapshot.json').read_text())
for name,expected in snap['source_hashes'].items():
    assert hashlib.sha256((HERE/name).read_bytes()).hexdigest()==expected,name
tests=(out/'python-tests.log').read_text();cairo=(out/'cairo-tests.log').read_text()
assert tests.rstrip().endswith('OK') and 'Tests: 59 passed, 0 failed' in cairo
save(out/'evidence.json',{'status':'PASS','python_tests':int(re.search(r'Ran (\d+) tests',tests)[1]),
    'cairo_tests':59,'successful_native_spends':4,'onchain_rejections':summary['negative_tests'],
    'source_hashes':{str(p.relative_to(HERE)):hashlib.sha256(p.read_bytes()).hexdigest()
        for p in [*HERE.glob('*.py'),HERE/'README.md',HERE/'REVIEW.md',HERE/'cairo/Scarb.toml',HERE/'cairo/Scarb.lock',
                  *sorted((HERE/'cairo/src').rglob('*.cairo'))]},
    'public_archive_only':True})
files=sorted(p for p in out.rglob('*') if p.is_file() and p.name!='SHA256SUMS')
(out/'SHA256SUMS').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+str(p.relative_to(out))+'\n' for p in files))
print((out/'measurements.md').read_text())
print('Archived',len(files),'public evidence files.')
