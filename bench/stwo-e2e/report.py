"""Archive an explicit allowlist of public results, never private run inputs."""
from common import *
import shutil,hashlib,decimal
s=json.loads((RUN/'results/summary.json').read_text());assert s['status']=='PASS' and s['stage']==4
out=HERE/'results';out.mkdir(exist_ok=True)
for name in ['summary.json','fee-token-address-check.json','pool-and-adapter-tests.log','transient-state-read-failure.json','resume-check.json']:
 shutil.copy2(RUN/'results'/name,out/name)
shutil.copy2(RUN/'deployment.json',out/'deployment.json')
for pattern in ['state-*.json','negative-*.json','events-*.json']:
 for p in (RUN/'results').glob(pattern):shutil.copy2(p,out/p.name)
for name in ['payment','recipient-respend','withdrawal','zero-recipient','invalid-owner','invalid-conservation']:
 src=RUN/'cases'/name;dest=out/'cases'/name;dest.mkdir(parents=True,exist_ok=True)
 allow=['benchmark.json','base-block.json','cgroup.txt'] if name.startswith('invalid-') else ['benchmark.json','base-block.json','prover.log','cgroup.txt','local-verification.log','proof.bin','proof-facts.txt','public-call.json']
 for file in allow:
  if (src/file).exists():shutil.copy2(src/file,dest/file)
for p in (RUN/'results').glob('*/receipt.json'):
 dest=out/'transactions'/p.parent.name;dest.mkdir(parents=True,exist_ok=True);shutil.copy2(p,dest/'receipt.json')
# Public proof-facts/call data only. Proof and source bytes are independently identified.
assert not list(out.rglob('*private*')) and not list(out.rglob('*signed*')) and not list(out.rglob('*request*'))
rows=[]
for name in ['payment','recipient-respend','withdrawal']:
 p=s['proofs'][name];tx=s['transactions'][name];fee=decimal.Decimal(int(tx['actual_fee']['amount'],16))/decimal.Decimal(10**18)
 rows.append(f"| {name} | {p['request_seconds']:.3f} s | {p['peak_rss_gib']:.2f} GiB | {p['proof_bytes']:,} | {tx['execution_resources']['l2_gas']:,} | {fee:.6f} |")
(out/'measurements.md').write_text('| Step | Prover request | Peak RSS | Proof bytes | L2 gas | Actual test-STRK fee |\n|---|---:|---:|---:|---:|---:|\n'+'\n'.join(rows)+'\n')
files=sorted(p for p in out.rglob('*') if p.is_file() and p.name!='SHA256SUMS');(out/'SHA256SUMS').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+str(p.relative_to(out))+'\n' for p in files))
print((out/'measurements.md').read_text());print('Archived',len(files),'public records',sum(p.stat().st_size for p in files),'bytes')
