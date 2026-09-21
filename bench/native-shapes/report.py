from pathlib import Path
import hashlib,json,shutil,re,sys
here=Path(sys.argv[1]).resolve() if len(sys.argv)>1 else Path(__file__).resolve().parent;run=Path(json.loads((here/'run-location.json').read_text())['runtime']);out=here/'results';s=json.loads((run/'results/summary.json').read_text())
def cp(source,dest):dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(source,dest)
for name in ['deployment.json','source-snapshot.json']:cp(run/name,out/name)
for p in (run/'results').glob('*/receipt.json'):cp(p,out/'transactions'/p.parent.name/'receipt.json')
rows=[]
for r in s['results']:
 folder=run/'cases'/r['case'];dest=out/'cases'/r['case']
 for name in ['benchmark.json','failure.json','cgroup.txt','base-block.json','proof.bin','proof-facts.txt','local-verification.log','prover.log']:
  if (folder/name).exists():cp(folder/name,dest/name)
 log=re.sub(r'\x1b\[[0-9;]*m','',(folder/'prover.log').read_text())
 m=re.search(r'n_steps=(\d+)',log);r['virtual_os_steps']=int(m[1]) if m else None
 cg=(folder/'cgroup.txt').read_text();r['cgroup_result']=re.search(r'^Result=(.*)$',cg,re.M)[1]
 r['cgroup_peak_gib']=int(re.search(r'^MemoryPeak=(\d+)$',cg,re.M)[1])/2**30
 if r['status']=='PASS':
  assert r['local_verification_passed'] and r['public_binding_matches']
  assert hashlib.sha256((folder/'proof.bin').read_bytes()).hexdigest()==r['proof_sha256']
  measure=f"{r['request_seconds']:.3f} s | {r['peak_rss_gib']:.2f} GiB | {r['proof_bytes']:,} | {r['public_spend_calldata_felts']}"
 else:measure=f"— | ≥{r['cgroup_peak_gib']:.0f} GiB cgroup | — | —"
 shape='/'.join(map(str,r['shape']));rows.append(f"| {shape} | {r['status']} | {measure} | {r['virtual_os_steps']:,} |")
for name in ['reject-over-cap','reject-old-version']:
 p=run/'cases'/name/'benchmark.json';assert json.loads(p.read_text())['rejected'];cp(p,out/'cases'/name/p.name)
(out/'summary.json').write_text(json.dumps(s,indent=2)+'\n')
(out/'measurements.md').write_text('| Inputs/outputs/withdrawals | Outcome | Request | Peak memory | Proof bytes | Public spend felts | Virtual OS steps |\n|---|---|---:|---:|---:|---:|---:|\n'+'\n'.join(rows)+'\n')
snap=json.loads((run/'source-snapshot.json').read_text())
for name,h in snap['source_hashes'].items():assert hashlib.sha256((here/name).read_bytes()).hexdigest()==h
manifest=json.loads((run/'manifest.json').read_text())
for name in ['prover','verifier']:assert hashlib.sha256(Path(manifest[name]).read_bytes()).hexdigest()==manifest[name+'_sha256']
(out/'evidence.json').write_text(json.dumps({'scope':s['scope'],'statement_only':True,'fixed_upper_bound':[64,64,32],
 'memory_cap_gib':16,'cores':4,'swap_allowed':False,'prover_sha256':manifest['prover_sha256'],'verifier_sha256':manifest['verifier_sha256'],
 'source_hashes':{str(p.relative_to(here)):hashlib.sha256(p.read_bytes()).hexdigest() for p in [*here.glob('*.py'),*here.glob('*.md'),*here.glob('cairo/Scarb.*'),*here.glob('cairo/src/*.cairo')]}},indent=2)+'\n')
files=sorted(p for p in out.rglob('*') if p.is_file() and p.name!='SHA256SUMS')
(out/'SHA256SUMS').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+str(p.relative_to(out))+'\n' for p in files))
print((out/'measurements.md').read_text())
