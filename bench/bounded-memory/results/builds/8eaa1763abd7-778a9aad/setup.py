"""Isolate the reviewed Cairo-memory baseline for bounded-column experiments."""
from pathlib import Path
import json, shutil, subprocess, tomllib
H=Path(__file__).resolve().parent
PREVIOUS=H.parent/'cairo-memory'
E=json.loads((PREVIOUS/'environment.json').read_text())
OLD=Path(E['work']);W=H.parent.parent/'target/bounded-memory'
W.mkdir(parents=True,exist_ok=True);(H/'results').mkdir(exist_ok=True)
for name in ['stwo','stwo-cairo','sequencer','proving-utils']:
 if not (W/name).exists():
  shutil.copytree(OLD/name,W/name,ignore=shutil.ignore_patterns('.git','target'))
CIRCUITS=Path('/home/broody/.cargo/git/checkouts/stwo-circuits-acca305c7c7af9d7/5ef951a')
if not (W/'stwo-circuits').exists():
 shutil.copytree(CIRCUITS,W/'stwo-circuits',ignore=shutil.ignore_patterns('.git','target'))
manifest=W/'sequencer/Cargo.toml';s=manifest.read_text()
header='[patch."https://github.com/starkware-libs/stwo"]'
entry='stwo-constraint-framework = { path = "../stwo/crates/constraint-framework" }'
if entry not in s:s=s.replace(header,header+'\n'+entry)
header='[patch."https://github.com/starkware-libs/stwo-circuits"]'
if header not in s:
 s+='\n'+header+'\n'
 active={p['name'] for p in tomllib.loads((OLD/'sequencer/Cargo.lock').read_text())['package'] if 'stwo-circuits' in p.get('source','')}
 for path in sorted((W/'stwo-circuits/crates').glob('*/Cargo.toml')):
  name=tomllib.loads(path.read_text())['package']['name']
  if name in active:s+=f'{name} = {{ path = "../stwo-circuits/crates/{path.parent.name}" }}\n'
manifest.write_text(s)
for name in ['rust-target','public-rpc-cache','stwo-test-target']:
 if (OLD/name).exists() and not (W/name).exists():
  subprocess.run(['cp','-a','--reflink=auto',str(OLD/name),str(W/name)],check=True)
(W/'bin').mkdir(exist_ok=True)
shutil.copy2(OLD/'bin/low-memory-prover',W/'bin/baseline-prover')
E.update(work=str(W),previous_work=str(OLD),previous_benchmark=str(PREVIOUS),baseline_prover=str(W/'bin/baseline-prover'),stwo_circuits_original=str(CIRCUITS))
(H/'environment.json').write_text(json.dumps(E,indent=2)+'\n')
print('Isolated bounded-column experiment ready.')
