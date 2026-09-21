"""Isolate the pinned stage-local baseline for Cairo working-set experiments.

Reuses the previous experiment's public RPC cache and build cache. Neither its
source copies nor accepted prover/verifier binaries are modified.
"""
from pathlib import Path
import json, shutil, subprocess

H = Path(__file__).resolve().parent
ROOT = H.parent.parent
PREVIOUS = H.parent / 'prover-memory'
E = json.loads((PREVIOUS / 'environment.json').read_text())
OLD = Path(E['work'])
W = ROOT / 'target/cairo-memory'
STWO = Path('/home/broody/.cargo/git/checkouts/stwo-59e22971a65c0edb/489a0f3')
CAIRO = Path('/home/broody/.cargo/git/checkouts/stwo-cairo-ef02e8e85a2fe399/9b6be27')
W.mkdir(parents=True, exist_ok=True)
(H / 'results').mkdir(exist_ok=True)

for name, original, patch in [
    ('sequencer', Path(E['sequencer_original']), 'sequencer.patch'),
    ('proving-utils', Path(E['proving_original']), 'proving-utils.patch'),
]:
    destination = W / name
    if not destination.exists():
        shutil.copytree(original, destination, ignore=shutil.ignore_patterns('.git', 'target'))
        subprocess.run(['patch', '-p1', '-i', str(PREVIOUS / patch)], cwd=destination, check=True)
if not (W / 'stwo').exists():
    shutil.copytree(STWO, W / 'stwo', ignore=shutil.ignore_patterns('.git', 'target'))
if not (W / 'stwo-cairo').exists():
    shutil.copytree(CAIRO, W / 'stwo-cairo', ignore=shutil.ignore_patterns('.git', 'target'))
for name in ['rust-target', 'public-rpc-cache']:
    if not (W / name).exists():
        subprocess.run(['cp', '-a', '--reflink=auto', str(OLD / name), str(W / name)], check=True)
(W / 'bin').mkdir(exist_ok=True)
shutil.copy2(OLD / 'bin/low-memory-prover', W / 'bin/baseline-prover')

manifest = W / 'sequencer/Cargo.toml'
s = manifest.read_text()
if '[patch."https://github.com/starkware-libs/stwo"]' not in s:
    s += '\n[patch."https://github.com/starkware-libs/stwo"]\nstwo = { path = "../stwo/crates/stwo" }\n'
if '[patch."https://github.com/starkware-libs/stwo-cairo"]' not in s:
    s += '\n[patch."https://github.com/starkware-libs/stwo-cairo"]\nstwo-cairo-prover = { path = "../stwo-cairo/stwo_cairo_prover/crates/prover" }\n'
for package, directory in [('cairo-air', 'cairo-air'), ('stwo-cairo-adapter', 'adapter'),
                           ('stwo-cairo-common', 'common'), ('stwo-cairo-serialize', 'cairo-serialize'),
                           ('stwo-cairo-serialize-derive', 'cairo-serialize-derive')]:
    entry = f'{package} = {{ path = "../stwo-cairo/stwo_cairo_prover/crates/{directory}" }}\n'
    if entry not in s:
        s += entry
manifest.write_text(s)
E.update(work=str(W), stwo_original=str(STWO),
         stwo_revision=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=STWO, text=True).strip(),
         baseline_prover=str(W / 'bin/baseline-prover'), stwo_cairo_original=str(CAIRO))
(H / 'environment.json').write_text(json.dumps(E, indent=2) + '\n')
print('Isolated Cairo working-set experiment ready.')
