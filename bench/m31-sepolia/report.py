"""Copy allowlisted public evidence from the private runtime into `results/`: deployment,
states, negatives, receipts, gateway responses, proof facts and benchmarks. Never wallet
secrets, spend witnesses, client inputs or signed requests."""
from sepolia import *
import hashlib, shutil, sys

# `report.py [SUBDIR]`: archive under results/SUBDIR (each run keeps its own evidence).
OUT = HERE / 'results' / (sys.argv[1] if len(sys.argv) > 1 else '')
OUT.mkdir(exist_ok=True)


def copy(src, dst):
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)


for name in ['deployment.json', 'classes.json', 'source-snapshot.json']:
    if (RUN / name).exists():
        copy(RUN / name, OUT / name)
for p in (RUN / 'results').glob('*.json'):
    copy(p, OUT / p.name)
for p in (RUN / 'steps').glob('*/*'):
    if p.name in ('receipt.json', 'response.json', 'gateway-response.json'):
        copy(p, OUT / 'transactions' / p.parent.name / p.name)
for case in (RUN / 'cases').glob('*'):
    for rel in ['server/benchmark.json', 'server/base-block.json', 'server/proof-facts.txt', 'server/proof2/summary.json',
                'server/proof2/run.log', 'server/capture/capture.json', 'client/public.json', 'client/report.json',
                'client/trusted-config.json']:
        if (case / rel).exists():
            copy(case / rel, OUT / 'cases' / case.name / rel)
banned = ('private', 'signed', 'request', 'spend', 'wallet', 'cairo-arguments')
leaks = [p for p in OUT.rglob('*') if p.is_file() and any(b in p.name for b in banned)]
assert not leaks, leaks
for p in OUT.rglob('*.json'):
    for w in load(RUN / 'private-wallets.json').values():
        assert json.dumps(w['sk'])[1:-1] not in p.read_text(), f'secret in {p}'
files = sorted(p for p in OUT.rglob('*') if p.is_file() and p.name != 'SHA256SUMS')
(OUT / 'SHA256SUMS').write_text(''.join(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(OUT)}\n' for p in files))
print('archived', len(files), 'files')
