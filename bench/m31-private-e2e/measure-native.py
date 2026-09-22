"""Bounded native integration measurement; synthetic witness never enters report."""
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys

binary = Path(sys.argv[1]).resolve()
out = Path(sys.argv[2]).resolve()
out.mkdir(parents=True, exist_ok=False)
client, verifier = out / 'client', out / 'verifier'
client.mkdir()
verifier.mkdir()
env = dict(os.environ, RAYON_NUM_THREADS='1')


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def run(name, args, cwd, measured=False, accepted=True):
    command = [str(binary), *map(str, args)]
    executed = command
    if measured:
        executed = ['/usr/bin/time', '-v', '-o', str(out / (name + '.time.log')), *command]
    r = subprocess.run(executed, cwd=cwd, env=env, capture_output=True, timeout=120)
    (out / (name + '.stdout.log')).write_bytes(r.stdout)
    (out / (name + '.stderr.log')).write_bytes(r.stderr)
    assert (r.returncode == 0) == accepted, f'{name}: unexpected exit {r.returncode}'
    item = {'name': name, 'command': executed, 'cwd': str(cwd), 'exit': r.returncode}
    if accepted:
        item['result'] = json.loads(r.stdout)
    else:
        item['rejection'] = r.stderr.decode().strip()
    if measured:
        lines = (out / (name + '.time.log')).read_text().splitlines()
        item['peak_rss_kib'] = int(next(s.rsplit(':', 1)[1] for s in lines if 'Maximum resident set size' in s))
        item['elapsed_wall'] = next(s.split('):', 1)[1].strip() for s in lines if 'Elapsed (wall clock)' in s)
    return item


report = {'binary_sha256': sha(binary), 'binary': str(binary), 'platform': platform.platform(),
          'cpu': next(s.split(':', 1)[1].strip() for s in Path('/proc/cpuinfo').read_text().splitlines() if s.startswith('model name')),
          'mem_total_kib': int(Path('/proc/meminfo').read_text().splitlines()[0].split()[1]),
          'threads': 1, 'fixture': 'fresh synthetic, same witness for three randomized proofs',
          'scope': 'private depth32 membership; separate-process verification, no filesystem access sandbox',
          'runs': [], 'negatives': []}
run('fixture', ['fixture', 'public.json', 'private.json'], client)
assert (client / 'private.json').stat().st_mode & 0o777 == 0o600
shutil.copy2(client / 'public.json', verifier / 'public.json')
for n in range(1, 4):
    name = f'proof-{n}.bin'
    prove = run(f'prove-{n}', ['prove', 'public.json', 'private.json', name], client, True)
    shutil.copy2(client / name, verifier / name)
    verify = run(f'verify-{n}', ['verify', 'public.json', name], verifier, True)
    report['runs'].append({'prove': prove, 'verify': verify, 'proof_sha256': sha(verifier / name),
                           'proof_bytes': (verifier / name).stat().st_size})
assert len({r['proof_sha256'] for r in report['runs']}) == 3
report['verifier_files_before_negatives'] = sorted(p.name for p in verifier.iterdir())
public = json.loads((verifier / 'public.json').read_text())
for field in ['root', 'pool', 'chain']:
    bad = dict(public)
    if field == 'root':
        bad['root'] = public['root'].copy()
        bad['root'][0] = (bad['root'][0] + 1) % 2147483647
    else:
        bad[field] = '0x124' if field == 'pool' else '0x2'
    filename = f'bad-{field}.json'
    (verifier / filename).write_text(json.dumps(bad))
    report['negatives'].append(run('reject-' + field, ['verify', filename, 'proof-1.bin'], verifier, accepted=False))
proof = (verifier / 'proof-1.bin').read_bytes()
flip = bytearray(proof)
flip[len(flip) // 2] ^= 1
noncanonical = bytearray(proof)
noncanonical[8 + 96 * 16:12 + 96 * 16] = (2147483647).to_bytes(4, 'little')
for name, data in [('flip', flip), ('truncated', proof[:-1]), ('trailing', proof + b'\0'), ('noncanonical', noncanonical)]:
    filename = f'bad-{name}.bin'
    (verifier / filename).write_bytes(data)
    report['negatives'].append(run('reject-' + name, ['verify', 'public.json', filename], verifier, accepted=False))
report['public_sha256'] = sha(verifier / 'public.json')
report['status'] = 'passed'
(out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps({'status': report['status'], 'runs': [
    {'prove_seconds': r['prove']['result']['seconds'], 'verify_seconds': r['verify']['result']['seconds'],
     'peak_rss_kib': r['prove']['peak_rss_kib'], 'proof_bytes': r['proof_bytes']} for r in report['runs']],
    'negative_rejections': len(report['negatives'])}))
