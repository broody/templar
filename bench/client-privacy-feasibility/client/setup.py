"""Copy frozen bounded-memory sources and apply the isolated stage-checkpoint patch."""
from pathlib import Path
import hashlib
import json
import shutil
import subprocess

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
SOURCE = REPO / 'target/bounded-memory'
DEST = REPO / 'target/client-privacy-feasibility'
NAMES = ['stwo', 'stwo-cairo', 'stwo-circuits', 'sequencer', 'proving-utils']

if __name__ == '__main__':
    for name in NAMES:
        if (DEST / name).exists():
            raise SystemExit(f'Refusing to overwrite existing source copy: {DEST / name}')
    manifest = {}
    for name in NAMES:
        shutil.copytree(SOURCE / name, DEST / name,
                        ignore=shutil.ignore_patterns('.git', 'target', '__pycache__'))
        files = {str(p.relative_to(DEST / name)): hashlib.sha256(p.read_bytes()).hexdigest()
                 for p in sorted((DEST / name).rglob('*')) if p.is_file()}
        manifest[name] = {'origin': str(SOURCE / name), 'files': files}
    (DEST / 'copied-source-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    subprocess.run(['patch', '-p1', '--batch', '-i',
                    str(HERE / 'patches/proving-utils-checkpoint.patch')],
                   cwd=DEST / 'proving-utils', check=True)
