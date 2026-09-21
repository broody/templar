"""Isolate the compact-proof experiment without changing previous measurements."""
from pathlib import Path
import hashlib
import json
import shutil

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
PREVIOUS = ROOT / 'bench/bounded-memory'
WORK = ROOT / 'target/direct-air'


def main():
    previous = json.loads((PREVIOUS / 'environment.json').read_text())
    WORK.mkdir(parents=True, exist_ok=True)
    for name in ['stwo', 'stwo-cairo', 'stwo-circuits']:
        source = Path(previous['work']) / name
        destination = WORK / name
        if not destination.exists():
            shutil.copytree(source, destination, ignore=shutil.ignore_patterns('.git', 'target'))
    (HERE / 'results').mkdir(exist_ok=True)
    environment = {
        'work': str(WORK),
        'previous_work': previous['work'],
        'rustup_home': previous['rustup_home'],
        'build_path': previous['build_path'],
        'prover': str(Path(previous['work']) / 'bin/low-memory-prover'),
        'prover_sha256': '8eaa1763abd7216f43fff2a935a3646e5643f55763236b41885ee77f5286d471',
        'verifier': previous['verifier'],
        'verifier_sha256': '492e2ea2b2bbc9eef05239407e9f3cbcc39199934b3f3bb02172aba3fd198934',
        'sequencer_original': previous['sequencer_original'],
        'previous_archive_manifest_sha256': hashlib.sha256((PREVIOUS / 'SHA256SUMS').read_bytes()).hexdigest(),
        'source_pins': json.loads((PREVIOUS / 'results/source-pins.json').read_text()),
    }
    for key in ['prover', 'verifier']:
        assert hashlib.sha256(Path(environment[key]).read_bytes()).hexdigest() == environment[key + '_sha256']
    path = HERE / 'environment.json'
    if path.exists():
        assert json.loads(path.read_text()) == environment, 'Existing environment differs; inspect before replacing'
    else:
        path.write_text(json.dumps(environment, indent=2) + '\n')
    print('Isolated direct-air sources ready; accepted prover/verifier remain unchanged.')


if __name__ == '__main__':
    main()
