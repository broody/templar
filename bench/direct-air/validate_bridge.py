"""Run existing synthetic Cairo proof fixtures; no witness generation or chain writes."""
from pathlib import Path
import hashlib
import json
import re
import subprocess
import sys

HERE = Path(__file__).resolve().parent
SCARB = Path('/home/broody/.asdf/installs/scarb/2.18.0/bin/scarb')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    saved = HERE / 'results/eq-one-thread-8g/proof'
    expected = json.loads((HERE / 'cairo/hash-fixtures.json').read_text())['verification_output_u32_le']
    cases = [('valid-1', saved / 'cairo-arguments-1.json', True)]
    cases.extend((p.stem, p, False) for p in sorted((HERE / 'results/cairo-mutations').glob('*.json')))
    assert len(cases) == 10
    report = {
        'scope': 'synthetic Cairo interoperability only; no PROOF1, payment or privacy qualification',
        'scarb_sha256': sha(SCARB),
        'executor_sha256': sha(SCARB.with_name('scarb-execute')),
        'executable_sha256': sha(HERE / 'cairo/target/dev/templar_synthetic_circuit_bridge.executable.json'),
        'expected_output': expected,
        'cases': [],
    }
    for name, fixture, accept in cases:
        run_name = 'bridge-check-' + name
        command = [
            sys.executable, str(HERE / 'measure.py'), '--name', run_name,
            '--cap-gib', '8', '--threads', '4', '--scope', report['scope'], '--',
            str(SCARB), '--manifest-path', str(HERE / 'cairo/Scarb.toml'),
            'execute', '--no-build', '-p', 'templar_synthetic_circuit_bridge',
            '--arguments-file', str(fixture), '--print-program-output', '--print-resource-usage',
        ]
        result = subprocess.run(command, capture_output=True, text=True, timeout=620)
        folder = HERE / 'results' / run_name
        (folder / 'driver.log').write_text(result.stdout + result.stderr)
        resources = json.loads((folder / 'summary.json').read_text())
        log = (folder / 'stdout.log').read_text()
        output = re.search(r'Program output:\s*([\d\s]+)Resources:', log)
        values = [int(x) for x in output[1].split()] if output else None
        rejected_in_program = 'Panicked with' in log or 'Run panicked with' in log
        passed = (result.returncode == 0 and values == expected) if accept else (
            result.returncode != 0 and rejected_in_program and not resources['sampled_oom_kill']
        )
        record = {
            'name': name, 'fixture_sha256': sha(fixture), 'expected_accept': accept,
            'exit_code': result.returncode, 'output_matches': values == expected,
            'program_rejection': rejected_in_program, 'passed': passed,
            'peak_rss_gib': resources['time_peak_rss_gib'],
            'elapsed_seconds': resources['elapsed_seconds'],
        }
        report['cases'].append(record)
        (HERE / 'results/cairo-bridge-validation.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(record), flush=True)
    assert all(c['passed'] for c in report['cases']), 'See per-case logs for failures'


if __name__ == '__main__':
    main()
