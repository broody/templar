"""Compare synthetic split outputs and invoke the preserved PROOF1 verifier.

This is a file-format adapter around the unchanged existing verifier, not a
replacement verifier or a privacy test. All inputs must be public fixtures.
"""
from pathlib import Path
import argparse
import hashlib
import json
import subprocess
import time

VERIFIER = Path('/tmp/templar-stwo-privacy-dtgn6e8l/sepolia-v1-test/local-verifier')
VERIFIER_SHA256 = '492e2ea2b2bbc9eef05239407e9f3cbcc39199934b3f3bb02172aba3fd198934'
HERE = Path(__file__).resolve().parent


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference', type=Path, required=True)
    parser.add_argument('outputs', type=Path, nargs='+')
    args = parser.parse_args()
    assert sha(VERIFIER) == VERIFIER_SHA256, 'Preserved verifier identity changed'
    adapter_meta = json.loads((HERE / 'results/verifier-adapter-build/metadata.json').read_text())
    adapter = Path(adapter_meta['binary'])
    assert sha(adapter) == adapter_meta['binary_sha256']
    reference = (args.reference / 'proof.bin').read_bytes()
    public_output = json.loads((args.reference / 'output-preimage.json').read_text())
    values = [int(x, 0) if isinstance(x, str) else int(x) for x in public_output]
    assert values[0] == 1 and values[1] == len(values) - 1
    # Matches ProgramOutput::try_into_proof_facts. Variant is not used by the
    # recursive verifier; this synthetic fixture is not a transaction submission.
    facts = [int.from_bytes(b'PROOF1', 'big'), 0, *values[2:]]
    for folder in args.outputs:
        assert (folder / 'proof.bin').read_bytes() == reference, folder
        assert json.loads((folder / 'output-preimage.json').read_text()) == public_output, folder
        (folder / 'proof-facts.txt').write_text(','.join(hex(x) for x in facts) + '\n')
        if folder.resolve() == args.reference.resolve():
            original = subprocess.run([str(VERIFIER), str(folder.resolve())],
                                      capture_output=True, text=True, timeout=120)
            (folder / 'original-binary.log').write_text(original.stdout + original.stderr)
            # This fixture ends in zero. The original executable accepts the
            # valid artifact, then its doubling-zero control is a no-op and its
            # test adapter asserts. Never label that whole mutation suite PASS.
            assert values[-1] == 0
            assert 'valid proof: PASS' in original.stdout
            assert original.returncode != 0
            assert 'mutation accepted: changed message digest' in original.stderr
            (folder / 'original-binary.json').write_text(json.dumps({
                'valid_proof_accepted': True, 'exit_code': original.returncode,
                'mutation_suite_passed': False,
                'limitation': 'Legacy adapter doubles zero final fact; the mutation is unchanged',
                'binary_sha256': VERIFIER_SHA256,
            }, indent=2) + '\n')
        start = time.perf_counter()
        run = subprocess.run([str(adapter), str(folder.resolve())],
                             capture_output=True, text=True, timeout=120)
        elapsed = time.perf_counter() - start
        (folder / 'preserved-verifier.log').write_text(run.stdout + run.stderr)
        result = {
            'reference': str(args.reference.resolve()),
            'byte_parity': True, 'public_output_parity': True,
            'proof_bytes': len(reference), 'proof_sha256': sha(folder / 'proof.bin'),
            'preserved_original_verifier_sha256': VERIFIER_SHA256,
            'mutation_adapter_sha256': adapter_meta['binary_sha256'],
            'verifier_library_modified': False, 'mutation': 'add one to each changed public field',
            'exit_code': run.returncode,
            'external_verification_and_controls_seconds': elapsed,
            'external_verification_excluded_from_wrapper_measurement': True,
            'privacy_qualified_by_measurement': False,
        }
        (folder / 'preserved-verifier.json').write_text(json.dumps(result, indent=2) + '\n')
        assert run.returncode == 0, run.stdout + run.stderr
        assert 'valid proof: PASS' in run.stdout
        assert run.stdout.count(': rejected (') == 3, run.stdout
        print(json.dumps({'folder': str(folder), **result}), flush=True)


if __name__ == '__main__':
    main()
