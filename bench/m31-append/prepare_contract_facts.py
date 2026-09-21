"""Stage local contract fixtures only from five independently accepted PROOF1s."""
from pathlib import Path
import argparse
import base64
import json
import subprocess
import time

from run_outer import HERE, PROGRAM, VERIFIER, PINS, number, save, sha, load_reference


def tag(value):
    return int.from_bytes(value.encode(), 'big')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--outer-root', type=Path, required=True)
    parser.add_argument('--state-fixture', type=Path, required=True)
    parser.add_argument('--fixture-sha256', required=True)
    parser.add_argument('--output', type=Path, default=HERE / 'cairo/fixtures/verified-facts.txt')
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    assert not args.output.exists(), 'fresh contract fixture required'
    assert sha(args.state_fixture) == args.fixture_sha256
    assert sha(VERIFIER) == PINS[VERIFIER]
    fixture = json.loads(args.state_fixture.read_text())
    authority = fixture['authority']
    args.evidence.mkdir(parents=True, exist_ok=False)
    chain = number(fixture['chain_id'])
    pool, account, account_class = [number(authority[k]) for k in ('pool', 'statement', 'statement_class')]
    block = fixture['block']['block_number']
    words = [tag('M31_VERIFIED_FACTS_V1'), chain, pool, account, account_class,
             block + 1, 20, 3, 1, 2, 3, 5]
    records = []
    reference = load_reference()
    for name, old_count, commitments in [('single', 0, [1]), ('batch', 0, [1, 2]),
                                        ('branch12', 1, [2]), ('branch13', 1, [3]),
                                        ('refresh123', 2, [3])]:
        source = (args.outer_root / name).resolve()
        report = json.loads((source / 'report.json').read_text())
        anchor = json.loads((source / 'anchor.json').read_text())
        response = json.loads((source / 'public-response.json').read_text())
        facts = [number(x) for x in (source / 'proof-facts.txt').read_text().strip().split(',')]
        proof = (source / 'proof.bin').read_bytes()
        assert report['status'] == 'passed' and report['native_verification_passed']
        assert report['public_binding_matches'] and report['outer_negative_controls'] == 3
        assert report['proof_sha256'] == sha(source / 'proof.bin')
        assert base64.b64decode(response['proof'], validate=True) == proof
        assert facts == [number(x) for x in response['proof_facts']]
        assert anchor['fixture_sha256'] == args.fixture_sha256 and anchor['authority'] == authority
        assert len(facts) == 9 and facts[:8] == [tag('PROOF1'), tag('VIRTUAL_SNOS'), PROGRAM,
            tag('VIRTUAL_SNOS0'), block, number(fixture['block']['block_hash']),
            number(authority['os_config_hash']), 1]
        assert facts[8] != 0
        binding = json.loads((source / 'append-public-output.json').read_text())
        preimage = [number(x) for x in binding['transition_preimage']]
        expected_prefix = [tag('M31_APPEND_V1'), chain, pool, *[number(x) for x in binding['old_root_packed']],
                           old_count, len(commitments), *commitments]
        assert preimage[:-3] == expected_prefix
        new_root = [number(x) for x in binding['new_root_packed']]
        assert preimage[-3:] == [*new_root, old_count + len(commitments)]
        public8 = [number(x) for x in binding['public8']]
        assert reference.hash_span(preimage) == number(binding['transition_digest']) == public8[6]
        assert public8 == [tag('M31_APPEND_V1'), chain, pool, *expected_prefix[3:6],
                          number(binding['transition_digest']), len(commitments)]
        message = response['l2_to_l1_messages']
        assert len(message) == 1 and number(message[0]['from_address']) == account and number(message[0]['to_address']) == 0
        assert [number(x) for x in response['l2_to_l1_messages'][0]['payload']] == [account_class, *public8]
        assert reference.hash_span([account, 0, 9, account_class, *public8]) == facts[8]
        # Repeat original verification at the artifact-to-contract boundary; it
        # checks the actual staged proof/facts, not just a producer status flag.
        unit = 'templar-m31-stage-' + name + '-' + str(time.time_ns())
        command = ['systemd-run', '--user', '--wait', '--pipe', '--unit=' + unit,
            '-p', 'MemoryMax=4G', '-p', 'MemorySwapMax=0', '-p', 'CPUQuota=100%',
            '-p', 'CPUAffinity=0', '-p', 'RuntimeMaxSec=120', str(VERIFIER), str(source)]
        with (args.evidence / (name + '-verification.log')).open('w') as log:
            result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT)
        assert result.returncode == 0, f'original verifier failed for {name}'
        words += [tag(name), len(facts), *facts, *[number(x) for x in binding['old_root_packed']],
                  old_count, *new_root, old_count + len(commitments), len(commitments), *commitments]
        records.append({'name': name, 'source': str(source), 'proof_sha256': sha(source / 'proof.bin'),
                        'facts_sha256': sha(source / 'proof-facts.txt'), 'verification_command': command})
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text('\n'.join(hex(x) for x in words) + '\n')
    save(args.evidence / 'manifest.json', {'scope': 'native-verified-facts contract integration; no full-node attachment claim',
        'fixture_sha256': args.fixture_sha256, 'contract_fixture_sha256': sha(args.output),
        'verifier_sha256': PINS[VERIFIER], 'cases': records})
    print(json.dumps({'staged': str(args.output), 'verified_cases': len(records)}))


if __name__ == '__main__':
    main()
