"""Public Blake hash workload through unchanged PROOF1 and original verification.

This proves only hash computations, not private membership verification.

Only loopback HTTP is used. The fixture is an externally pinned synthetic anchor,
not a network block. Native verification and local-node attachment are distinct.
"""
from pathlib import Path
import argparse
import base64
import hashlib
import importlib.util
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
import urllib.request

HERE = Path(__file__).resolve().parent
BASE = Path('/tmp/templar-stwo-privacy-dtgn6e8l/sepolia-v1-test')
UPSTREAM = BASE / 'upstream/sequencer-e6b6fd2e9932909107833579e5b6efd6c75fa0af'
PROVER = BASE / 'rust-target/release/starknet_transaction_prover'
VERIFIER = BASE / 'local-verifier'
PINS = {PROVER: '31fb582d5ec8cfcb028ae7c144f0152acc432f68d5cbfeb4c10e881a00f18db5',
        VERIFIER: '492e2ea2b2bbc9eef05239407e9f3cbcc39199934b3f3bb02172aba3fd198934'}
PROGRAM = int('53f6c9fcfd31d27279ff7d7e422b44623550a732b59fe193354a7316a96daa1', 16)


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def load_reference():
    spec = importlib.util.spec_from_file_location('public_binding_reference', HERE.parent / 'push-e2e/reference.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def number(value):
    return int(value, 16) if isinstance(value, str) else int(value)


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def rpc(port, method, params, timeout=10):
    request = urllib.request.Request(f'http://127.0.0.1:{port}', json.dumps({
        'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode(),
        {'Content-Type': 'application/json'})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        result = json.load(response)
    if 'error' in result:
        raise RuntimeError(json.dumps(result['error']))
    return result['result']


def ready(process, port):
    for _ in range(120):
        if process.poll() is not None:
            raise RuntimeError(f'service on {port} exited: {process.returncode}')
        try:
            rpc(port, 'starknet_specVersion', {}, 1)
            return
        except (OSError, RuntimeError):
            time.sleep(0.25)
    raise RuntimeError(f'service on {port} not ready')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--fixture', type=Path, required=True)
    parser.add_argument('--fixture-sha256', required=True)
    parser.add_argument('--batch', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--timeout-seconds', type=int, default=600)
    parser.add_argument('--l2-gas-max-amount', type=int, default=1_000_000_000)
    parser.add_argument('--memory-cap-gib', type=int, choices=(16, 32, 64), default=16)
    args = parser.parse_args()
    assert 0 < args.l2_gas_max_amount < 2**64
    args.fixture = args.fixture.resolve()
    args.batch = args.batch.resolve()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    assert sha(args.fixture) == args.fixture_sha256, 'external fixture pin mismatch'
    for path, expected in PINS.items():
        assert sha(path) == expected, f'unchanged binary pin mismatch: {path}'
    fixture = json.loads(args.fixture.read_text())
    authority = fixture['authority']
    public = json.loads(args.batch.read_text())
    save(out / 'hash-batch.json', public)
    public_values = [number(x) for x in public['public_values']]
    assert public_values[0] == int.from_bytes(b'BLAKE_COST_V1', 'big')
    assert public_values[1] == number(fixture['chain_id'])
    calldata = public['calldata']
    assert number(calldata[0]) == len(calldata) - 1
    reference = load_reference()
    expected_words = public['expected_digest_words']
    assert reference.hash_span(expected_words) == public_values[-1]
    assert public_values[2] == len(expected_words) // 8
    request = {'block_id': {'block_number': fixture['block']['block_number']}, 'transaction': {
        'type': 'INVOKE', 'version': '0x3', 'sender_address': authority['statement'],
        'calldata': calldata, 'signature': [], 'nonce': '0x0',
        'resource_bounds': {gas: {'max_amount': hex(args.l2_gas_max_amount) if gas == 'l2_gas' else '0x0',
                                 'max_price_per_unit': '0x0'} for gas in ('l1_gas', 'l2_gas', 'l1_data_gas')},
        'tip': '0x0', 'paymaster_data': [], 'account_deployment_data': [],
        'nonce_data_availability_mode': 'L1', 'fee_data_availability_mode': 'L1'}}
    save(out / 'public-request.json', request)
    save(out / 'anchor.json', {'fixture_sha256': args.fixture_sha256, 'authority': authority,
        'base_block_hash': fixture['block']['block_hash'], 'base_number': fixture['block']['block_number'],
        'program_hash': hex(PROGRAM), 'binaries': {str(k): v for k, v in PINS.items()},
        'scope': 'synthetic authenticated local state; no network finality'})
    fixture_port, prover_port = free_port(), free_port()
    while prover_port == fixture_port:
        prover_port = free_port()
    unit = 'templar-blake-outer-' + str(os.getpid())
    samples, processes, logs = [], [], []
    done = threading.Event()
    sampler = None
    report = {'status': 'started', 'memory_cap_gib': args.memory_cap_gib, 'cores': 4,
              'l2_gas_max_amount': args.l2_gas_max_amount,
              'scope': 'public hash workload only; not membership verification',
              'local_node_attachment': False, 'native_verification_passed': False}
    try:
        fixture_log = (out / 'fixture-server.log').open('w')
        logs.append(fixture_log)
        fixture_process = subprocess.Popen([sys.executable, str(HERE.parent / 'm31-append/fixture_server.py'),
            '--fixture', str(args.fixture), '--sha256', args.fixture_sha256,
            '--port', str(fixture_port), '--log', str(out / 'rpc-requests.jsonl')], stdout=fixture_log, stderr=subprocess.STDOUT)
        processes.append(fixture_process)
        ready(fixture_process, fixture_port)
        assert rpc(fixture_port, 'starknet_getBlockWithTxHashes', {'block_id': 'latest'}) == fixture['block']
        command = ['systemd-run', '--user', '--wait', '--pipe', '--unit=' + unit,
            '-p', 'WorkingDirectory=' + str(UPSTREAM), '-p', f'MemoryMax={args.memory_cap_gib}G', '-p', 'MemorySwapMax=0',
            '-p', 'CPUQuota=400%', '-p', 'CPUAffinity=0 1 2 3',
            '-p', 'RuntimeMaxSec=' + str(args.timeout_seconds + 60)]
        env = {'RPC_URL': f'http://127.0.0.1:{fixture_port}', 'CHAIN_ID': 'SN_SEPOLIA',
               'PROVER_IP': '127.0.0.1', 'PROVER_PORT': str(prover_port),
               'MAX_CONCURRENT_REQUESTS': '1', 'MAX_QUEUED_REQUESTS': '0',
               'COMPILED_CLASS_CACHE_SIZE': '16', 'PREFETCH_STATE': 'false',
               'RAYON_NUM_THREADS': '4', 'TOKIO_WORKER_THREADS': '4',
               'RUST_LOG': 'warn,starknet_transaction_prover=info,privacy_prove=info',
               'PATH': '/usr/bin:/home/broody/.cargo/bin:/bin'}
        command += ['--setenv=' + k + '=' + v for k, v in env.items()]
        command += ['/usr/bin/time', '-v', str(PROVER)]
        save(out / 'prover-command.json', command)
        prover_log = (out / 'prover.log').open('w')
        logs.append(prover_log)
        prover = subprocess.Popen(command, stdout=prover_log, stderr=subprocess.STDOUT)
        processes.append(prover)
        ready(prover, prover_port)
        cgroup = Path('/sys/fs/cgroup') / subprocess.check_output([
            'systemctl', '--user', 'show', unit, '-p', 'ControlGroup', '--value'], text=True).strip().lstrip('/')
        start = time.monotonic()

        def sample():
            while not done.is_set():
                row = {'elapsed_seconds': time.monotonic() - start}
                for name in ('memory.current', 'memory.peak', 'memory.swap.current', 'memory.events', 'cpu.stat'):
                    try:
                        row[name] = (cgroup / name).read_text().strip()
                    except OSError:
                        pass
                try:
                    for pid in (cgroup / 'cgroup.procs').read_text().split():
                        status = (Path('/proc') / pid / 'status').read_text()
                        if 'starknet_transa' in status.splitlines()[0]:
                            for line in status.splitlines():
                                if line.startswith(('VmRSS:', 'VmHWM:', 'VmSwap:')):
                                    row[line.split(':')[0] + '_KiB'] = int(line.split()[1])
                except OSError:
                    pass
                samples.append(row)
                done.wait(0.1)

        sampler = threading.Thread(target=sample)
        sampler.start()
        response = rpc(prover_port, 'starknet_proveTransaction', request, args.timeout_seconds)
        report['request_seconds'] = time.monotonic() - start
        save(out / 'public-response.json', response)
        done.set()
        sampler.join()
        # Shut down prover before the separate verifier resource measurement.
        subprocess.run(['systemctl', '--user', 'stop', unit], check=False, capture_output=True)
        prover.wait(timeout=20)
        proof = base64.b64decode(response['proof'], validate=True)
        facts = [number(x) for x in response['proof_facts']]
        expected_prefix = [int.from_bytes(b'PROOF1', 'big'), int.from_bytes(b'VIRTUAL_SNOS', 'big'),
            PROGRAM, int.from_bytes(b'VIRTUAL_SNOS0', 'big'), fixture['block']['block_number'],
            number(fixture['block']['block_hash']), number(authority['os_config_hash']), 1]
        assert len(facts) == 9 and facts[:8] == expected_prefix, 'outer program/anchor/config mismatch'
        payload = [number(authority['statement_class']), *public_values]
        message = response['l2_to_l1_messages']
        assert len(message) == 1
        assert number(message[0]['from_address']) == number(authority['statement'])
        assert number(message[0]['to_address']) == 0
        assert [number(x) for x in message[0]['payload']] == payload
        assert reference.hash_span([number(authority['statement']), 0, len(payload), *payload]) == facts[8]
        assert facts[8] != 0 and len(proof) > 12, 'preserved verifier mutation controls must change their inputs'
        (out / 'proof.bin').write_bytes(proof)
        (out / 'proof.base64').write_text(response['proof'])
        (out / 'proof-facts.txt').write_text(','.join(hex(x) for x in facts))
        verify_command = ['systemd-run', '--user', '--wait', '--pipe', '--unit=' + unit + '-verify',
            '-p', 'MemoryMax=4G', '-p', 'MemorySwapMax=0', '-p', 'CPUQuota=100%', '-p', 'CPUAffinity=0',
            '-p', 'RuntimeMaxSec=120', '/usr/bin/time', '-v', str(VERIFIER), str(out)]
        save(out / 'verifier-command.json', verify_command)
        with (out / 'local-verification.log').open('w') as stream:
            verification = subprocess.run(verify_command, stdout=stream, stderr=subprocess.STDOUT)
        assert verification.returncode == 0, 'preserved verifier rejected proof or failed negative controls'
        report.update(status='passed', native_verification_passed=True, outer_negative_controls=3,
            public_binding_matches=True, proof_bytes=len(proof), proof_sha256=sha(out / 'proof.bin'),
            peak_rss_gib=max((p.get('VmHWM_KiB', 0) for p in samples), default=0) / 1048576,
            cgroup_peak_bytes=max((int(p.get('memory.peak', 0)) for p in samples), default=0),
            swap_peak_bytes=max((int(p.get('memory.swap.current', 0)) for p in samples), default=0))
    except Exception as exc:
        report.update(status='failed', error=str(exc), error_type=type(exc).__name__)
        raise
    finally:
        done.set()
        if sampler:
            sampler.join()
        save(out / 'resources.json', samples)
        properties = subprocess.run(['systemctl', '--user', 'show', unit,
            '-p', 'MemoryPeak,MemorySwapPeak,MemoryMax,MemorySwapMax,CPUAffinity,CPUUsageNSec,Result'], capture_output=True, text=True)
        (out / 'cgroup.txt').write_text(properties.stdout)
        subprocess.run(['systemctl', '--user', 'stop', unit], capture_output=True)
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        for stream in logs:
            stream.close()
        report.update(peak_rss_gib=max((p.get('VmHWM_KiB', 0) for p in samples), default=0) / 1048576,
            cgroup_peak_bytes=max((int(p.get('memory.peak', 0)) for p in samples), default=0),
            swap_peak_bytes=max((int(p.get('memory.swap.current', 0)) for p in samples), default=0),
            resource_samples=len(samples))
        if (out / 'prover.log').exists():
            clean = re.sub(r'\x1b\[[0-9;]*m', '', (out / 'prover.log').read_text())
            for phase in ('os', 'prove'):
                matches = re.findall(phase + r'_duration_ms=(\d+)', clean)
                if matches:
                    report[phase + '_seconds'] = int(matches[-1]) / 1000
        save(out / 'report.json', report)
        print(json.dumps(report), flush=True)


if __name__ == '__main__':
    main()
