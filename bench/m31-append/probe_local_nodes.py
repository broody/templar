"""Inspect fresh loopback-only nodes; never use a wallet or external RPC."""
from pathlib import Path
import json
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request

HERE = Path(__file__).resolve().parent


def rpc(url, method, params):
    request = {'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}
    data = json.dumps(request).encode()
    req = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=4) as response:
            reply = json.load(response)
    except urllib.error.HTTPError as exc:
        reply = {'http_error': exc.code, 'body': exc.read().decode()[:1000]}
    return {'request': request, 'response': reply}


def probe(name, binary, options):
    folder = HERE / 'results/local-capability' / name
    folder.mkdir(parents=True, exist_ok=True)
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    command = [binary] + [str(port) if word == '{port}' else word for word in options]
    unit = f'templar-m31-capability-{name}-{time.time_ns()}'
    launch = ['systemd-run', '--user', '--wait', '--pipe', f'--unit={unit}',
              '-p', 'MemoryMax=4G', '-p', 'MemorySwapMax=0', '-p', 'RuntimeMaxSec=180'] + command
    report = {'scope': 'fresh synthetic local node capability, not a proving benchmark',
              'command': launch, 'url': f'http://127.0.0.1:{port}', 'calls': []}
    with (folder / 'startup.log').open('w') as log:
        process = subprocess.Popen(launch, stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 45
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RuntimeError(f'node exited at startup: {process.returncode}')
                try:
                    call = rpc(report['url'], 'starknet_specVersion', [])
                    break
                except (OSError, ValueError):
                    time.sleep(.25)
            else:
                raise RuntimeError('node startup timed out')
            report['calls'].append(call)
            if name == 'katana-mined':
                time.sleep(2.5)
            for method, params in [
                ('starknet_chainId', []), ('starknet_blockNumber', []),
                ('starknet_getBlockWithTxHashes', {'block_id': 'latest'}),
                ('starknet_getStorageProof', {'block_id': 'latest', 'class_hashes': [],
                                            'contract_addresses': [], 'contracts_storage_keys': []}),
            ]:
                report['calls'].append(rpc(report['url'], method, params))
        except Exception as exc:
            report['error'] = str(exc)
        finally:
            subprocess.run(['systemctl', '--user', 'stop', unit], capture_output=True, check=False)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.terminate()
                process.wait(timeout=5)
    (folder / 'probe.json').write_text(json.dumps(report, indent=2) + '\n')
    print(name, json.dumps({
        'error': report.get('error'),
        'responses': {c['request']['method']: c['response'] for c in report['calls']}
    })[:4500])


if __name__ == '__main__':
    import sys
    if '--mined-katana' in sys.argv:
        probe('katana-mined', shutil.which('katana'),
              ['--dev', '--silent', '--dev.seed', '42', '--dev.accounts', '1',
               '--block-time', '1000', '--http.addr', '127.0.0.1', '--http.port', '{port}'])
    else:
        probe('devnet', '/home/broody/.asdf/installs/starknet-devnet/0.6.0/bin/starknet-devnet',
              ['--host', '127.0.0.1', '--port', '{port}', '--seed', '42', '--accounts', '1',
               '--state-archive-capacity', 'full'])
        probe('katana', shutil.which('katana'),
              ['--dev', '--silent', '--dev.seed', '42', '--dev.accounts', '1',
               '--http.addr', '127.0.0.1', '--http.port', '{port}'])
