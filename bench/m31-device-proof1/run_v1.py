"""Phase 0: replay a fully local fixture through a V1 transaction prover (stock or bounded).

Loopback only: the prover's RPC is `bench/m31-append/fixture_server.py` serving an externally
pinned synthetic fixture. No chain, no public node. The request is sent as archived; the response
is compared with an archived one when given (message, proof facts, proof bytes), and the proof is
checked by the rebuilt original V1 verifier (valid + three rejections) in a separate 4 GiB unit.

The prover runs in `systemd-run --user --wait` with MemoryMax, MemorySwapMax=0, CPUQuota 400%,
CPUAffinity 0-3 (physical cores) and RuntimeMaxSec. `--variant bounded` uses the bounded-memory
build and bench/bounded-memory/run.py's full environment (TEMPLAR_LOW_MEMORY=1,
TEMPLAR_RECOMPUTE_CAIRO_COMMITMENTS=1, TEMPLAR_CAIRO_COEFFICIENTS=1, both column settings = 16).

`--cpus` pins the unit (CPUAffinity, CPUQuota and RAYON/TOKIO threads follow the CPU count).
`--expected-messages CAPTURE_JSON` fails the run unless the response's messages equal the local
capture's and proof facts[8] is their digest.

Usage: run_v1.py --variant stock|bounded --fixture F --fixture-sha256 H --request R --cap GIB
                 --name NAME [--expected-response RESP] [--expected-messages CAPTURE_JSON]
                 [--cpus '0 1 2 3'] [--phase phase0|phase2]
"""
from pathlib import Path
import argparse, base64, hashlib, json, re, socket, subprocess, sys, threading, time, urllib.request
sys.path.insert(0, str(Path(__file__).resolve().parent))
import capture  # noqa: E402
import run_v2  # noqa: E402

H = Path(__file__).resolve().parent
ROOT = H.parents[1]
W = ROOT / 'target/m31-device-proof1'
RUNS = Path.home() / '.local/share/templar/runs/m31-device-proof1'
BINARIES = {
    'stock': (W / 'bin/v1-stock-prover', W / 'src/sequencer-e6b6fd2e'),
    # The preserved bounded build (bench/bounded-memory/results/low-memory-prover-build.json).
    'bounded': (ROOT / 'target/bounded-memory/bin/low-memory-prover', ROOT / 'target/bounded-memory/sequencer'),
}
BOUNDED_PIN = '8eaa1763abd7216f43fff2a935a3646e5643f55763236b41885ee77f5286d471'
VERIFIER = W / 'bin/v1-local-verifier'


def sha(p):
    with open(p, 'rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def save(p, v):
    p.write_text(json.dumps(v, indent=2) + '\n')


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def rpc(port, method, params, timeout=10):
    req = urllib.request.Request(f'http://127.0.0.1:{port}', json.dumps(
        {'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode(), {'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        out = json.load(r)
    if 'error' in out:
        raise RuntimeError(json.dumps(out['error']))
    return out['result']


def ready(process, port, tries=240):
    for _ in range(tries):
        if process.poll() is not None:
            raise RuntimeError(f'service on {port} exited: {process.returncode}')
        try:
            rpc(port, 'starknet_specVersion', {}, 1)
            return
        except (OSError, RuntimeError):
            time.sleep(0.25)
    raise RuntimeError(f'service on {port} not ready')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--variant', choices=BINARIES, required=True)
    ap.add_argument('--fixture', type=Path, required=True)
    ap.add_argument('--fixture-sha256', required=True)
    ap.add_argument('--request', type=Path, required=True)
    ap.add_argument('--expected-response', type=Path)
    ap.add_argument('--cap', type=int, required=True)
    ap.add_argument('--name', required=True)
    ap.add_argument('--timeout', type=int, default=900)
    ap.add_argument('--column-batch-size', type=int, default=16)
    ap.add_argument('--expected-messages', type=Path)
    ap.add_argument('--cpus', default='0 1 2 3')
    ap.add_argument('--phase', default='phase0')
    a = ap.parse_args()
    threads = capture.ncpus(a.cpus)
    assert re.fullmatch('[a-zA-Z0-9_-]+', a.name)
    out = H / 'results' / a.phase / a.name
    run = RUNS / a.phase / a.name
    out.mkdir(parents=True, exist_ok=False)
    run.mkdir(parents=True, exist_ok=False)
    binary, workdir = BINARIES[a.variant]
    assert sha(a.fixture) == a.fixture_sha256, 'fixture pin mismatch'
    if a.variant == 'bounded':
        assert sha(binary) == BOUNDED_PIN, 'bounded build differs from its archived record'
    request = json.loads(a.request.read_text())
    fixture = json.loads(a.fixture.read_text())
    summary = {'name': a.name, 'variant': a.variant, 'cap_gib': a.cap, 'cpus': a.cpus, 'threads': threads, 'swap': 0,
               'binary': str(binary), 'binary_sha256': sha(binary), 'verifier_sha256': sha(VERIFIER),
               'fixture': str(a.fixture), 'fixture_sha256': a.fixture_sha256, 'request_sha256': sha(a.request),
               'scope': 'loopback synthetic fixture; no chain, no public node', 'status': 'started'}
    fport, pport = free_port(), free_port()
    while pport == fport:
        pport = free_port()
    unit = f'templar-dp1-{a.name}-{time.time_ns()}'
    env = {'RPC_URL': f'http://127.0.0.1:{fport}', 'CHAIN_ID': 'SN_SEPOLIA', 'PROVER_IP': '127.0.0.1',
           'PROVER_PORT': str(pport), 'MAX_CONCURRENT_REQUESTS': '1', 'MAX_QUEUED_REQUESTS': '0',
           'COMPILED_CLASS_CACHE_SIZE': '16', 'PREFETCH_STATE': 'false', 'RAYON_NUM_THREADS': str(threads),
           'TOKIO_WORKER_THREADS': str(threads), 'RUST_LOG': 'warn,starknet_transaction_prover=info,privacy_prove=info',
           'PATH': '/usr/bin:/home/broody/.cargo/bin:/bin'}
    if a.variant == 'bounded':
        n = str(a.column_batch_size)
        env.update(TEMPLAR_LOW_MEMORY='1', TEMPLAR_RECOMPUTE_CAIRO_COMMITMENTS='1', TEMPLAR_CAIRO_COEFFICIENTS='1',
                   TEMPLAR_BOUNDED_CAIRO_COLUMNS=n, TEMPLAR_BOUNDED_CIRCUIT_COLUMNS=n)
    cmd = ['systemd-run', '--user', '--wait', '--pipe', '--unit=' + unit, '-p', f'WorkingDirectory={workdir}',
           '-p', f'MemoryMax={a.cap}G', '-p', 'MemorySwapMax=0', '-p', f'CPUQuota={100 * threads}%', '-p', f'CPUAffinity={a.cpus}',
           '-p', f'RuntimeMaxSec={a.timeout + 60}']
    cmd += ['--setenv=' + k + '=' + v for k, v in env.items()] + ['/usr/bin/time', '-v', str(binary)]
    summary['prover_command'] = cmd
    samples, procs, logs = [], [], []
    done = threading.Event()
    sampler = None
    try:
        flog = (run / 'fixture-server.log').open('w')
        logs.append(flog)
        fp = subprocess.Popen([sys.executable, str(ROOT / 'bench/m31-append/fixture_server.py'), '--fixture', str(a.fixture),
                               '--sha256', a.fixture_sha256, '--port', str(fport), '--log', str(run / 'rpc-requests.jsonl')],
                              stdout=flog, stderr=subprocess.STDOUT)
        procs.append(fp)
        ready(fp, fport)
        assert rpc(fport, 'starknet_getBlockWithTxHashes', {'block_id': 'latest'}) == fixture['block']
        plog = (run / 'prover.log').open('w')
        logs.append(plog)
        pp = subprocess.Popen(cmd, stdout=plog, stderr=subprocess.STDOUT)
        procs.append(pp)
        t0 = time.monotonic()
        ready(pp, pport)
        summary['startup_seconds'] = time.monotonic() - t0
        cg = Path('/sys/fs/cgroup') / subprocess.check_output(
            ['systemctl', '--user', 'show', unit, '-p', 'ControlGroup', '--value'], text=True).strip().lstrip('/')
        start = time.monotonic()

        def sample():
            while not done.is_set():
                row = {'elapsed_seconds': time.monotonic() - start}
                for name in ('memory.current', 'memory.peak', 'memory.swap.current', 'memory.events'):
                    try:
                        row[name] = (cg / name).read_text().strip()
                    except OSError:
                        pass
                try:
                    for pid in (cg / 'cgroup.procs').read_text().split():
                        status = (Path('/proc') / pid / 'status').read_text()
                        if Path(f'/proc/{pid}/exe').resolve() == binary.resolve():
                            for line in status.splitlines():
                                if line.startswith(('VmRSS:', 'VmHWM:', 'VmSwap:')):
                                    row[line.split(':')[0] + '_KiB'] = int(line.split()[1])
                except OSError:
                    pass
                samples.append(row)
                done.wait(0.1)

        sampler = threading.Thread(target=sample)
        sampler.start()
        response = rpc(pport, 'starknet_proveTransaction', request, a.timeout)
        summary['request_seconds'] = time.monotonic() - start
        done.set()
        sampler.join()
        subprocess.run(['systemctl', '--user', 'stop', unit], capture_output=True)
        pp.wait(timeout=30)
        save(run / 'public-response.json', response)
        proof = base64.b64decode(response['proof'], validate=True)
        (run / 'proof.bin').write_bytes(proof)
        (run / 'proof-facts.txt').write_text(','.join(response['proof_facts']))
        summary.update(proof_bytes=len(proof), proof_sha256=hashlib.sha256(proof).hexdigest(),
                       proof_facts=response['proof_facts'], l2_to_l1_messages=response['l2_to_l1_messages'])
        if a.expected_response:
            exp = json.loads(a.expected_response.read_text())
            summary['matches_archived'] = {
                'l2_to_l1_messages': response['l2_to_l1_messages'] == exp['l2_to_l1_messages'],
                'proof_facts': response['proof_facts'] == exp['proof_facts'],
                'proof_bytes_identical': response['proof'] == exp['proof'],
            }
        if a.expected_messages:
            captured = json.loads(a.expected_messages.read_text())['l2_to_l1_messages']
            num = lambda v: int(v, 16) if isinstance(v, str) else int(v)
            norm = lambda ms: [[num(m['from_address']), num(m['to_address']), [num(x) for x in m['payload']]] for m in ms]
            summary['message_matches_capture'] = norm(response['l2_to_l1_messages']) == norm(captured) and \
                num(response['proof_facts'][8]) == run_v2.message_digest(captured)
        vcmd = ['systemd-run', '--user', '--wait', '--pipe', '--unit=' + unit + '-verify', '-p', 'MemoryMax=4G',
                '-p', 'MemorySwapMax=0', '-p', 'CPUQuota=100%', '-p', 'CPUAffinity=0', '-p', 'RuntimeMaxSec=120',
                '/usr/bin/time', '-v', str(VERIFIER), str(run)]
        with (out / 'local-verification.log').open('w') as f:
            v = subprocess.run(vcmd, stdout=f, stderr=subprocess.STDOUT)
        summary['verifier_passed_with_three_rejections'] = v.returncode == 0
        summary['status'] = 'passed' if v.returncode == 0 and summary.get('message_matches_capture', True) else 'verification-failed'
    except Exception as exc:
        summary.update(status='failed', error=str(exc)[-2000:], error_type=type(exc).__name__)
    finally:
        done.set()
        if sampler:
            sampler.join()
        props = subprocess.run(['systemctl', '--user', 'show', unit, '-p',
                                'MemoryPeak,MemorySwapPeak,MemoryMax,MemorySwapMax,CPUAffinity,CPUUsageNSec,Result'],
                               capture_output=True, text=True)
        (out / 'cgroup.txt').write_text(props.stdout)
        subprocess.run(['systemctl', '--user', 'stop', unit], capture_output=True)
        for p in reversed(procs):
            if p.poll() is None:
                p.terminate()
                try:
                    p.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    p.kill()
        for f in logs:
            f.close()
        save(run / 'resources.json', samples)
        summary.update(
            peak_rss_gib=max((s.get('VmHWM_KiB', 0) for s in samples), default=0) / 2**20,
            cgroup_peak_gib=max((int(s.get('memory.peak', 0)) for s in samples), default=0) / 2**30,
            swap_peak_bytes=max((int(s.get('memory.swap.current', 0)) for s in samples), default=0),
            oom_kill=max((int(dict(x.split() for x in s.get('memory.events', '').splitlines()).get('oom_kill', 0))
                          for s in samples), default=0),
            resource_samples=len(samples))
        if (run / 'prover.log').exists():
            clean = re.sub(r'\x1b\[[0-9;]*m', '', (run / 'prover.log').read_text())
            (out / 'prover.log').write_text(clean)
            summary['oom_kill'] = int(bool(summary['oom_kill'] or 'oom-kill' in clean))
            for phase in ('os', 'prove'):
                m = re.findall(phase + r'_duration_ms=(\d+)', clean)
                if m:
                    summary[phase + '_seconds'] = int(m[-1]) / 1000
            m = re.search(r'n_steps=(\d+) n_memory_holes=(\d+) builtins=(\{[^}]*\})', clean)
            if m:
                summary['virtual_os'] = {'n_steps': int(m[1]), 'n_memory_holes': int(m[2]), 'builtins': m[3]}
        if summary['status'] == 'failed' and summary['oom_kill']:
            summary['status'] = 'oom'
        save(out / 'summary.json', summary)
        print(json.dumps({k: summary.get(k) for k in ('name', 'status', 'threads', 'request_seconds', 'prove_seconds', 'os_seconds',
                                                       'peak_rss_gib', 'cgroup_peak_gib', 'proof_bytes', 'matches_archived',
                                                       'message_matches_capture', 'virtual_os', 'oom_kill')}), flush=True)
    if summary['status'] != 'passed':
        raise SystemExit(2 if summary['status'] == 'oom' else 1)


if __name__ == '__main__':
    main()
