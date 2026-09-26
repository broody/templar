"""Local virtual-OS capture and shape analysis of one transaction. No proof, no chain.

`capture`: serve a pinned synthetic fixture on loopback (`bench/m31-append/fixture_server.py`),
run the preserved V1 capture binary (`bench/m31-private-wrapper/bridge-capacity/capture.rs`,
sequencer e6b6fd2e virtual OS 0x53f6…daa1, binary pinned below) under a capped systemd unit, and
write `os.pie.zip` and `capture.json` (virtual-OS resources and L2-to-L1 messages).

`analyze`: on that PIE, run
- `capacity trace` (V1 prover stack, proving-utils 3035dd0): V1 component claim;
- `prove-small trace` (V2 small path, proving@2b495a3 + bounded patches): V2 component claim,
  opcode rows, builtins, bootloader steps, the fixed small-path component list;
- `blake_sites`: Blake compressions and steps by code segment, visited account PCs.

Usage: capture.py capture FIXTURE FIXTURE_SHA256 REQUEST OUT | analyze PIE OUT
"""
from pathlib import Path
import hashlib, json, socket, subprocess, sys, threading, time, urllib.request

H = Path(__file__).resolve().parent
ROOT = H.parents[1]
W = ROOT / 'target/m31-device-proof1'
CAPTURE = ROOT / 'target/m31-private-wrapper/capacity-capture-build-v3/capture'
CAPACITY = ROOT / 'target/m31-private-wrapper/capacity-build-original-v3/capacity'
BLAKE_SITES = ROOT / 'target/m31-private-wrapper/attribution-build/blake_sites'
PROVE_SMALL = W / 'bin/prove-small'
PINS = {
    # bench/m31-private-wrapper/results/bridge-capacity/os-capture/execution.json and others.
    CAPTURE: '9920dedb496508ae1245ab8261dca7c76641dd11ff9a79d3709010e39e8b722b',
    # bench/m31-private-wrapper/results/server-circuit/capacity-boot-optimized/summary.json.
    CAPACITY: '27cf06db20a3b7b887ae47bb9640992acaf7fef8e2da4e1a2aab187b41713726',
    # No archived binary record; source bench/m31-private-wrapper/proof2-large/blake-attribution/
    # blake_sites.rs matches the build's recorded source hash (attribution-build/inputs.json).
    BLAKE_SITES: '8d980f158eb3ca46e2ece60394e0421a02369291273c6d0f21a3464c43dfc40d',
}
# The capture binary's compiled-in sequencer path; it only needs to exist (see memory of the
# 2026-09-24 reboot), so it is recreated empty if missing.
UPSTREAM = Path('/tmp/templar-stwo-privacy-dtgn6e8l/sepolia-v1-test/upstream/sequencer-e6b6fd2e9932909107833579e5b6efd6c75fa0af')


def sha(p):
    with open(p, 'rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def ready(process, port):
    for _ in range(120):
        if process.poll() is not None:
            raise RuntimeError('fixture server exited')
        try:
            req = urllib.request.Request(f'http://127.0.0.1:{port}', json.dumps(
                {'jsonrpc': '2.0', 'id': 1, 'method': 'starknet_specVersion', 'params': {}}).encode(),
                {'Content-Type': 'application/json'})
            urllib.request.urlopen(req, timeout=1).read()
            return
        except OSError:
            time.sleep(0.25)
    raise RuntimeError('fixture server not ready')


def ncpus(cpus):
    """Number of CPUs in a systemd CPUAffinity list such as '0 1 2 3' or '0-15'."""
    n = 0
    for part in cpus.replace(',', ' ').split():
        a, _, b = part.partition('-')
        n += int(b or a) - int(a) + 1
    return n


def unit(name, cap_gib, cmd, log, cpus='0 1 2 3', runtime=900, workdir=None, sample=False):
    """Run `cmd` in a capped transient unit (zero swap, pinned CPUs, RAYON/TOKIO threads = CPUs).
    With `sample`, record the cgroup's memory and the processes' VmRSS every 50 ms with wall time."""
    threads = ncpus(cpus)
    u = f'templar-dp1-{name}-{time.time_ns()}'
    full = ['systemd-run', '--user', '--wait', '--pipe', '--unit=' + u, '-p', f'MemoryMax={cap_gib}G',
            '-p', 'MemorySwapMax=0', '-p', f'CPUAffinity={cpus}', '-p', f'CPUQuota={100 * threads}%',
            '-p', f'RuntimeMaxSec={runtime}', f'--setenv=RAYON_NUM_THREADS={threads}',
            f'--setenv=TOKIO_WORKER_THREADS={threads}']
    if workdir:
        full += ['-p', f'WorkingDirectory={workdir}']
    full += ['/usr/bin/time', '-v'] + [str(c) for c in cmd]
    samples, done = [], threading.Event()
    start = time.monotonic()
    with open(log, 'w') as f:
        proc = subprocess.Popen(full, stdout=f, stderr=subprocess.STDOUT)
        sampler = None
        if sample:
            def run_sampler():
                cg = None
                while not done.is_set() and cg is None:
                    path = subprocess.run(['systemctl', '--user', 'show', u, '-p', 'ControlGroup', '--value'],
                                          capture_output=True, text=True).stdout.strip()
                    cg = Path('/sys/fs/cgroup') / path.lstrip('/') if path else None
                    if cg is None:
                        time.sleep(0.02)
                while not done.is_set():
                    row = {'t': time.time()}
                    try:
                        row['cgroup_current'] = int((cg / 'memory.current').read_text())
                        row['cgroup_peak'] = int((cg / 'memory.peak').read_text())
                        rss = 0
                        for pid in (cg / 'cgroup.procs').read_text().split():
                            for line in (Path('/proc') / pid / 'status').read_text().splitlines():
                                if line.startswith('VmRSS:'):
                                    rss = max(rss, int(line.split()[1]))
                        row['rss_kib'] = rss
                    except (OSError, ValueError):
                        pass
                    samples.append(row)
                    done.wait(0.05)
            sampler = threading.Thread(target=run_sampler)
            sampler.start()
        code = proc.wait()
        done.set()
        if sampler:
            sampler.join()
    wall = time.monotonic() - start
    text = Path(log).read_text()
    rss = [l for l in text.splitlines() if 'Maximum resident set size' in l]
    result = {'exit_code': code, 'wall_seconds': wall, 'command': full, 'cpus': cpus, 'threads': threads,
              'max_rss_gib': int(rss[-1].split()[-1]) / 2**20 if rss else None,
              'oom_kill': 'oom-kill' in text or 'Result: oom-kill' in text or 'signal 9' in text}
    if sample:
        Path(str(log) + '.samples.json').write_text(json.dumps(samples))
        result['samples'] = len(samples)
        result['cgroup_peak_gib'] = max((r.get('cgroup_peak', 0) for r in samples), default=0) / 2**30
    return result


def capture(fixture, fixture_sha, request, out):
    fixture, request, out = Path(fixture).resolve(), Path(request).resolve(), Path(out).resolve()
    out.mkdir(parents=True, exist_ok=False)
    assert sha(CAPTURE) == PINS[CAPTURE], 'capture binary pin mismatch'
    assert sha(fixture) == fixture_sha, 'fixture pin mismatch'
    UPSTREAM.mkdir(parents=True, exist_ok=True)
    port = free_port()
    with (out / 'fixture.log').open('w') as log:
        p = subprocess.Popen([sys.executable, str(ROOT / 'bench/m31-append/fixture_server.py'), '--fixture', str(fixture),
                              '--sha256', fixture_sha, '--port', str(port), '--log', str(out / 'rpc.jsonl')],
                             stdout=log, stderr=subprocess.STDOUT)
        try:
            ready(p, port)
            r = unit('capture', 16, [CAPTURE, f'http://127.0.0.1:{port}', request, out], out / 'capture.log',
                     runtime=600, workdir=UPSTREAM)
        finally:
            p.terminate()
            p.wait(timeout=10)
    r.update(fixture_sha256=fixture_sha, request_sha256=sha(request), capture_binary_sha256=PINS[CAPTURE])
    if r['exit_code'] == 0:
        r['pie_sha256'] = sha(out / 'os.pie.zip')
    (out / 'execution.json').write_text(json.dumps(r, indent=2) + '\n')
    assert r['exit_code'] == 0, (out / 'capture.log').read_text()[-3000:]
    return json.loads((out / 'capture.json').read_text())


def analyze(pie, out, v1=True, v2=True, blake=True):
    pie, out = Path(pie).resolve(), Path(out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    runs = {}
    if v1:
        assert sha(CAPACITY) == PINS[CAPACITY]
        runs['capacity_trace_v1'] = unit('trace-v1', 64, [CAPACITY, 'trace', pie, out / 'trace-v1'], out / 'trace-v1.log',
                                         cpus='0 1 2 3', runtime=1800)
    if v2:
        runs['prove_small_trace_v2'] = unit('trace-v2', 64, [PROVE_SMALL, 'trace', pie, out / 'trace-v2'],
                                            out / 'trace-v2.log', cpus='0 1 2 3', runtime=1800)
    if blake:
        assert sha(BLAKE_SITES) == PINS[BLAKE_SITES]
        runs['blake_sites'] = unit('blake', 32, [BLAKE_SITES, pie, out / 'blake'], out / 'blake.log',
                                   cpus='0 1 2 3', runtime=1800)
    for name, r in runs.items():
        assert r['exit_code'] == 0, f'{name} failed: see {out}'
    previous = json.loads((out / 'tools.json').read_text()) if (out / 'tools.json').exists() else {}
    (out / 'tools.json').write_text(json.dumps(previous | runs, indent=2) + '\n')
    return runs


if __name__ == '__main__':
    if sys.argv[1] == 'capture' and len(sys.argv) == 6:
        print(json.dumps(capture(Path(sys.argv[2]), sys.argv[3], Path(sys.argv[4]), Path(sys.argv[5]))['resources']))
    elif sys.argv[1] == 'analyze' and len(sys.argv) == 4:
        print(json.dumps(analyze(Path(sys.argv[2]), Path(sys.argv[3])), indent=1))
    else:
        raise SystemExit(__doc__)
