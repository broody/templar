"""Capture one virtual-OS execution of the circuit-A account over a synthetic local
fixture, and check the exact emitted statement message. No proof, no network."""
from pathlib import Path
import argparse, hashlib, importlib.util, json, subprocess, sys, time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
WRAPPER = HERE.parent
spec = importlib.util.spec_from_file_location('outer_helpers', WRAPPER / 'run_server_outer.py')
helpers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helpers)
spec = importlib.util.spec_from_file_location('bridge_builder', HERE / 'build_bridge.py')
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)
CAPTURE = ROOT / 'target/m31-private-wrapper/capacity-capture-build-v3/capture'
FIXTURE_TOOL = ROOT / 'target/m31-append/state-fixture-build-v4/state-fixture'
TEMPLATE = WRAPPER / 'results/bridge-capacity/optimized/public-request.json'
# V1: statement check in the account (log25/log23 runs). V2: upstream verifier, digest only.
# SA: arithmetic-profile client bridge, statement emitted directly. R0: payment bridge, binding.
TAG_VERSION = 'V1'


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


PREFIX = None  # statement prefix override (hex) for non-TMPZK002 statements
TAG = None


def expected_payload(fixture, public):
    chain = int.from_bytes(b'SN_SEPOLIA', 'big')
    assert int(public['chain'], 16) == chain
    if TAG_VERSION == 'R0':
        # R0 payment bridge: the pool recomputes the binding from its spend data.
        import validate_bridge_r0
        tag = int.from_bytes((TAG or 'TMPZR0_PAYMENT_V3').encode(), 'big')
        return [int(fixture['authority']['statement_class'], 16), tag, chain, int(public['pool'], 16), validate_bridge_r0.binding(public)]
    if TAG_VERSION == 'SA':
        # Arithmetic-profile client route: the statement itself, no digest.
        tag = int.from_bytes((TAG or 'TMPZSA01_MEMBERSHIP_V1').encode(), 'big')
        return [int(fixture['authority']['statement_class'], 16), tag, chain, int(public['pool'], 16), *public['root']]
    prefix = bytes.fromhex(PREFIX) if PREFIX else builder.statement_prefix()
    x = prefix + json.dumps(public, separators=(',', ':')).encode()
    if TAG_VERSION == 'V2':
        x += b''.join(r.to_bytes(4, 'little') for r in public['root'])
    d = hashlib.blake2s(x, digest_size=32).digest()
    lo, hi = int.from_bytes(d[:16], 'little'), int.from_bytes(d[16:], 'little')
    chain = int.from_bytes(b'SN_SEPOLIA', 'big')
    assert int(public['chain'], 16) == chain
    tag = int.from_bytes((TAG or 'TMPZK002_MEMBERSHIP_' + TAG_VERSION).encode(), 'big')
    tail = [] if TAG_VERSION == 'V2' else public['root']
    return [int(fixture['authority']['statement_class'], 16), tag, chain, lo, hi, *tail]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--sierra', type=Path, required=True)
    ap.add_argument('--proof-dir', type=Path, required=True)
    ap.add_argument('--public', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--l2-gas', default='0x3b9aca00')
    ap.add_argument('--tag-version', default='V1', choices=['V1', 'V2', 'SA', 'R0'])
    ap.add_argument('--prefix-hex')
    ap.add_argument('--tag')
    ap.add_argument('--expect-reject', action='store_true',
                    help='negative capture: pass only if the account run fails or emits no message')
    a = ap.parse_args()
    global TAG_VERSION, PREFIX, TAG
    TAG_VERSION, PREFIX, TAG = a.tag_version, a.prefix_hex, a.tag
    out = a.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    fixture_path = out / 'state-fixture.json'
    subprocess.run([str(FIXTURE_TOOL), 'make', str(a.sierra.resolve()), str(fixture_path)], check=True)
    subprocess.run([str(FIXTURE_TOOL), 'check', str(fixture_path), str(out / 'state-validation.json')], check=True)
    fixture = json.loads(fixture_path.read_text())
    public = json.loads(a.public.read_text())
    request = json.loads(TEMPLATE.read_text())
    request['transaction']['sender_address'] = fixture['authority']['statement']
    request['transaction']['calldata'] = json.loads((a.proof_dir / 'cairo-arguments.json').read_text())
    request['transaction']['resource_bounds']['l2_gas']['max_amount'] = a.l2_gas
    request_path = out / 'request.json'
    request_path.write_text(json.dumps(request))
    port = helpers.free_port()
    command = ['systemd-run', '--user', '--wait', '--pipe', '--unit=templar-client-capture-' + str(time.time_ns()),
               '-p', 'WorkingDirectory=' + str(helpers.UPSTREAM), '-p', 'MemoryMax=16G', '-p', 'MemorySwapMax=0',
               '-p', 'CPUQuota=400%', '-p', 'CPUAffinity=0 1 2 3', '-p', 'RuntimeMaxSec=600',
               '--setenv=RAYON_NUM_THREADS=4', '--setenv=TOKIO_WORKER_THREADS=4',
               '/usr/bin/time', '-v', str(CAPTURE), f'http://127.0.0.1:{port}', str(request_path), str(out)]
    with (out / 'fixture.log').open('w') as log:
        p = subprocess.Popen([sys.executable, str(ROOT / 'bench/m31-append/fixture_server.py'), '--fixture', str(fixture_path),
                              '--sha256', sha(fixture_path), '--port', str(port), '--log', str(out / 'rpc.jsonl')],
                             stdout=log, stderr=subprocess.STDOUT)
        try:
            helpers.ready(p, port)
            start = time.monotonic()
            with (out / 'capture.log').open('w') as stream:
                r = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT)
            result = {'command': command, 'fixture_sha256': sha(fixture_path), 'request_sha256': sha(request_path),
                      'capture_binary_sha256': sha(CAPTURE), 'exit_code': r.returncode,
                      'elapsed_seconds': time.monotonic() - start}
            (out / 'execution.json').write_text(json.dumps(result, indent=2) + '\n')
            if a.expect_reject:
                log = (out / 'capture.log').read_text()
                produced = json.loads((out / 'capture.json').read_text()) if (out / 'capture.json').exists() else {}
                messages = produced.get('l2_to_l1_messages', [])
                reasons = [l.strip() for l in log.splitlines() if 'panic' in l.lower() or 'revert' in l.lower() or 'error' in l.lower()]
                result.update(expect_reject=True, rejected=r.returncode != 0 or not messages,
                              n_messages=len(messages), reason=reasons[:5])
                (out / 'execution.json').write_text(json.dumps(result, indent=2) + '\n')
                print(json.dumps({k: result[k] for k in ('rejected', 'exit_code', 'n_messages', 'reason')}))
                assert result['rejected'], 'negative capture was accepted'
                return
            assert r.returncode == 0, (out / 'capture.log').read_text()[-3000:]
            produced = json.loads((out / 'capture.json').read_text())
            messages = produced['l2_to_l1_messages']
            assert len(messages) == 1
            num = lambda v: int(v, 16) if isinstance(v, str) else int(v)
            got = [num(x) for x in messages[0]['payload']]
            want = expected_payload(fixture, public)
            assert got == want, (got, want)
            assert num(messages[0]['from_address']) == num(fixture['authority']['statement'])
            result.update(exact_message_verified=True, pie_sha256=sha(out / 'os.pie.zip'), payload=[hex(v) for v in got])
            (out / 'execution.json').write_text(json.dumps(result, indent=2) + '\n')
            print(json.dumps(result, indent=2))
        finally:
            p.terminate()
            p.wait(timeout=10)


if __name__ == '__main__':
    main()
