"""P0b spike (throwaway): capture one virtual-OS execution of an R4 statement account over the
synthetic local state fixture and check the exact emitted message. Adapted from
bench/m31-private-wrapper/client-port/capture_os.py (R4 only) with `--auth`: extra calldata
felts after the proof span (the spike account's [owner_pubkey, salt, valid_until, r, s]).
No proof, no network beyond the loopback fixture server, nothing on chain.
"""
from pathlib import Path
import argparse, hashlib, importlib.util, json, subprocess, sys, time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
WRAPPER = ROOT / 'bench/m31-private-wrapper'
CLIENT = WRAPPER / 'client-port'
sys.path.insert(0, str(CLIENT))
import validate_bridge_r4  # noqa: E402  (independent Python binding: bench/adr8/ref_poseidon.py)

spec = importlib.util.spec_from_file_location('outer_helpers', WRAPPER / 'run_server_outer.py')
helpers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helpers)
CAPTURE = ROOT / 'target/m31-private-wrapper/capacity-capture-build-v3/capture'
FIXTURE_TOOL = ROOT / 'target/m31-append/state-fixture-build-v4/state-fixture'
TEMPLATE = WRAPPER / 'results/bridge-capacity/optimized/public-request.json'
CHAIN = int.from_bytes(b'SN_SEPOLIA', 'big')


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def expected_payload(fixture, public):
    assert int(public['chain'], 16) == CHAIN
    tag = int.from_bytes(b'TMPZR0_PAYMENT_V4', 'big')
    return [int(fixture['authority']['statement_class'], 16), tag, CHAIN, int(public['pool'], 16), validate_bridge_r4.binding(public)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--sierra', type=Path, required=True)
    ap.add_argument('--proof-dir', type=Path, required=True)
    ap.add_argument('--public', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--auth', type=Path, help='JSON list of hex felts appended to the calldata after the proof span')
    ap.add_argument('--l2-gas', default='0x3b9aca00')
    ap.add_argument('--expect-reject', action='store_true',
                    help='negative capture: pass only if the account run fails or emits no message')
    a = ap.parse_args()
    out = a.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    fixture_path = out / 'state-fixture.json'
    subprocess.run([str(FIXTURE_TOOL), 'make', str(a.sierra.resolve()), str(fixture_path)], check=True)
    subprocess.run([str(FIXTURE_TOOL), 'check', str(fixture_path), str(out / 'state-validation.json')], check=True)
    fixture = json.loads(fixture_path.read_text())
    public = json.loads(a.public.read_text())
    request = json.loads(TEMPLATE.read_text())
    request['transaction']['sender_address'] = fixture['authority']['statement']
    calldata = json.loads((a.proof_dir / 'cairo-arguments.json').read_text())
    auth = json.loads(a.auth.read_text()) if a.auth else []
    request['transaction']['calldata'] = calldata + auth
    request['transaction']['resource_bounds']['l2_gas']['max_amount'] = a.l2_gas
    request_path = out / 'request.json'
    request_path.write_text(json.dumps(request))
    port = helpers.free_port()
    command = ['systemd-run', '--user', '--wait', '--pipe', '--unit=templar-wallet-sig-capture-' + str(time.time_ns()),
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
            result = {'command': command, 'sierra': str(a.sierra.resolve()), 'sierra_sha256': sha(a.sierra),
                      'proof_calldata_sha256': sha(a.proof_dir / 'cairo-arguments.json'),
                      'auth': auth, 'calldata_felts': len(calldata) + len(auth),
                      'fixture_sha256': sha(fixture_path), 'request_sha256': sha(request_path),
                      'capture_binary_sha256': sha(CAPTURE), 'exit_code': r.returncode,
                      'elapsed_seconds_single_run_not_a_benchmark': time.monotonic() - start}
            (out / 'execution.json').write_text(json.dumps(result, indent=2) + '\n')
            if a.expect_reject:
                log = (out / 'capture.log').read_text()
                produced = json.loads((out / 'capture.json').read_text()) if (out / 'capture.json').exists() else {}
                messages = produced.get('l2_to_l1_messages', [])
                reasons = [l.strip()[:400] for l in log.splitlines()
                           if 'panic' in l.lower() or 'revert' in l.lower() or 'error' in l.lower() or 'owner signature' in l]
                result.update(expect_reject=True, rejected=r.returncode != 0 or not messages,
                              n_messages=len(messages), reason=reasons[:8], pie_exists=(out / 'os.pie.zip').exists())
                (out / 'execution.json').write_text(json.dumps(result, indent=2) + '\n')
                print(json.dumps({k: result[k] for k in ('rejected', 'exit_code', 'n_messages', 'reason', 'pie_exists')}))
                assert result['rejected'], 'negative capture was accepted'
                return
            assert r.returncode == 0, (out / 'capture.log').read_text()[-3000:]
            produced = json.loads((out / 'capture.json').read_text())
            messages = produced['l2_to_l1_messages']
            assert len(messages) == 1, messages
            num = lambda v: int(v, 16) if isinstance(v, str) else int(v)
            got = [num(x) for x in messages[0]['payload']]
            want = expected_payload(fixture, public)
            assert got == want, (got, want)
            assert num(messages[0]['from_address']) == num(fixture['authority']['statement'])
            result.update(exact_message_verified=True, n_messages=len(messages), pie_sha256=sha(out / 'os.pie.zip'),
                          payload=[hex(v) for v in got], resources=produced['resources'])
            (out / 'execution.json').write_text(json.dumps(result, indent=2) + '\n')
            print(json.dumps({k: result[k] for k in ('exit_code', 'n_messages', 'exact_message_verified', 'pie_sha256', 'payload')}))
        finally:
            p.terminate()
            p.wait(timeout=10)


if __name__ == '__main__':
    main()
