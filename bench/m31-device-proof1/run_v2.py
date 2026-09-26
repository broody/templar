"""The V2 small path on a virtual-OS PIE with `prove-small` (phases 0 and 2).

Runs `prove-small recursive|cairo-only PIE RUN_DIR` (or `recursion CAIRO_RUN_DIR RUN_DIR`, the
recursion stage alone from an earlier cairo-only run) in a capped unit (MemoryMax, zero swap,
CPUAffinity = --cpus on physical cores, RAYON threads = CPU count, RuntimeMaxSec) while sampling
the unit every 50 ms, then `prove-small verify RUN_DIR` in a separate 8 GiB unit on one core
(valid + changed output + flipped byte + truncation).
- Peak RSS is /usr/bin/time's maximum resident set (VmHWM); the cgroup peak is kept too.
- Stage windows come from the prover's own log lines, and each stage's peak from the samples:
  `cairo` (Cairo proof), `recursion` (circuit context and circuit proof).
- `--expected-messages CAPTURE_JSON` fails the run unless the proof's output preimage carries the
  capture's single message digest: Poseidon(from, to, len, payload...), as in PROOF1 facts[8].
- `--expect-failure` marks the U2 negative control: the run passes only if proving fails.
- A cairo-only run passes on the native Rust verification plus its rejected one-byte PoW mutation;
  the fixed small-path verifier (`verify_cairo`) result is recorded beside it (U2 for QM31).

Usage: run_v2.py --mode recursive|cairo-only|recursion --pie PIE|CAIRO_RUN_DIR --cap GIB --name NAME [--cpus '0 1 2 3']
                 [--expected-messages CAPTURE_JSON] [--expect-failure] [--results-dir D]
"""
from pathlib import Path
from datetime import datetime
import argparse, hashlib, importlib.util, json, re, sys

H = Path(__file__).resolve().parent
ROOT = H.parents[1]
sys.path.insert(0, str(H))
import capture  # noqa: E402

RUNS = Path.home() / '.local/share/templar/runs/m31-device-proof1'
STAGES = {  # (start event, end event) in privacy_prove's own log
    'bootloader': ('Run privacy bootloader and get the prover input', 'Generate the cairo proof'),
    'cairo': ('Generate the cairo proof', 'Prepare the cairo proof for the cairo-circuit verifier'),
    'recursion': ('Prepare the cairo proof for the cairo-circuit verifier', 'Serialize and compress the proof'),
    'cairo_only': ('Generate the cairo proof', 'Serialize and compress the proof and public data'),
}


def sha(p):
    with open(p, 'rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def reference():
    spec = importlib.util.spec_from_file_location('public_binding_reference', ROOT / 'bench/push-e2e/reference.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def message_digest(messages):
    """PROOF1 facts[8] / the output preimage's last word for exactly one L2-to-L1 message."""
    assert len(messages) == 1
    num = lambda v: int(v, 16) if isinstance(v, str) else int(v)
    m = messages[0]
    payload = [num(x) for x in m['payload']]
    return reference().hash_span([num(m['from_address']), num(m['to_address']), len(payload), *payload])


def events(log):
    out = []
    for line in Path(log).read_text().splitlines():
        m = re.match(r'(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+)Z\s+INFO\s+(.*)', line)
        if m and ' close time.' not in line:
            out.append((datetime.fromisoformat(m[1] + '+00:00').timestamp(), m[2]))
    return out


def stage_peaks(log, samples_path):
    ev = events(log)
    samples = json.loads(Path(samples_path).read_text())
    out = {}
    for name, (a, b) in STAGES.items():
        ta = next((t for t, text in ev if text.endswith(a) or a in text), None)
        tb = next((t for t, text in ev if (text.endswith(b) or b in text) and ta is not None and t >= ta), None)
        if ta is None or tb is None:
            continue
        window = [s for s in samples if ta <= s['t'] <= tb and 'rss_kib' in s]
        out[name] = {'seconds': tb - ta, 'peak_rss_gib': max((s['rss_kib'] for s in window), default=0) / 2**20,
                     'rss_at_start_gib': (window[0]['rss_kib'] / 2**20) if window else None, 'samples': len(window)}
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--mode', choices=['recursive', 'cairo-only', 'recursion'], required=True)
    ap.add_argument('--pie', type=Path, required=True)
    ap.add_argument('--cap', type=int, required=True)
    ap.add_argument('--name', required=True)
    ap.add_argument('--cpus', default='0 1 2 3')
    ap.add_argument('--expected-messages', type=Path)
    ap.add_argument('--expect-failure', action='store_true')
    ap.add_argument('--results-dir', type=Path, default=H / 'results/phase0')
    ap.add_argument('--timeout', type=int, default=3600)
    a = ap.parse_args()
    run = RUNS / 'v2' / a.name
    run.mkdir(parents=True, exist_ok=False)
    a.results_dir.mkdir(parents=True, exist_ok=True)
    pie = a.pie.resolve()
    prove = capture.unit('v2-' + a.name, a.cap, [capture.PROVE_SMALL, a.mode, pie, run], run / 'prove.log',
                         cpus=a.cpus, runtime=a.timeout, sample=True)
    text = (run / 'prove.log').read_text()
    summary = {'name': a.name, 'mode': a.mode, 'cap_gib': a.cap, 'cpus': a.cpus, 'threads': prove['threads'], 'swap': 0,
               'pie': str(pie), 'pie_sha256': sha(pie) if pie.is_file() else sha(pie / 'proof.bin'), 'prove_small_sha256': sha(capture.PROVE_SMALL),
               'exit_code': prove['exit_code'], 'wall_seconds': prove['wall_seconds'],
               'peak_rss_gib': prove['max_rss_gib'], 'cgroup_peak_gib': prove['cgroup_peak_gib'],
               'oom_killed': prove['exit_code'] != 0 and ('oom-kill' in text or 'signal 9' in text or 'Killed' in text),
               'stages': stage_peaks(run / 'prove.log', str(run / 'prove.log') + '.samples.json'),
               'command': prove['command']}
    errors = [l.strip() for l in text.splitlines() if 'Error' in l or 'panicked' in l or 'error' in l.lower()]
    summary['error_lines'] = errors[-5:]
    if prove['exit_code'] == 0:
        summary.update(json.loads((run / 'summary.json').read_text()))
        summary['proof_sha256'] = sha(run / 'proof.bin')
        preimage = [int(x, 16) for x in json.loads((run / 'output-preimage.json').read_text())]
        summary['output_preimage'] = [hex(x) for x in preimage]
        if a.expected_messages:
            digest = message_digest(json.loads(a.expected_messages.read_text())['l2_to_l1_messages'])
            summary['message_matches_capture'] = preimage[-1] == digest and preimage[-2] == 1
        v = capture.unit('v2-verify-' + a.name, 8, [capture.PROVE_SMALL, 'verify', run], run / 'verify.log',
                         cpus='0', runtime=300)
        summary['verify'] = json.loads((run / 'verify.json').read_text()) if (run / 'verify.json').exists() else None
        summary['verify_exit_code'] = v['exit_code']
        summary['verify_peak_rss_gib'] = v['max_rss_gib']
        ok = v['exit_code'] == 0 and summary.get('message_matches_capture', True)
        if a.mode == 'cairo-only':
            summary['fixed_small_path_verifier_accepts'] = v['exit_code'] == 0
            ok = summary['native_verify'] and summary['native_pow_byte_mutation_rejected'] and \
                summary.get('message_matches_capture', True)
        summary['status'] = 'unexpected-success' if a.expect_failure else ('passed' if ok else 'failed-check')
    else:
        summary['status'] = 'expected-failure' if a.expect_failure and not summary['oom_killed'] else \
            ('oom' if summary['oom_killed'] else 'failed')
    (a.results_dir / (a.name + '.json')).write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps({k: summary.get(k) for k in ('name', 'status', 'threads', 'wall_seconds', 'prove_seconds',
                                                  'peak_rss_gib', 'proof_bytes', 'message_matches_capture')}
                     | {'stages': {k: (round(v['seconds'], 2), round(v['peak_rss_gib'], 2)) for k, v in summary['stages'].items()}}),
          flush=True)
    if summary.get('verify'):
        print(json.dumps({k: summary['verify'][k] for k in ('valid', 'passed', 'controls')}), flush=True)
    if summary['status'] not in ('passed', 'expected-failure'):
        raise SystemExit(2 if summary['status'] == 'oom' else 1)


if __name__ == '__main__':
    main()
