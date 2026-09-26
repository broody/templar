"""Phase 2: the proving sweep over phase-1 captures, one run at a time. No chain.

- `sweep`: compact k in {0, 16, 32, 64, 106} through V1 stock, V1 bounded (bench/bounded-memory
  run.py's full environment) and V2 small unbounded (`prove-small recursive`). Caps escalate
  16 -> 32 -> 64 -> 96 GiB on OOM (zero swap, cores 0-3); the first passing cap is reused for
  repeats (three at k = 0 and k = 106, one elsewhere).
- `stages VARIANT...`: at k = 106, `prove-small cairo-only` (escalating caps: the Cairo stage),
  then the recursion stage alone from it (`prove-small recursion`, a fresh process). For compact it
  is the stock recursion-stage proxy; for QM31 variants it and `prove-small recursive` are expected
  to fail (U2), the negative controls.
- `scaling`: 1, 4, 8 and 16 threads on physical cores 0, 0-3, 0-7, 0-15, for compact k = 106
  (V2 small recursive) and the qm31 Cairo stage (`cairo-only`).
Every run checks its proof's message against the capture's and verifies the proof with its
rejection controls (the run scripts). Results go to results/phase2/.
"""
from pathlib import Path
import json, subprocess, sys

H = Path(__file__).resolve().parent
ROOT = H.parents[1]
RUNS = Path.home() / '.local/share/templar/runs/m31-device-proof1'
OUT = H / 'results/phase2'
CAPS = [16, 32, 64, 96]
LOG = OUT / 'phase2-driver.jsonl'


def record(entry):
    OUT.mkdir(parents=True, exist_ok=True)
    with LOG.open('a') as f:
        f.write(json.dumps(entry) + '\n')


def capture_dir(variant, k):
    return RUNS / 'phase1' / variant / f'k{k}'


def v1(variant_v1, variant, k, cap, name, cpus='0 1 2 3'):
    prep = json.loads((RUNS / 'phase1' / variant / 'prepare.json').read_text())
    d = capture_dir(variant, k)
    cmd = [sys.executable, str(H / 'run_v1.py'), '--variant', variant_v1,
           '--fixture', str(RUNS / 'phase1' / variant / 'state-fixture.json'), '--fixture-sha256', prep['fixture_sha256'],
           '--request', str(d / 'request.json'), '--expected-messages', str(d / 'os/capture.json'),
           '--cap', str(cap), '--name', name, '--cpus', cpus, '--phase', 'phase2', '--timeout', '3000']
    return subprocess.run(cmd).returncode


def v2(mode, variant, k, cap, name, cpus='0 1 2 3', expect_failure=False):
    d = capture_dir(variant, k)
    cmd = [sys.executable, str(H / 'run_v2.py'), '--mode', mode, '--pie', str(d / 'os/os.pie.zip'),
           '--expected-messages', str(d / 'os/capture.json'), '--cap', str(cap), '--name', name,
           '--cpus', cpus, '--results-dir', str(OUT / 'v2'), '--timeout', '5400']
    if expect_failure:
        cmd.append('--expect-failure')
    return subprocess.run(cmd).returncode


def escalate(run, base_name, start_cap=16):
    """Run at increasing caps until it passes (exit 0) or fails for a reason other than OOM."""
    for cap in [c for c in CAPS if c >= start_cap]:
        name = f'{base_name}-{cap}g'
        code = run(cap, name)
        record({'name': name, 'cap': cap, 'exit': code})
        if code == 0:
            return cap
        if code != 2:
            return None
    return None


def sweep(ks):
    for k in ks:
        repeats = 3 if k in (0, 106) else 1
        for prover in ('v1-stock', 'v1-bounded', 'v2-small'):
            if prover == 'v2-small':
                run = lambda cap, name: v2('recursive', 'compact', k, cap, name)
            else:
                run = lambda cap, name, p=prover: v1(p.split('-')[1], 'compact', k, cap, name)
            base = f'compact-k{k}-{prover}'
            cap = escalate(run, base)
            record({'group': base, 'passing_cap': cap})
            if cap is None:
                continue
            for r in range(2, repeats + 1):
                name = f'{base}-{cap}g-r{r}'
                record({'name': name, 'cap': cap, 'exit': run(cap, name)})


def recursion_stage(cairo_run, name, cap, variant, k, expect_failure=False):
    """The recursion stage alone, in a fresh process, from a cairo-only run directory."""
    d = capture_dir(variant, k)
    cmd = [sys.executable, str(H / 'run_v2.py'), '--mode', 'recursion', '--pie', str(RUNS / 'v2' / cairo_run),
           '--expected-messages', str(d / 'os/capture.json'), '--cap', str(cap), '--name', name,
           '--results-dir', str(OUT / 'v2'), '--timeout', '3600']
    if expect_failure:
        cmd.append('--expect-failure')
    return subprocess.run(cmd).returncode


def stages(variant, k=106):
    """Cairo stage (cairo-only) and recursion stage (fresh process) for a variant; for QM31 the
    recursion attempts are the U2 negative controls: the in-process `recursive` and the stage alone."""
    base = f'{variant}-k{k}-v2-cairo-only'
    cap = escalate(lambda cap, name: v2('cairo-only', variant, k, cap, name), base)
    record({'group': base, 'passing_cap': cap})
    if cap is None:
        return
    qm31 = variant.startswith('qm31')
    name = f'{variant}-k{k}-v2-recursion'
    record({'name': name, 'exit': recursion_stage(f'{base}-{cap}g', name, 32, variant, k, expect_failure=qm31)})
    if qm31:
        name = f'{variant}-k{k}-v2-recursive-u2-negative'
        record({'name': name, 'exit': v2('recursive', variant, k, cap, name, expect_failure=True)})


def scaling(variant_cap):
    for threads, cpus in ((1, '0'), (4, '0-3'), (8, '0-7'), (16, '0-15')):
        for variant, mode, cap in variant_cap:
            name = f'scaling-{variant}-k106-{mode}-t{threads}'
            record({'name': name, 'exit': v2(mode, variant, 106, cap, name, cpus=cpus)})


if __name__ == '__main__':
    cmd = sys.argv[1]
    if cmd == 'sweep':
        sweep([int(k) for k in sys.argv[2:]] or [0, 16, 32, 64, 106])
    elif cmd == 'stages':
        for v in sys.argv[2:]:
            stages(v)
    elif cmd == 'scaling':
        # scaling VARIANT:MODE:CAP ...
        scaling([tuple(x.split(':')[:2]) + (int(x.split(':')[2]),) for x in sys.argv[2:]])
    else:
        raise SystemExit(__doc__)
