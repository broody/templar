"""Run the PROOF2 large path (`prove_large`) under a hard memory cap with an optional
bounded-memory storage policy, and record where its memory goes.

The prover runs in its own cgroup (`systemd-run --user`, zero swap, four pinned workers). Its
memory (`MemoryCurrent`) is sampled every 0.5 s and each sample is attributed to the stage the
prover's log was in at that time (the last `Program execution done` / span-close / `... done`
line), giving a per-stage peak. The summary adds the kernel's peak RSS and the proof's
verification and rejection checks from `prove_large`.

    bounded.py PIE OUT [--cap 115G] [--cairo N] [--circuit N] [--no-stream] [--bin PATH]

`--cairo` / `--circuit`: FRI column batch size for the Cairo and circuit stages (0 = default
storage). Never run while another build or proving job is running on the host."""
from pathlib import Path
import argparse, datetime, json, re, subprocess, threading, time

ROOT = Path(__file__).resolve().parents[3]
BIN = ROOT / 'target/proving-server-target/release/examples/prove_large'
WORKDIR = ROOT / 'target/proving-server'


def sampler(unit, stop, rows):
    while not stop.is_set():
        r = subprocess.run(['systemctl', '--user', 'show', unit, '-p', 'MemoryCurrent', '--value'],
                           capture_output=True, text=True)
        v = r.stdout.strip()
        if v.isdigit():
            rows.append((time.time(), int(v)))
        time.sleep(0.5)


STAGE = re.compile(r'^(\S+Z)\s+INFO\s+(.*)$')
ANSI = re.compile(r'\x1b\[[0-9;]*m')
# Spans worth a stage of their own (closing one starts the next stage).
SPANS = ('Write Preprocessed trace', 'Compute preprocessed trace commitment', 'Write Base trace',
         'Compute base trace commitment', 'Write interaction trace', 'Compute interaction trace commitment',
         'Prove STARKs', 'prove_cairo', 'cairo run')


def stages(log):
    """(unix time, label) for each milestone in the prover's log: selected span closes and the
    leaf prover's `... done` lines."""
    out = []
    for line in log.splitlines():
        m = STAGE.match(ANSI.sub('', line))
        if not m:
            continue
        t = datetime.datetime.fromisoformat(m.group(1).replace('Z', '+00:00')).timestamp()
        text = m.group(2)
        head, _, msg = text.rpartition(': ')
        if msg.startswith('close'):
            span = head.rsplit(': ', 1)[0].split(':')[-1].strip()
            if span in SPANS:
                out.append((t, 'after ' + span))
        elif msg.rstrip('.').endswith('done'):
            out.append((t, 'after ' + msg.split('.')[0]))
    return out


def main():
    import sys
    if len(sys.argv) == 3 and sys.argv[1] == '--reanalyze':
        print(json.dumps(analyze(Path(sys.argv[2])), indent=1))
        return
    ap = argparse.ArgumentParser()
    ap.add_argument('pie', type=Path)
    ap.add_argument('out', type=Path)
    ap.add_argument('--cap', default='115G')
    ap.add_argument('--cairo', type=int, default=0)
    ap.add_argument('--circuit', type=int, default=0)
    ap.add_argument('--bin', type=Path, default=BIN)
    ap.add_argument('--no-stream', action='store_true', help='bounded trees built whole, not 16 columns at a time')
    a = ap.parse_args()
    out = a.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    unit = f'templar-proof2-bounded-{time.time_ns()}'
    cmd = ['systemd-run', '--user', '--wait', '--pipe', f'--unit={unit}', f'-p', f'MemoryMax={a.cap}', '-p', 'MemorySwapMax=0',
           '-p', 'CPUQuota=400%', '-p', 'CPUAffinity=0 1 2 3', '-p', f'WorkingDirectory={WORKDIR}',
           '--setenv=RAYON_NUM_THREADS=4', f'--setenv=TEMPLAR_BOUNDED_CAIRO_COLUMNS={a.cairo}',
           f'--setenv=TEMPLAR_BOUNDED_CIRCUIT_COLUMNS={a.circuit}', '--setenv=TEMPLAR_SPAN_EVENTS=1',
           f'--setenv=TEMPLAR_BOUNDED_STREAM={0 if a.no_stream else 1}',
           '/usr/bin/time', '-v', str(a.bin.resolve()), str(a.pie.resolve()), str(out)]
    rows, stop = [], threading.Event()
    th = threading.Thread(target=sampler, args=(unit, stop, rows), daemon=True)
    start = time.time()
    with (out / 'run.log').open('w') as log:
        th.start()
        r = subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT)
    stop.set()
    th.join()
    elapsed = time.time() - start
    (out / 'memory.csv').write_text('unix_time,bytes\n' + ''.join(f'{t:.2f},{b}\n' for t, b in rows))
    summary = {'pie': str(a.pie), 'cap': a.cap, 'cairo_fri_columns': a.cairo or None,
               'circuit_fri_columns': a.circuit or None, 'stream_commitments': not a.no_stream,
               'exit_code': r.returncode, 'elapsed_seconds': elapsed}
    (out / 'bounded-summary.json').write_text(json.dumps(summary, indent=1) + '\n')
    print(json.dumps(analyze(out), indent=1))


def analyze(out):
    """Per-stage peaks from a run directory's `memory.csv` and `run.log`; updates its summary."""
    summary = json.loads((out / 'bounded-summary.json').read_text())
    log = (out / 'run.log').read_text()
    rows = [tuple(map(float, l.split(','))) for l in (out / 'memory.csv').read_text().splitlines()[1:]]
    marks = stages(log)
    per_stage = {}
    for t, b in rows:
        label = 'before program execution'
        for mt, ml in marks:
            if mt <= t:
                label = ml
        per_stage[label] = max(per_stage.get(label, 0), int(b))
    rss = [l for l in log.splitlines() if 'Maximum resident' in l]
    killed = 'Killed' in log or summary['exit_code'] == 137 or 'oom' in log.lower()
    summary.update({
        'oom_killed': killed,
        'max_rss_gib': int(rss[-1].split()[-1]) / 2**20 if rss else None,
        'cgroup_peak_gib': max((b for _, b in rows), default=0) / 2**30,
        'stage_peaks_gib': {k: round(v / 2**30, 2) for k, v in per_stage.items()},
    })
    if (out / 'summary.json').exists():
        summary['prover'] = json.loads((out / 'summary.json').read_text())
    (out / 'bounded-summary.json').write_text(json.dumps(summary, indent=1) + '\n')
    return summary


if __name__ == '__main__':
    main()
