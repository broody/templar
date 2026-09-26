"""The hiding regression for R0 V6 (F27, ADR-0024 gate 4; docs/pool-v3-spec.md §4.4): the three
audits V5 recorded (results/stwo-client-r5/hiding), on V6's circuit. Rank: all 8 shapes. Seed
invariants and per-point rank: transfer and single. Writes results/stwo-client-r6/hiding/{rank,
invariants,points}.json; raw outputs go to RUN (default ~/.local/share/templar/runs/r6-p1/hiding).

    python3 hiding_r6.py [RUN]
"""
import json, os, subprocess, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
RUN = Path(sys.argv[1] if len(sys.argv) > 1 else os.path.expanduser('~/.local/share/templar/runs/r6-p1/hiding'))
OUT = HERE / 'results/stwo-client-r6/hiding'
SHAPES = ['transfer', 'single', 'one-out', 'partial', 'full', 'invoke', 'shadow', 'nft']
subprocess.run(['cargo', '+nightly-2026-01-15', 'build', '--release', '--example', 'hiding_rank', '--example', 'hiding_invariants',
                '--example', 'hiding_points'], cwd=HERE, check=True)
OUT.mkdir(parents=True, exist_ok=True)


def audit(example, key, shape, extra=()):
    out = RUN / f'{key}-r6-{shape}'
    subprocess.run([str(HERE / f'target/release/examples/{example}'), str(out), *extra, '--relation', 'r6', '--shape', shape],
                   cwd=HERE, check=True, capture_output=True, text=True)
    report = json.loads((out / 'report.json').read_text())
    print(key, shape, json.dumps({k: v for k, v in report.items() if k not in ('groups', 'results')})[:200], flush=True)
    return report


rank = {f'rank-r6-{s}': audit('hiding_rank', 'rank', s) for s in SHAPES}
(OUT / 'rank.json').write_text(json.dumps(rank, indent=1, sort_keys=True) + '\n')
inv = {f'inv-r6-{s}': audit('hiding_invariants', 'inv', s) for s in ('transfer', 'single')}
(OUT / 'invariants.json').write_text(json.dumps(inv, indent=1, sort_keys=True) + '\n')
pts = {f'pts-r6-{s}': audit('hiding_points', 'pts', s) for s in ('transfer', 'single')}
(OUT / 'points.json').write_text(json.dumps(pts, indent=1, sort_keys=True) + '\n')
summary = {
    'rank_unblinded_total': sum(r['unblinded_combinations_total'] for r in rank.values()),
    'seed_invariant_total': sum(r['seed_invariant_combinations'] for r in inv.values()),
    'points_full_rank': all(x['full_rank'] for r in pts.values() for x in r['results']),
}
print(json.dumps(summary))
assert summary['rank_unblinded_total'] == 0 and summary['seed_invariant_total'] == 0 and summary['points_full_rank']
