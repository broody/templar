"""Audit recorded artifacts and collect the isolated experiment's evidence."""
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT/'results'

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def run():
    experiment = json.loads((RESULTS/'experiment.json').read_text())
    cairo = json.loads((RESULTS/'cairo.json').read_text())
    recovery = json.loads((RESULTS/'recovery.json').read_text())
    previous = json.loads((ROOT.parent/'push-receive/results/cairo.json').read_text())
    assert cairo['source_sha256'] == sha(ROOT/'cairo/src/lib.cairo')
    tests = (RESULTS/'python-tests.log').read_text()
    assert tests.rstrip().endswith('OK')
    proofs = []
    for case in ['alice-send','carol-send','bob-spend','restored-owner-spend']:
        row = json.loads((RESULTS/f'{case}.stwo.json').read_text())
        execution = next(x for x in cairo['cases'] if x['case']==case)
        expected = json.loads((RESULTS/f'{case}.public.json').read_text())
        public = [int(x,16) for x in json.loads((RESULTS/f'{case}.stwo.public.json').read_text())]
        assert row['verified'] and row['public_matches'] and row['modified_output_and_program_rejected']
        assert row['proof_sha256'] == sha(RESULTS/f'{case}.stwo.proof')
        assert execution['pie_sha256'] == sha(RESULTS/f'{case}.pie.zip')
        assert public == [1,11,int(row['statement_program_hash'],16),8,*expected]
        proofs.append({k:row[k] for k in ['case','wall_seconds','peak_rss_gib','proof_bytes','proof_sha256',
                                        'statement_program_hash','verified','modified_output_and_program_rejected']})
    assert len({p['statement_program_hash'] for p in proofs}) == 1
    comparisons = []
    for name in ['alice-send','carol-send','bob-spend']:
        old = next(x for x in previous['cases'] if x['case']==name)
        new = next(x for x in cairo['cases'] if x['case']==name)
        comparisons.append({'case':name,'old_steps':old['steps'],'new_steps':new['steps'],
                            'old_poseidon':old['poseidon'],'new_poseidon':new['poseidon'],
                            'extra_poseidon':new['poseidon']-old['poseidon']})
    sources = [*ROOT.glob('*.py'),ROOT/'README.md',ROOT/'cairo/Scarb.toml',ROOT/'cairo/Scarb.lock',ROOT/'cairo/src/lib.cairo',
               ROOT.parent/'stwo-e2e/reference.py',ROOT.parents[1]/'docs/adr/0020-full-viewing-and-recovery.md']
    report = {'scope':'isolated model, Cairo execution and earlier standalone privacy prover; no new deployment',
      'python_tests':int(re.search(r'Ran (\d+) tests',tests)[1]),
      'valid_cairo_vectors':sum(bool(x.get('public_matches')) for x in cairo['cases']),
      'rejected_cairo_vectors':sum(bool(x.get('rejected_at')) for x in cairo['cases']),
      'ciphertext_bytes_per_output':experiment['ciphertext_bytes_per_note'],
      'discovery':experiment['discovery'],'final_balances':experiment['final_balances'],
      'withdrawn':experiment['withdrawn'],'after_seed_restore':experiment['recovery'],
      'recovery_demo':recovery,'cairo_comparison_with_poc1':comparisons,'proofs':proofs,
      'source_hashes':{str(p.relative_to(ROOT.parents[1])):sha(p) for p in sources}}
    (RESULTS/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k!='source_hashes'},indent=2))

if __name__ == '__main__':
    run()
