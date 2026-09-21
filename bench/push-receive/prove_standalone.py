"""Optional local recursive proof check using the preserved ADR-0018 harness.

This is the EARLIER staged-allocation standalone prover, not the Sepolia V1
virtual-OS service. Its artifacts are not native Starknet transaction proofs.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
import uuid

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT/'results'
DEFAULT_SOURCE = Path('/tmp/templar-stwo-privacy-dtgn6e8l/source')

def prove(name, source, binary, expected):
    prefix = RESULTS/(name+'.stwo')
    unit = 'templar-push-'+uuid.uuid4().hex[:10]
    command = ['systemd-run','--user','--wait','--pipe','--collect','--unit='+unit,
      '-p','WorkingDirectory='+str(source),'-p','MemoryMax=10G','-p','MemorySwapMax=0',
      '-p','CPUQuota=400%','-p','CPUAffinity=0 1 2 3','-p','RuntimeMaxSec=180',
      '--setenv=RAYON_NUM_THREADS=4','--setenv=RUST_MIN_STACK=4194304',
      '--setenv=PATH=/usr/bin:/bin','--setenv=BENCH_STAGED=1','--setenv=BENCH_NEGATIVE_VERIFY=1',
      '--setenv=BENCH_PIE='+str(RESULTS/f'{name}.pie.zip'),'--setenv=BENCH_OUTPUT='+str(prefix),
      '/usr/bin/time','-v',str(binary),'tests::slow_tests::test_privacy_recursive_prove_and_verify',
      '--exact','--nocapture','--test-threads=1']
    start = time.perf_counter()
    with (RESULTS/f'{name}.stwo.log').open('w') as log:
        p = subprocess.run(command,stdout=log,stderr=subprocess.STDOUT)
    log = (RESULTS/f'{name}.stwo.log').read_text()
    row = {'case':name,'scope':'earlier staged standalone privacy prover; no virtual OS or native submission',
      'command':command,'exit_code':p.returncode,'wall_seconds':time.perf_counter()-start,
      'limits':{'memory_gib':10,'swap':0,'cores':[0,1,2,3]},
      'prover_binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest()}
    rss = re.search(r'Maximum resident set size \(kbytes\): (\d+)',log)
    row['peak_rss_gib'] = int(rss[1])/1024**2 if rss else None
    (RESULTS/f'{name}.stwo.json').write_text(json.dumps(row,indent=2)+'\n')
    assert p.returncode == 0 and 'test result: ok.' in log, log[-6000:]
    assert 'BENCH_CHECK modified_statement_and_program_rejected' in log
    public = [int(x,16) for x in json.loads(Path(str(prefix)+'.public.json').read_text())]
    # The privacy bootloader binds the program hash and the exact serialized output.
    assert public[3:] == expected['pie_output'], (name,public,expected['pie_output'])
    assert public[:2] == [1,len(public)-1]
    proof = Path(str(prefix)+'.proof').read_bytes()
    row.update({'verified':True,'modified_output_and_program_rejected':True,'public_matches':True,
                'statement_program_hash':hex(public[2]),
                'proof_bytes':len(proof),'proof_sha256':hashlib.sha256(proof).hexdigest(),
                'stages':[line for line in log.splitlines() if 'BENCH_STAGE' in line]})
    (RESULTS/f'{name}.stwo.json').write_text(json.dumps(row,indent=2)+'\n')
    print(json.dumps({k:v for k,v in row.items() if k not in ['command','stages']},indent=2),flush=True)
    return row

def run():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('cases',nargs='*',default=['alice-send','carol-send','bob-spend'])
    parser.add_argument('--source',type=Path,default=DEFAULT_SOURCE)
    parser.add_argument('--binary',type=Path)
    args = parser.parse_args()
    binary = args.binary or args.source/'target/release/deps/privacy_prove-0f4017300f924673'
    assert binary.is_file(), 'Build the pinned ADR-0018 standalone harness first; see README.'
    cairo = json.loads((RESULTS/'cairo.json').read_text())
    cases = {r['case']:r for r in cairo['cases'] if r.get('public_matches')}
    archive = ROOT.parents[1]/'docs/adr/evidence/0018'
    earlier = json.loads((archive/'standalone-metadata.json').read_text())
    old_run = json.loads((archive/'standalone-ordinary.json').read_text())
    binary_hash = hashlib.sha256(binary.read_bytes()).hexdigest()
    assert binary_hash == old_run['binary_sha256'], 'Different binary: independently qualify before use.'
    metadata = {'source_revision_from_preserved_evidence':earlier['proving_revision'],
                'binary_matches_preserved_experiment':True,'binary_sha256':binary_hash,
                'source':str(args.source),'binary':str(binary),'source_files':{}}
    for name in ['crates/privacy_prove/src/lib.rs','crates/privacy_prove/src/tests.rs','Cargo.lock']:
        metadata['source_files'][name] = hashlib.sha256((args.source/name).read_bytes()).hexdigest()
    (RESULTS/'standalone-prover.json').write_text(json.dumps(metadata,indent=2)+'\n')
    for name in args.cases:
        prove(name,args.source,binary,cases[name])

if __name__ == '__main__':
    run()
