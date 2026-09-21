"""Compile/execute the experimental statement against positive and negative vectors."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT/'results'
P = 2**251 + 17*2**192 + 1
SCARB = os.environ.get('PUSH_SCARB', '/home/broody/.asdf/installs/scarb/2.18.0/bin/scarb')
PIE_EXECUTOR = os.environ.get('PUSH_PIE_EXECUTOR', '/home/broody/.asdf/installs/scarb/2.14.0/bin/scarb-execute')
env = dict(os.environ, PATH='/usr/bin:'+str(Path(SCARB).parent)+':'+os.environ['PATH'])

def run():
    subprocess.run([SCARB,'build'],cwd=ROOT/'cairo',env=env,check=True,
                   stdout=(RESULTS/'cairo-build.log').open('w'),stderr=subprocess.STDOUT)
    config = json.loads((RESULTS/'experiment.json').read_text())
    rows = []
    for case in config['cases']:
        name = case['name']
        cmd = [SCARB,'execute','--no-build','--target','standalone','--arguments-file',str(RESULTS/f'{name}.args.json'),
               '--output','none','--print-program-output','--print-resource-usage']
        start = time.perf_counter()
        p = subprocess.run(cmd,cwd=ROOT/'cairo',env=env,capture_output=True,text=True,timeout=60)
        log = p.stdout+p.stderr
        (RESULTS/f'{name}.execute.log').write_text(log)
        row = {'case':name,'exit_code':p.returncode,'seconds':time.perf_counter()-start}
        if case['expected_error']:
            assert p.returncode != 0 and case['expected_error'] in log, (name,log)
            row['rejected_at'] = case['expected_error']
        else:
            assert p.returncode == 0, (name,log)
            public = [int(x) % P for x in log.split('Program output:\n',1)[1].split('Resources:',1)[0].split()]
            assert public == [8,*case['public']], (name,public)
            row['public_matches'] = True
            for metric,pattern in [('steps',r'steps: ([\d,]+)'),('poseidon',r'poseidon_builtin: ([\d,]+)')]:
                row[metric] = int(re.search(pattern,log)[1].replace(',',''))
            # 2.18's bootloader target wraps the executable in a new runner PIE
            # rejected by the preserved privacy harness. 2.14 executes the same
            # 2.18-compiled Bootloader entry point directly and exports its PIE.
            pie_cmd = [PIE_EXECUTOR,'--no-build','--target','bootloader',
                       '--arguments-file',str(RESULTS/f'{name}.args.json'),
                       '--output','cairo-pie','--print-program-output','--print-resource-usage']
            pie_env = dict(env,SCARB=SCARB,SCARB_PROFILE='dev',
                           SCARB_TARGET_DIR=str(ROOT/'cairo/target'),SCARB_MANIFEST_PATH=str(ROOT/'cairo/Scarb.toml'))
            pp = subprocess.run(pie_cmd,cwd=ROOT/'cairo',env=pie_env,capture_output=True,text=True,timeout=60)
            pie_log = pp.stdout+pp.stderr
            (RESULTS/f'{name}.pie.log').write_text(pie_log)
            assert pp.returncode == 0, pie_log
            pie_output = [int(x) % P for x in pie_log.split('Program output:\n',1)[1].split('Resources:',1)[0].split()]
            assert pie_output == [8,*case['public']]
            row['pie_output'] = pie_output
            pie = ROOT/'cairo'/re.search(r'Saving output to: (.+cairo_pie.zip)',pie_log)[1]
            dst = RESULTS/f'{name}.pie.zip'
            shutil.copy2(pie,dst)
            row['pie_sha256'] = hashlib.sha256(dst.read_bytes()).hexdigest()
        rows.append(row)
        print(json.dumps(row),flush=True)
    report = {'scarb':subprocess.check_output([SCARB,'--version'],text=True).strip(),
              'pie_executor':subprocess.check_output([PIE_EXECUTOR,'--version'],text=True).strip(),
              'pie_executor_sha256':hashlib.sha256(Path(PIE_EXECUTOR).read_bytes()).hexdigest(),
              'source_sha256':hashlib.sha256((ROOT/'cairo/src/lib.cairo').read_bytes()).hexdigest(),'cases':rows}
    (RESULTS/'cairo.json').write_text(json.dumps(report,indent=2)+'\n')

if __name__ == '__main__':
    run()
