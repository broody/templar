#!/usr/bin/env python3
"""Generate both wallets' proofs using the same VK and collect bounded runtime evidence."""
from pathlib import Path
import json,shutil,subprocess
from bench import stage
ROOT=Path(__file__).resolve().parent;project=ROOT/'statement-native'
nargo=shutil.which('nargo');bb=shutil.which('bb');garaga='/tmp/garaga-venv/bin/garaga'
common=['-s','ultra_honk','--oracle_hash','keccak'];rows=[]
(ROOT/'cairo/tests').mkdir(exist_ok=True)
try:
 for who,fixture in [('alice','alice-pay'),('bob','bob-withdraw')]:
  shutil.copy2(project/f'fixtures/{fixture}.toml',project/'Prover.toml')
  out=project/'results'/who;out.mkdir(exist_ok=True)
  for label,command in [
   ('witness',[nargo,'execute','witness']),
   ('prove',[bb,'prove',*common,'-b',str(project/'target/bench.json'),'-w',str(project/'target/witness.gz'),'-k',str(project/'results/vk'),'-o',str(out)]),
   ('verify',[bb,'verify',*common,'-v','-k',str(project/'results/vk'),'-p',str(out/'proof'),'-i',str(out/'public_inputs')]),
   ('calldata',[garaga,'calldata','--system','ultra_keccak_zk_honk','--vk',str(project/'results/vk'),'--proof',str(out/'proof'),'--public-inputs',str(out/'public_inputs'),'--format','snforge','--output-path',str(out)])]:
   row=stage(project,f'{who}-{label}',command);rows.append(row)
   assert row['exit_code']==0,(who,label)
  shutil.copy2(out/'proof_calldata.txt',ROOT/f'cairo/tests/{who}.txt')
finally:
 shutil.copy2(project/'fixtures/alice-pay.toml',project/'Prover.toml')
 (ROOT/'results/flow-proving.json').write_text(json.dumps(rows,indent=2)+'\n')
