"""Build the isolated prover; never overwrite the accepted stock binary."""
from pathlib import Path
import json,subprocess,time,argparse,shutil,hashlib,re
H=Path(__file__).resolve().parent; E=json.loads((H/'environment.json').read_text()); W=Path(E['work'])
ap=argparse.ArgumentParser();ap.add_argument('--profile-allocations',action='store_true');a=ap.parse_args()
features='stwo_proving,memory_profile' if a.profile_allocations else 'stwo_proving'
name='profiled-prover' if a.profile_allocations else 'low-memory-prover'
log_path=H/'results'/f'{name}-build.log'
if log_path.exists():log_path.rename(H/'results'/f'previous-build-attempt-{time.time_ns()}.log')
files=['stwo.patch','stwo-cairo.patch','stwo-circuits.patch','integration.patch','setup.py','build.py']
def source_tree_hash():
 digest=hashlib.sha256()
 for directory in ['stwo','stwo-cairo','stwo-circuits','proving-utils','sequencer']:
  paths=sorted(p for p in (W/directory).rglob('*') if p.is_file() and p.suffix in ['.rs','.toml'] and 'target' not in p.relative_to(W).parts)
  for p in paths:
   digest.update(str(p.relative_to(W)).encode()+b'\0');digest.update(p.read_bytes())
 return digest.hexdigest()
source_before=source_tree_hash()
cmd=['systemd-run','--user','--wait','--pipe','--unit=templar-memory-build-'+str(time.time_ns()),'-p',f'WorkingDirectory={W}/sequencer','-p','MemoryMax=24G','-p','MemorySwapMax=0','-p','CPUQuota=1200%','-p','CPUAffinity=0 1 2 3 4 5 6 7 8 9 10 11','-p','RuntimeMaxSec=2400']
env={'RUSTUP_HOME':E['rustup_home'],'PATH':E['build_path'],'RUSTC_WRAPPER':'','RUSTFLAGS':'-Ctarget-cpu=native','CARGO_TARGET_DIR':str(W/'rust-target'),'CARGO_BUILD_JOBS':'12','RAYON_NUM_THREADS':'4'}
cmd+=['--setenv='+k+'='+v for k,v in env.items()]
cmd+=['/home/broody/.cargo/bin/rustup','run','nightly-2026-01-15','cargo','build','--offline','--release','-p','starknet_transaction_prover','--features',features]
with log_path.open('w') as log:r=subprocess.run(cmd,stdout=log,stderr=subprocess.STDOUT)
if r.returncode==0 and not re.search(r'Finished .release. profile',log_path.read_text()):
 print('No Cargo release completion: refusing to publish a possibly stale binary.',flush=True)
 raise SystemExit(1)
print('build exit',r.returncode,flush=True)
if r.returncode: print(log_path.read_text()[-4500:])
if r.returncode==0:
 assert source_tree_hash()==source_before,'Source changed during the build; rebuild before benchmarking'
 (W/'bin').mkdir(exist_ok=True);shutil.copy2(W/'rust-target/release/starknet_transaction_prover',W/'bin'/name)
 binary_hash=hashlib.sha256((W/'bin'/name).read_bytes()).hexdigest()
 artifact_id=binary_hash[:12]+'-'+source_before[:8]
 snapshot={'features':features,'artifact_id':artifact_id,'source_tree_sha256':source_before,'binary_sha256':binary_hash,'source_sha256':{f:hashlib.sha256((H/f).read_bytes()).hexdigest() for f in files},'cargo_lock_sha256':hashlib.sha256((W/'sequencer/Cargo.lock').read_bytes()).hexdigest()}
 archive=H/'results/builds'/artifact_id;archive.mkdir(parents=True,exist_ok=True)
 binaries=W/'bin/builds';binaries.mkdir(exist_ok=True)
 shutil.copy2(W/'bin'/name,binaries/artifact_id)
 for f in files:shutil.copy2(H/f,archive/f)
 shutil.copy2(log_path,archive/'build.log');shutil.copy2(W/'sequencer/Cargo.lock',archive/'Cargo.lock')
 (archive/'metadata.json').write_text(json.dumps(snapshot,indent=2)+'\n')
 (H/'results'/f'{name}-build.json').write_text(json.dumps(snapshot,indent=2)+'\n')
 shutil.copy2(W/'sequencer/Cargo.lock',H/'results/Cargo.lock')
raise SystemExit(r.returncode)
