"""Build the isolated prover; never overwrite the accepted stock binary."""
from pathlib import Path
import json,subprocess,time,argparse,shutil,hashlib
H=Path(__file__).resolve().parent; E=json.loads((H/'environment.json').read_text()); W=Path(E['work'])
ap=argparse.ArgumentParser();ap.add_argument('--profile-allocations',action='store_true');a=ap.parse_args()
features='stwo_proving,memory_profile' if a.profile_allocations else 'stwo_proving'
cmd=['systemd-run','--user','--wait','--pipe','--unit=templar-memory-build-'+str(time.time_ns()),'-p',f'WorkingDirectory={W}/sequencer','-p','MemoryMax=24G','-p','MemorySwapMax=0','-p','CPUQuota=400%','-p','CPUAffinity=0 1 2 3','-p','RuntimeMaxSec=2400']
env={'RUSTUP_HOME':E['rustup_home'],'PATH':E['build_path'],'RUSTC_WRAPPER':'','RUSTFLAGS':'-Ctarget-cpu=native','CARGO_TARGET_DIR':str(W/'rust-target'),'CARGO_BUILD_JOBS':'4','RAYON_NUM_THREADS':'4'}
cmd+=['--setenv='+k+'='+v for k,v in env.items()]
cmd+=['/home/broody/.cargo/bin/rustup','run','nightly-2026-01-15','cargo','build','--offline','--release','-p','starknet_transaction_prover','--features',features]
with (H/'results/build.log').open('w') as log:r=subprocess.run(cmd,stdout=log,stderr=subprocess.STDOUT)
print('build exit',r.returncode,flush=True)
if r.returncode: print((H/'results/build.log').read_text()[-4500:])
if r.returncode==0:
 name='profiled-prover' if a.profile_allocations else 'low-memory-prover'
 (W/'bin').mkdir(exist_ok=True);shutil.copy2(W/'rust-target/release/starknet_transaction_prover',W/'bin'/name)
 files=['proving-utils.patch','sequencer.patch','overlay/low_memory.rs','overlay/memory_profile.rs']
 snapshot={'features':features,'binary_sha256':hashlib.sha256((W/'bin'/name).read_bytes()).hexdigest(),'source_sha256':{f:hashlib.sha256((H/f).read_bytes()).hexdigest() for f in files},'cargo_lock_sha256':hashlib.sha256((W/'sequencer/Cargo.lock').read_bytes()).hexdigest()}
 (H/'results'/f'{name}-build.json').write_text(json.dumps(snapshot,indent=2)+'\n')
raise SystemExit(r.returncode)
