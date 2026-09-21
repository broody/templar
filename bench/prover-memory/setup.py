"""Create isolated source copies and build cache from the already-pinned V1 toolchain.

Defaults locate this workspace's existing Sepolia reference installation. Paths
can be overridden; environment.json records the actual inputs. Never modifies
source dependencies in Cargo's cache or the accepted stock installation.
"""
from pathlib import Path
import argparse,hashlib,json,shutil,subprocess
H=Path(__file__).resolve().parent;ROOT=H.parent.parent
BASE=Path('/tmp/templar-stwo-privacy-dtgn6e8l/sepolia-v1-test')
def main():
 ap=argparse.ArgumentParser(description=__doc__)
 ap.add_argument('--sequencer-source',type=Path,default=BASE/'upstream/sequencer-e6b6fd2e9932909107833579e5b6efd6c75fa0af')
 ap.add_argument('--proving-source',type=Path,default=Path('/home/broody/.cargo/git/checkouts/proving-utils-fe3a66dc6b32d5d3/3035dd0'))
 ap.add_argument('--stock-target',type=Path,default=BASE/'rust-target')
 ap.add_argument('--verifier',type=Path,default=BASE/'local-verifier')
 ap.add_argument('--rustup-home',type=Path,default=BASE.parent/'rustup')
 ap.add_argument('--build-path',default=str(BASE.parent/'sepolia-test/.cairo-venv/bin')+':/usr/bin:/home/broody/.cargo/bin:/bin')
 a=ap.parse_args();W=ROOT/'target/prover-memory';W.mkdir(parents=True,exist_ok=True)
 for src,dst in [(a.sequencer_source,W/'sequencer'),(a.proving_source,W/'proving-utils')]:
  assert (src/'Cargo.toml').is_file(),f'Missing source {src}'
  if not dst.exists():shutil.copytree(src,dst,ignore=shutil.ignore_patterns('.git','target'))
 assert a.verifier.is_file()
 if not (W/'rust-target').exists():subprocess.run(['cp','-a','--reflink=auto',str(a.stock_target),str(W/'rust-target')],check=True)
 e={'sequencer_original':str(a.sequencer_source.resolve()),'proving_original':str(a.proving_source.resolve()),'sequencer_revision':'e6b6fd2e9932909107833579e5b6efd6c75fa0af','proving_revision':'3035dd00421daa541894297bd754db6e2787807b','stock_prover':str(a.stock_target.resolve()/'release/starknet_transaction_prover'),'verifier':str(a.verifier.resolve()),'rustup_home':str(a.rustup_home.resolve()),'build_path':a.build_path,'work':str(W)}
 (H/'environment.json').write_text(json.dumps(e,indent=2)+'\n');(H/'results').mkdir(exist_ok=True)
 print('Isolated build environment ready.')
if __name__=='__main__':main()
