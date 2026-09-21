"""Initialize a new isolated run. Does not submit transactions."""
from pathlib import Path
import argparse,json,hashlib,tempfile
here=Path(__file__).resolve().parent
p=argparse.ArgumentParser();p.add_argument('--prover',required=True,type=Path);p.add_argument('--verifier',required=True,type=Path);p.add_argument('--upstream',required=True,type=Path);p.add_argument('--run-dir',type=Path);args=p.parse_args()
for file in [args.prover,args.verifier,args.upstream/'Cargo.lock']:assert file.exists(),file
prover_sha=hashlib.sha256(args.prover.read_bytes()).hexdigest();pins=json.loads((here/'source-snapshot.json').read_text());assert prover_sha==pins['prover_sha256'],'Different prover build: qualify it before reusing this benchmark baseline'
for file,sha in pins['copied_pool_files'].items():assert hashlib.sha256((here/'cairo'/file).read_bytes()).hexdigest()==sha,file
run=args.run_dir or Path(tempfile.mkdtemp(prefix='templar-stwo-e2e-'))
if args.run_dir:run.mkdir(mode=0o700,parents=True,exist_ok=False)
(run/'results').mkdir();(run/'cases').mkdir()
manifest={'runtime':str(run.resolve()),'deployment_salt_base':hex(int(hashlib.sha256(str(run.resolve()).encode()).hexdigest(),16)%(2**251)),'pool_source':str(here.parents[1]/'packages/pool'),'pool_source_sha256':pins['copied_pool_files'],'toolchain':'Scarb 2.18.0 / snforge 0.63.0','prover':str(args.prover.resolve()),'verifier':str(args.verifier.resolve()),'upstream':str(args.upstream.resolve())}
(run/'manifest.json').write_text(json.dumps(manifest,indent=2));(here/'run-location.json').write_text(json.dumps({'runtime':str(run.resolve())},indent=2));print(run)
