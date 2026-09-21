"""Initialize isolated Sepolia runtime. Does not sign or submit transactions."""
import hashlib,json,tempfile,os,secrets
from starknet_py.hash.utils import private_to_stark_key
from pathlib import Path

here=Path(__file__).resolve().parent
assert not (here/'run-location.json').exists(), 'Existing run: resume it, do not replace its pointer.'
old=here.parent/'stwo-e2e'
baseline=json.loads((old/'source-snapshot.json').read_text())
old_run=Path(json.loads((old/'run-location.json').read_text())['runtime'])
previous=json.loads((old_run/'manifest.json').read_text())
assert hashlib.sha256(Path(previous['prover']).read_bytes()).hexdigest()==baseline['prover_sha256']
assert Path(previous['verifier']).is_file() and Path(previous['upstream']).is_dir()
run=Path(tempfile.mkdtemp(prefix='templar-control-e2e-'))
os.chmod(run,0o700)
for name in ['results','cases']: (run/name).mkdir()
manifest={k:previous[k] for k in ['prover','verifier','upstream','toolchain']}
manifest.update(runtime=str(run),deployment_salt_base=hex(int.from_bytes(os.urandom(31),'big')),
                protocol='TEMPLAR_CONTROL_POC1',prover_sha256=baseline['prover_sha256'],
                verifier_sha256=hashlib.sha256(Path(previous['verifier']).read_bytes()).hexdigest(),
                baseline_snapshot=baseline)
private_key=secrets.randbelow(2**250-1)+1
key_path=run/'controller-key.json'
key_path.write_text(json.dumps({'private_key':private_key,'public_key':private_to_stark_key(private_key)})+'\n')
os.chmod(key_path,0o600)
(run/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
(here/'run-location.json').write_text(json.dumps({'runtime':str(run)},indent=2)+'\n')
print(run)
