"""Isolated log22 small-Cairo preprocessing experiment; originals stay unchanged.

Extend only sequence columns and exact metadata. Commitment roots and recursive
circuit topology are regenerated from these public columns, never supplied by proof.
"""
from pathlib import Path
import hashlib,json,shutil,tomllib
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2];WORK=ROOT/'target/m31-private-wrapper/large-capacity'
CAIRO=Path('/home/broody/.cargo/git/checkouts/stwo-cairo-ef02e8e85a2fe399/9b6be27')
CIRCUITS=Path('/home/broody/.cargo/git/checkouts/stwo-circuits-acca305c7c7af9d7/5ef951a')
PU=Path('/home/broody/.cargo/git/checkouts/proving-utils-fe3a66dc6b32d5d3/3035dd0')
def main():
 WORK.mkdir(parents=True,exist_ok=True)
 for name,src in [('stwo-cairo',CAIRO),('stwo-circuits',CIRCUITS)]:
  dst=WORK/name
  if not dst.exists():shutil.copytree(src,dst,ignore=shutil.ignore_patterns('.git','target'))
 rel='stwo_cairo_prover/crates/common/src/preprocessed_columns/preprocessed_trace.rs';orig=(CAIRO/rel).read_text()
 changed=orig.replace('SMALL_MAX_SEQUENCE_LOG_SIZE: u32 = 20','SMALL_MAX_SEQUENCE_LOG_SIZE: u32 = 22').replace('PreProcessedTraceVariant::CanonicalSmall => 10161776','PreProcessedTraceVariant::CanonicalSmall => 16453232').replace('PreProcessedTraceVariant::CanonicalSmall => 156','PreProcessedTraceVariant::CanonicalSmall => 158').replace('PreProcessedTraceVariant::CanonicalSmall => 20','PreProcessedTraceVariant::CanonicalSmall => 22')
 assert changed!=orig and 'SMALL_MAX_SEQUENCE_LOG_SIZE: u32 = 22' in changed
 (WORK/'stwo-cairo'/rel).write_text(changed)
 # Extend the previously Small columns by sequence21 and sequence22:2^21+2^22 cells.
 assert 10161776+2**21+2**22==16453232
 out=HERE.parent/'results/bridge-capacity/large';out.mkdir(parents=True,exist_ok=True)
 (out/'source-change.json').write_text(json.dumps({'scope':'research larger preprocessing variant; incompatible trusted root','source':str(CAIRO/rel),'original_sha256':hashlib.sha256(orig.encode()).hexdigest(),'changed_sha256':hashlib.sha256(changed.encode()).hexdigest(),'max_sequence_log':22,'n_columns':158,'n_cells':16453232},indent=2)+'\n')
 direct={
  'privacy-prove':PU/'crates/privacy_prove','privacy-circuit-verify':PU/'crates/privacy_circuit_verify','cairo-program-runner-lib':PU/'crates/cairo-program-runner-lib',
  'cairo-air':WORK/'stwo-cairo/stwo_cairo_prover/crates/cairo-air','stwo-cairo-adapter':WORK/'stwo-cairo/stwo_cairo_prover/crates/adapter','stwo-cairo-prover':WORK/'stwo-cairo/stwo_cairo_prover/crates/prover',
  'circuit-cairo-verifier':WORK/'stwo-circuits/crates/cairo_verifier','circuit-common':WORK/'stwo-circuits/crates/circuit_common','circuit-prover':WORK/'stwo-circuits/crates/circuit_prover','circuit-verifier':WORK/'stwo-circuits/crates/circuit_verifier','circuit-serialize':WORK/'stwo-circuits/crates/circuit_serialize','circuits':WORK/'stwo-circuits/crates/circuits','circuits-stark-verifier':WORK/'stwo-circuits/crates/stark_verifier'}
 manifest='[package]\nname="templar-large-wrapper-capacity"\nversion="0.1.0"\nedition="2021"\n[workspace]\nexclude=["stwo-cairo", "stwo-circuits"]\n[[bin]]\nname="capacity"\npath='+json.dumps(str(HERE/'capacity.rs'))+'\n[dependencies]\n'
 manifest+=''.join(name+'={path='+json.dumps(str(p))+'}\n' for name,p in direct.items())
 manifest+='''stwo={git="https://github.com/starkware-libs/stwo",rev="489a0f3e",features=["parallel"]}
cairo-vm={git="https://github.com/lambdaclass/cairo-vm",rev=""}
serde="1"
serde_json="1"
tempfile="3"
zstd="0.13"
starknet-types-core="0.2.4"
'''
 # Exact cairo-vm spec from pinned workspace, preserving source identity.
 pu=tomllib.loads((PU/'Cargo.toml').read_text());vm=pu['workspace']['dependencies']['cairo-vm'];print('cairo_vm',vm)
 def inline(v):
  if isinstance(v,str):return json.dumps(v)
  return '{'+','.join(k+'='+json.dumps(x) for k,x in v.items())+'}'
 manifest=manifest.replace('cairo-vm={git="https://github.com/lambdaclass/cairo-vm",rev=""}', 'cairo-vm='+inline(vm))
 for repo,folder in [('stwo-cairo',WORK/'stwo-cairo/stwo_cairo_prover/crates'),('stwo-circuits',WORK/'stwo-circuits/crates')]:
  manifest+='\n[patch."https://github.com/starkware-libs/'+repo+'"]\n'
  for p in sorted(folder.glob('*/Cargo.toml')):
   info=tomllib.loads(p.read_text());name=info['package']['name'];manifest+=name+'={path='+json.dumps(str(p.parent))+'}\n'
 (WORK/'Cargo.toml').write_text(manifest)
 shutil.copyfile(Path('/tmp/templar-stwo-privacy-dtgn6e8l/sepolia-v1-test/upstream/sequencer-e6b6fd2e9932909107833579e5b6efd6c75fa0af/Cargo.lock'),WORK/'Cargo.lock')
 print(WORK/'Cargo.toml')
if __name__=='__main__':main()
