"""Build an isolated Cairo verifier from a trusted server-circuit build manifest.

Vendor source is copied from the preserved direct-air bridge; originals are untouched.
Never run this using a manifest supplied by an untrusted proof producer.
"""
from pathlib import Path
import hashlib, importlib.util, json, shutil, subprocess
HERE=Path(__file__).resolve().parent
ROOT=HERE.parent.parent
WORK=ROOT/'target/m31-private-wrapper/server-cairo'
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    manifest_path=HERE/'results/server-circuit/proof/trusted-config.json'
    manifest=json.loads(manifest_path.read_text())
    assert manifest['purpose']=='public-blake-server-circuit'
    assert manifest['output_addresses']==list(range(3,19))
    WORK.mkdir(parents=True,exist_ok=True)
    shutil.copytree(HERE/'server-cairo',WORK,dirs_exist_ok=True)
    source=HERE.parent/'direct-air/cairo'
    shutil.copytree(source/'vendor',WORK/'vendor',dirs_exist_ok=True)
    spec=importlib.util.spec_from_file_location('trusted_generator',source/'generate_constants.py')
    gen=importlib.util.module_from_spec(spec);spec.loader.exec_module(gen)
    # Reuse identical validated topology/config generation. Purpose describes the old caller,
    # so adapt only that metadata field; never change root, columns, outputs or security config.
    adapted=dict(manifest,purpose='synthetic-diagnostic')
    generated=gen.generate(adapted)
    for name,text in generated.items():
        (WORK/'vendor'/name).write_text(text.replace('trusted synthetic circuit','trusted public server hash circuit'))
    record={'trusted_manifest_sha256':sha(manifest_path),'work':str(WORK),'source_files':{str(p.relative_to(ROOT)):sha(p) for p in sorted((source/'vendor').rglob('*')) if p.is_file()},'generated_files':{n:sha(WORK/'vendor'/n) for n in generated},'template_files':{str(p.relative_to(HERE)):sha(p) for p in sorted((HERE/'server-cairo').rglob('*')) if p.is_file()}}
    (HERE/'results/server-circuit/bridge-build.json').write_text(json.dumps(record,indent=2)+'\n')
    subprocess.run(['scarb','--manifest-path',str(WORK/'Scarb.toml'),'build','-p','templar_server_hash_bridge'],check=True)
    subprocess.run(['scarb','--profile','contract','--manifest-path',str(WORK/'Scarb.toml'),'build','-p','templar_server_hash_account'],check=True)
if __name__=='__main__': main()
