"""Declare/deploy only the synthetic benchmark statement; no pool or token writes."""
from common import *
import hashlib
with (RUN/'results/build.log').open('w') as f:subprocess.run(['scarb','--release','build'],cwd=HERE/'cairo',env=ENV,stdout=f,stderr=subprocess.STDOUT,check=True)
artifact=HERE/'cairo/target/release/pool_StatementAccount.contract_class.json'
klass=subprocess.check_output(['/home/broody/.starkli/bin/starkli','class-hash',str(artifact)],text=True).strip()
v=normal_tx('declare-statement',['declare','--contract-name','StatementAccount',*bounds(600_000_000)]);assert int(v['class_hash'],16)==int(klass,16)
base=json.loads((RUN/'controller-baseline-deployment.json').read_text())
d=normal_tx('deploy-statement',['deploy','--class-hash',klass,'--salt',MANIFEST['deployment_salt_base'],'--constructor-calldata',base['pool'],*bounds(40_000_000)])
base.update(live_pool_statement=base['statement'],live_pool_statement_class=base['statement_class'])
base.update(statement=d['contract_address'],statement_class=klass)
base['classes']['StatementAccount']=klass
save(RUN/'deployment.json',base)
save(RUN/'source-snapshot.json',{'protocol':'TEMPLAR_SHAPES_POC1','maximum_shape':[64,64,32],'statement_class':klass,'statement':base['statement'],
 'synthetic_membership_only':True,'no_pool_verifier_or_funds_changed':True,'source_hashes':{str(p.relative_to(HERE)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((HERE/'cairo/src').glob('*.cairo'))}})
print('Synthetic native statement deployed; existing pool verifier unchanged.',flush=True)
