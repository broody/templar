"""Fresh Templar pool and unchanged upstream adapter; existing synthetic Ekubo pair."""
from common import *
import hashlib

assert int(rpc('starknet_chainId',{}),16)==int.from_bytes(b'SN_SEPOLIA','big')
assert hashlib.sha256(Path(MANIFEST['prover']).read_bytes()).hexdigest()==MANIFEST['prover_sha256']
assert hashlib.sha256(Path(MANIFEST['verifier']).read_bytes()).hexdigest()==MANIFEST['verifier_sha256']
with (RUN/'results/deployment-build.log').open('w') as log:
 subprocess.run(['scarb','--release','build'],cwd=HERE/'cairo',env=ENV,stdout=log,stderr=subprocess.STDOUT,check=True)
classes={}
for contract in ['Pool','StatementAccount','NativeProofVerifier','EkuboSwapAnonymizer']:
 artifact=HERE/'cairo/target/release'/f'pool_{contract}.contract_class.json'
 expected=subprocess.check_output(['/home/broody/.starkli/bin/starkli','class-hash',str(artifact)],text=True).strip()
 try:
  rpc('starknet_getClass',{'block_id':'latest','class_hash':expected})
  classes[contract]=expected
  save(RUN/'results'/f'reused-class-{contract}.json',{'class_hash':expected,'already_declared':True})
  continue
 except RuntimeError as e:
  if 'Class hash not found' not in str(e): raise
 print('Declare',contract,flush=True)
 v=normal_tx('declare-'+contract,['declare','--contract-name',contract,*bounds(1_100_000_000 if contract=='Pool' else 600_000_000)])
 assert int(v['class_hash'],16)==int(expected,16)
 classes[contract]=v['class_hash']
save(RUN/'results/classes.json',classes)

def deploy(name,klass,data):
 salt=(int(MANIFEST['deployment_salt_base'],16)+int.from_bytes(('RETURN_'+name).encode(),'big'))%(2**251)
 args=['deploy','--class-hash',classes[klass],'--salt',hex(salt)]
 if data: args+=['--constructor-calldata',*[hex(x) if isinstance(x,int) else x for x in data]]
 v=normal_tx('deploy-'+name,args+bounds(40_000_000))
 return v['contract_address']

old_run=Path(json.loads((HERE.parent/'defi-return-e2e/run-location.json').read_text())['runtime'])
old=json.loads((old_run/'deployment.json').read_text())
ekubo=json.loads((RUN/'ekubo.json').read_text())
for key in ['core','router','positions']:
 assert ekubo[key]['address']==old['ekubo'][key]['address']
 assert int(ekubo[key]['class_hash'],16)==int(old['ekubo'][key]['class_hash'],16),'Ekubo deployment changed; review before proceeding'
pool=deploy('pool','Pool',[ACCOUNT,0])
statement=deploy('statement','StatementAccount',[pool])
verifier=deploy('verifier','NativeProofVerifier',[pool,statement,classes['StatementAccount'],4096])
adapter=deploy('upstream-ekubo','EkuboSwapAnonymizer',[])
start=json.loads((RUN/'results/deploy-pool/receipt.json').read_text())['block_number']
d={'pool':pool,'statement':statement,'statement_class':classes['StatementAccount'],'verifier':verifier,
   'token':old['token_a'],'token_a':old['token_a'],'token_b':old['token_b'],'adapter':adapter,
   'relayer':ACCOUNT,'start_block':start,'classes':classes,'ekubo':ekubo,'pool_key':old['pool_key'],
   'protocol':'TEMPLAR_RETURN_POC1','ordinary_notes_only':True,
   'upstream_revision':'b40bf109c8e5b97d9d6e8ec6db48b16b9d10a106',
   'adapter_source_unchanged':True,'synthetic_pair_reused_from':'../defi-return-e2e'}
save(RUN/'deployment.json',d)
invoke('configure-verifier',pool,'set_verifier',[verifier])
invoke('approve-token-a',d['token_a'],'approve',[pool,5000,0])
assert call(pool,'get_verifier')==[int(verifier,16)]
save(RUN/'source-snapshot.json',{'source_hashes':{str(p.relative_to(HERE)):hashlib.sha256(p.read_bytes()).hexdigest()
 for p in sorted((HERE/'cairo/src').rglob('*.cairo'))},'classes':classes,
 'scarb_lock_sha256':hashlib.sha256((HERE/'cairo/Scarb.lock').read_bytes()).hexdigest(),
 'upstream_revision':d['upstream_revision'],'adapter_source_unchanged':True})
print('Fresh pool and unchanged upstream Ekubo adapter ready.',flush=True)
