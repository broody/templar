"""Fresh ordinary-only POC2 deployment using sncast and bounded test-STRK fees."""
from common import *
import hashlib

assert int(rpc('starknet_chainId',{}),16)==int.from_bytes(b'SN_SEPOLIA','big')
assert hashlib.sha256(Path(MANIFEST['prover']).read_bytes()).hexdigest()==MANIFEST['prover_sha256']
assert hashlib.sha256(Path(MANIFEST['verifier']).read_bytes()).hexdigest()==MANIFEST['verifier_sha256']
with (RUN/'results/deployment-build.log').open('w') as log:
 subprocess.run(['scarb','--release','build'],cwd=HERE/'cairo',env=ENV,stdout=log,stderr=subprocess.STDOUT,check=True)
classes={}
for contract in ['Pool','StatementAccount','NativeProofVerifier','E2EToken']:
 artifact=HERE/'cairo/target/release'/f'pool_{contract}.contract_class.json'
 expected=subprocess.check_output(['/home/broody/.starkli/bin/starkli','class-hash',str(artifact)],text=True).strip()
 try:
  rpc('starknet_getClass',{'block_id':'latest','class_hash':expected})
  classes[contract]=expected;save(RUN/'results'/f'reused-class-{contract}.json',{'class_hash':expected,'already_declared':True});continue
 except RuntimeError as e:
  if 'Class hash not found' not in str(e): raise
 print('Declare',contract,flush=True)
 v=normal_tx('declare-'+contract,['declare','--contract-name',contract,*bounds(850_000_000 if contract=='Pool' else 600_000_000)])
 assert int(v['class_hash'],16)==int(expected,16)
 classes[contract]=v['class_hash']
save(RUN/'results/classes.json',classes)
def deploy(name,klass,data):
 salt=(int(MANIFEST['deployment_salt_base'],16)+int.from_bytes(('PUSH_E2E_'+name).encode(),'big'))%(2**251)
 v=normal_tx('deploy-'+name,['deploy','--class-hash',classes[klass],'--salt',hex(salt),'--constructor-calldata',
                          *[hex(x) if isinstance(x,int) else x for x in data],*bounds(40_000_000)])
 return v['contract_address']
pool=deploy('pool','Pool',[ACCOUNT,0])
statement=deploy('statement','StatementAccount',[pool])
verifier=deploy('verifier','NativeProofVerifier',[pool,statement,classes['StatementAccount'],4096])
token=deploy('token','E2EToken',[ACCOUNT,10000,0])
start=json.loads((RUN/'results/deploy-pool/receipt.json').read_text())['block_number']
d={'pool':pool,'statement':statement,'verifier':verifier,'token':token,'statement_class':classes['StatementAccount'],
   'fee_collector':'0xfee','bob_withdrawal_address':'0xb0b','relayer':ACCOUNT,'max_proof_age':4096,
   'fee_amount':5,'classes':classes,'start_block':start}
save(RUN/'deployment.json',d)
invoke('configure-verifier',pool,'set_verifier',[verifier])
invoke('configure-fee',pool,'set_fee',[token,5,'0xfee'])
invoke('approve-test-token',token,'approve',[pool,10000,0])
assert call(pool,'get_verifier')==[int(verifier,16)]
save(RUN/'source-snapshot.json',{'source_hashes':{str(p.relative_to(HERE)):hashlib.sha256(p.read_bytes()).hexdigest()
     for p in sorted((HERE/'cairo/src').rglob('*.cairo'))},'classes':classes,'manifest':MANIFEST})
print('Deployment ready',json.dumps(d),flush=True)
