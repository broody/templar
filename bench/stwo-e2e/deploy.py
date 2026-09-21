from common import *
assert int(rpc('starknet_chainId',{}),16)==int.from_bytes(b'SN_SEPOLIA','big')
with (RUN/'results/deployment-build.log').open('w') as log:
 subprocess.run(['scarb','--release','build'],cwd=HERE/'cairo',env=ENV,stdout=log,stderr=subprocess.STDOUT,check=True)
classes={}
for contract in ['Pool','StatementAccount','NativeProofVerifier','E2EToken']:
 artifact=HERE/'cairo/target/release'/f'pool_{contract}.contract_class.json'
 expected=subprocess.check_output(['/home/broody/.starkli/bin/starkli','class-hash',str(artifact)],text=True).strip()
 try:
  rpc('starknet_getClass',{'block_id':'latest','class_hash':expected})
  classes[contract]=expected;save(RUN/'results'/f'reused-class-{contract}.json',{'class_hash':expected,'already_declared':True});print('reuse declared class',contract,flush=True);continue
 except RuntimeError as e:
  if 'Class hash not found' not in str(e):raise
 print('declare',contract,flush=True)
 v=normal_tx('declare-'+contract,['declare','--contract-name',contract,*bounds(850_000_000 if contract=="Pool" else 600_000_000)]);classes[contract]=v['class_hash']
save(RUN/'results/classes.json',classes)
def deploy(name,klass,calldata):
 salt=(int(MANIFEST.get('deployment_salt_base','0x0'),16)+int.from_bytes(('STWO_E2E_'+name).encode(),'big'))%(2**251)
 v=normal_tx('deploy-'+name,['deploy','--class-hash',classes[klass],'--salt',hex(salt),'--constructor-calldata',*[hex(x) if isinstance(x,int) else x for x in calldata],*bounds(40_000_000)]);return v['contract_address']
pool=deploy('pool','Pool',[ACCOUNT,0,0])
statement=deploy('statement','StatementAccount',[pool])
verifier=deploy('verifier','NativeProofVerifier',[pool,statement,classes['StatementAccount'],4096])
token=deploy('token','E2EToken',[ACCOUNT,10000,0])
d={'pool':pool,'statement':statement,'verifier':verifier,'token':token,'statement_class':classes['StatementAccount'],'fee_collector':'0xfee','bob_withdrawal_address':'0xb0b','relayer':ACCOUNT,'max_proof_age':4096,'fee_amount':5,'classes':classes};save(RUN/'deployment.json',d)
invoke('configure-verifier',pool,'set_verifier',[verifier])
invoke('configure-fee',pool,'set_fee',[token,5,'0xfee'])
invoke('approve-test-token',token,'approve',[pool,10000,0])
assert call(pool,'get_verifier')==[int(verifier,16)]
print('Deployment ready',json.dumps(d),flush=True)
