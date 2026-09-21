"""Deploy an isolated ordinary-note experiment and seed a real Ekubo test pool."""
from common import *
import hashlib

assert int(rpc('starknet_chainId',{}),16)==int.from_bytes(b'SN_SEPOLIA','big')
assert hashlib.sha256(Path(MANIFEST['prover']).read_bytes()).hexdigest()==MANIFEST['prover_sha256']
assert hashlib.sha256(Path(MANIFEST['verifier']).read_bytes()).hexdigest()==MANIFEST['verifier_sha256']
with (RUN/'results/deployment-build.log').open('w') as log:
 subprocess.run(['scarb','--release','build'],cwd=HERE/'cairo',env=ENV,stdout=log,stderr=subprocess.STDOUT,check=True)
classes={}
for contract in ['Pool','StatementAccount','NativeProofVerifier','E2EToken','MockSwapAdapter','EkuboAdapter']:
 artifact=HERE/'cairo/target/release'/f'pool_{contract}.contract_class.json'
 expected=subprocess.check_output(['/home/broody/.starkli/bin/starkli','class-hash',str(artifact)],text=True).strip()
 try:
  rpc('starknet_getClass',{'block_id':'latest','class_hash':expected})
  classes[contract]=expected;save(RUN/'results'/f'reused-class-{contract}.json',{'class_hash':expected,'already_declared':True});continue
 except RuntimeError as e:
  if 'Class hash not found' not in str(e):raise
 print('Declare',contract,flush=True)
 v=normal_tx('declare-'+contract,['declare','--contract-name',contract,*bounds(900_000_000 if contract=='Pool' else 600_000_000)])
 assert int(v['class_hash'],16)==int(expected,16)
 classes[contract]=v['class_hash']
save(RUN/'results/classes.json',classes)

def deploy(name,klass,data):
 salt=(int(MANIFEST['deployment_salt_base'],16)+int.from_bytes(('DEFI_'+name).encode(),'big'))%(2**251)
 v=normal_tx('deploy-'+name,['deploy','--class-hash',classes[klass],'--salt',hex(salt),'--constructor-calldata',
      *[hex(x) if isinstance(x,int) else x for x in data],*bounds(40_000_000)])
 return v['contract_address']

ekubo=json.loads((RUN/'ekubo.json').read_text())
pool=deploy('pool','Pool',[ACCOUNT,0])
statement=deploy('statement','StatementAccount',[pool])
verifier=deploy('verifier','NativeProofVerifier',[pool,statement,classes['StatementAccount'],4096])
token_a=deploy('token-a','E2EToken',[ACCOUNT,10**12,0])
token_b=deploy('token-b','E2EToken',[ACCOUNT,10**12,0])
mock=deploy('mock','MockSwapAdapter',[pool,ACCOUNT,950])
adapter=deploy('ekubo-adapter','EkuboAdapter',[pool,ekubo['router']['address']])
start=json.loads((RUN/'results/deploy-pool/receipt.json').read_text())['block_number']
key=sorted([int(token_a,16),int(token_b,16)])+[0,1000,0]
d={'pool':pool,'statement':statement,'statement_class':classes['StatementAccount'],'verifier':verifier,
   'token':token_a,'token_a':token_a,'token_b':token_b,'mock':mock,'adapter':adapter,
   'relayer':ACCOUNT,'start_block':start,'classes':classes,'ekubo':ekubo,'pool_key':key,
   'route':[0,1000,0,0],'protocol':'TEMPLAR_DEFI_POC1','ordinary_notes_only':True}
save(RUN/'deployment.json',d)
invoke('configure-verifier',pool,'set_verifier',[verifier])
invoke('approve-token-a',token_a,'approve',[pool,100000,0])
invoke('fund-mock-token-b',token_b,'transfer',[mock,100000,0])

def multicall(name,calls):
 path=RUN/(name+'.toml')
 rows=[]
 for address,method,data in calls:
  rows.append('[[call]]\ncall_type = "invoke"\ncontract_address = '+json.dumps(address)+'\nfunction = '+json.dumps(method)+'\ninputs = '+json.dumps([hex(x) if isinstance(x,int) else x for x in data]))
 path.write_text('\n\n'.join(rows)+'\n')
 return normal_tx(name,['multicall','run','--path',str(path),*bounds(120_000_000)])

# Both token transfers and LP mint happen atomically in the existing Positions contract.
positions=ekubo['positions']['address'];core=ekubo['core']['address']
multicall('seed-ekubo-liquidity',[
 (core,'initialize_pool',key+[0,0]),
 (token_a,'transfer',[positions,10**9,0]),
 (token_b,'transfer',[positions,10**9,0]),
 (positions,'mint_and_deposit_and_clear_both',key+[1000000,1,1000000,0,1]),
])
assert call(pool,'get_verifier')==[int(verifier,16)]
price=call(core,'get_pool_price',key)
save(RUN/'results/ekubo-initial-state.json',{'pool_key':key,'price':price,
    'core_balance_a':call(token_a,'balance_of',[core]),'core_balance_b':call(token_b,'balance_of',[core])})
save(RUN/'source-snapshot.json',{'source_hashes':{str(p.relative_to(HERE)):hashlib.sha256(p.read_bytes()).hexdigest()
 for p in sorted((HERE/'cairo/src').rglob('*.cairo'))},'classes':classes})
print('Deployment and real Ekubo liquidity ready.',flush=True)
