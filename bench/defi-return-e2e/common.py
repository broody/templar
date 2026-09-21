"""Bounded Sepolia transport for the isolated PROOF1 integration test."""
from pathlib import Path
from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor
import json,os,subprocess,time,urllib.request,urllib.error,copy,threading
from http.server import ThreadingHTTPServer,BaseHTTPRequestHandler
HERE=Path(__file__).resolve().parent
RUN=Path(os.environ.get('TEMPLAR_DEFI_E2E_RUN') or json.loads((HERE/'run-location.json').read_text())['runtime'])
MANIFEST=json.loads((RUN/'manifest.json').read_text())
RPC='https://api.zan.top/public/starknet-sepolia/rpc/v0_10'
GATEWAY='https://alpha-sepolia.starknet.io/gateway/add_transaction'
ACCOUNT='0x54f2b25070d70d49f1c1f7c10ef2639889fdac15894d3fba1a03caf5603eca3'
SNCAST='/home/broody/.asdf/installs/starknet-foundry/0.63.0/bin/sncast'
ENV=os.environ.copy();ENV['PATH']='/home/broody/.asdf/installs/scarb/2.18.0/bin:/home/broody/.local/bin:'+ENV['PATH']

def save(path,value):
 path=Path(path);path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(value,indent=2)+'\n')
def rpc(method,params,url=RPC,timeout=45):
 req=urllib.request.Request(url,json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':params}).encode(),{'Content-Type':'application/json'})
 attempts=3 if method!='starknet_proveTransaction' else 1
 for attempt in range(attempts):
  try:
   with urllib.request.urlopen(req,timeout=min(timeout,15) if attempts>1 else timeout) as r:v=json.load(r)
   break
  except (urllib.error.URLError,TimeoutError):
   if attempt==attempts-1:raise
   time.sleep(1)
 if 'error' in v:raise RuntimeError(json.dumps(v['error']))
 return v['result']
@lru_cache(None)
def selector(name):return subprocess.check_output(['/home/broody/.starkli/bin/starkli','selector',name],text=True).strip()
def call(address,name,data=(),block='latest'):
 return [int(x,16) for x in rpc('starknet_call',{'block_id':block,'request':{'contract_address':hex(address) if isinstance(address,int) else address,'entry_point_selector':selector(name),'calldata':[hex(x) if isinstance(x,int) else x for x in data]}})]
def receipt(tx,path,expected='SUCCEEDED'):
 path=Path(path)
 if path.exists():v=json.loads(path.read_text())
 else:
  for _ in range(60):
   try:v=rpc('starknet_getTransactionReceipt',{'transaction_hash':tx})
   except RuntimeError as e:
    if 'Transaction hash not found' not in str(e):raise
    time.sleep(2);continue
   if v.get('finality_status') in ['ACCEPTED_ON_L2','ACCEPTED_ON_L1']:
    save(path,v);break
   time.sleep(2)
  else:raise RuntimeError(f'Receipt pending for {tx}; inspect before resubmitting')
 assert v['execution_status']==expected,(tx,v.get('execution_status'),v.get('revert_reason'))
 print(json.dumps({'tx':tx,'status':v['execution_status'],'block':v.get('block_number'),'fee_test_STRK':int(v['actual_fee']['amount'],16)/1e18,'revert_reason':v.get('revert_reason')}),flush=True)
 return v

def bounds(l2):
 return ['--l2-gas',str(l2),'--l2-gas-price','25000000000','--l1-gas','1','--l1-gas-price','200000000000000','--l1-data-gas','10000','--l1-data-gas-price','1000000000000']
def sncast(name,args,expected_error=False):
 out=RUN/'results'/name;out.mkdir(parents=True,exist_ok=True)
 cmd=[SNCAST,'--account','account-1','--accounts-file','/home/broody/.starknet_accounts/starknet_open_zeppelin_accounts.json','--json']+args
 with (out/'stdout.jsonl').open('w') as stdout,(out/'stderr.log').open('w') as stderr:p=subprocess.run(cmd,cwd=HERE/'cairo',env=ENV,stdout=stdout,stderr=stderr)
 lines=[]
 for line in (out/'stdout.jsonl').read_text().splitlines():
  try:lines.append(json.loads(line))
  except json.JSONDecodeError:pass
 if p.returncode and not expected_error:raise RuntimeError((out/'stderr.log').read_text()[-1800:]+'\n'+str(lines)[-1800:])
 return lines

def normal_tx(name,args):
 path=RUN/'results'/name/'response.json'
 if path.exists():v=json.loads(path.read_text())
 else:
  if (path.parent/'stdout.jsonl').exists():raise RuntimeError(f'Inspect incomplete prior transaction {name} before retry')
  rows=sncast(name,args+['--url',RPC]);v=next(x for x in rows if x.get('type')=='response');save(path,v)
 receipt(v['transaction_hash'],path.parent/'receipt.json');return v

def invoke(name,address,method,data=(),l2=40_000_000):
 return normal_tx(name,['invoke','--contract-address',hex(address) if isinstance(address,int) else address,'--function',method,'--calldata',*[hex(x) if isinstance(x,int) else x for x in data],*bounds(l2)])

def proof_invoke(name,deploy,calldata,proof_dir,expected='SUCCEEDED',reason=None,method='apply_spend'):
 out=RUN/'results'/name;out.mkdir(parents=True,exist_ok=True);response_path=out/'gateway-response.json'
 if response_path.exists():response=json.loads(response_path.read_text())
 else:
  captured=out/'signed-request.json';tx_response=RUN/'results'/('capture-'+name)
  if captured.exists() or (tx_response/'stdout.jsonl').exists():raise RuntimeError(f'Inspect prior capture for {name}; no automatic retry')
  class Capture(BaseHTTPRequestHandler):
   def do_POST(self):
    body=self.rfile.read(int(self.headers['Content-Length']));v=json.loads(body)
    with (out/'rpc-methods.log').open('a') as trace:trace.write(v['method']+'\n')
    if v['method']=='starknet_addInvokeTransaction':
     save(captured,v);res={'jsonrpc':'2.0','id':v['id'],'error':{'code':-32603,'message':'Captured locally; not forwarded'}}
    else:
     assert v['method'].startswith(('starknet_get','starknet_spec','starknet_chain','starknet_block')) or v['method']=='starknet_call',v['method']
     res={'jsonrpc':'2.0','id':v['id'],'result':rpc(v['method'],v.get('params',{}))}
    payload=json.dumps(res).encode();self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(payload)));self.end_headers();self.wfile.write(payload)
   def log_message(self,*a):pass
  server=ThreadingHTTPServer(('127.0.0.1',0),Capture);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
  try:
   sncast('capture-'+name,['invoke','--url',f'http://127.0.0.1:{server.server_port}','--contract-address',deploy['pool'],'--function',method,'--calldata',*[hex(x) for x in calldata],'--proof-file',str(proof_dir/'proof.base64'),'--proof-facts-file',str(proof_dir/'proof-facts.txt'),*bounds(150_000_000)],expected_error=True)
  finally:server.shutdown();server.server_close();thread.join()
  tx=json.loads(captured.read_text())['params']['invoke_transaction'];assert tx['proof'] and tx['proof_facts'];assert tx['calldata'][-len(calldata):]==[hex(x) for x in calldata]
  assert int(tx['proof_facts'][0],16)==int.from_bytes(b'PROOF1','big')
  assert sum(int(x['max_amount'],16)*int(x['max_price_per_unit'],16) for x in tx['resource_bounds'].values())<4*10**18
  tx['type']='INVOKE_FUNCTION';tx['resource_bounds']={k.upper():v for k,v in tx['resource_bounds'].items()};tx['nonce_data_availability_mode']=0;tx['fee_data_availability_mode']=0
  save(out/'gateway-request.json',tx)
  req=urllib.request.Request(GATEWAY,json.dumps(tx).encode(),{'Content-Type':'application/json'})
  try:
   with urllib.request.urlopen(req,timeout=60) as r:response=json.load(r)
  except urllib.error.HTTPError as e:response=json.loads(e.read())
  save(response_path,response)
 assert response.get('code')=='TRANSACTION_RECEIVED',response
 v=receipt(response['transaction_hash'],out/'receipt.json',expected)
 if reason:assert reason in v.get('revert_reason',''),v.get('revert_reason')
 return v
