"""Run the pinned, unmodified privacy service under a per-case resource limit."""
from common import *
import base64,hashlib,re

def prove_case(case,private,public,deploy,expect_error=None):
 out=RUN/'cases'/case;out.mkdir(parents=True,exist_ok=True)
 if (out/'benchmark.json').exists():return json.loads((out/'benchmark.json').read_text())
 unit='templar-push-e2e-'+case;port=31458
 cmd=['systemd-run','--user','--wait','--pipe','--unit='+unit,'-p','WorkingDirectory='+MANIFEST['upstream'],'-p','MemoryMax=16G','-p','MemorySwapMax=0','-p','CPUQuota=400%','-p','CPUAffinity=0 1 2 3','-p','RuntimeMaxSec=600']
 variables={'RPC_URL':RPC,'CHAIN_ID':'SN_SEPOLIA','PROVER_IP':'127.0.0.1','PROVER_PORT':str(port),'MAX_CONCURRENT_REQUESTS':'1','MAX_QUEUED_REQUESTS':'0','COMPILED_CLASS_CACHE_SIZE':'16','PREFETCH_STATE':'false','RAYON_NUM_THREADS':'4','TOKIO_WORKER_THREADS':'4','RUST_LOG':'warn,starknet_transaction_prover=info,privacy_prove=info','PATH':'/usr/bin:/home/broody/.cargo/bin:/bin'}
 cmd += ['--setenv='+k+'='+v for k,v in variables.items()];cmd += ['/usr/bin/time','-v',MANIFEST['prover']]
 samples=[];done=threading.Event();thread=None;start=time.perf_counter()
 with (out/'prover.log').open('w') as log:
  process=subprocess.Popen(cmd,stdout=log,stderr=subprocess.STDOUT)
  try:
   for _ in range(40):
    try:rpc('starknet_specVersion',{},url=f'http://127.0.0.1:{port}',timeout=1);break
    except Exception:
     if process.poll() is not None:raise RuntimeError('Prover startup failed: '+(out/'prover.log').read_text()[-1800:])
     time.sleep(.25)
   else:raise RuntimeError('Prover not ready')
   startup=time.perf_counter()-start
   block=rpc('starknet_getBlockWithTxHashes',{'block_id':'latest'});assert block['starknet_version']=='0.14.4';save(out/'base-block.json',{k:v for k,v in block.items() if k!='transactions'})
   tx={'type':'INVOKE','version':'0x3','sender_address':deploy['statement'],'calldata':[hex(x) for x in [len(private),*private]],'signature':[],'nonce':'0x0','resource_bounds':{g:{'max_amount':hex(100_000_000) if g=='l2_gas' else '0x0','max_price_per_unit':'0x0'} for g in ['l1_gas','l2_gas','l1_data_gas']},'tip':'0x0','paymaster_data':[],'account_deployment_data':[],'nonce_data_availability_mode':'L1','fee_data_availability_mode':'L1'}
   params={'block_id':{'block_number':block['block_number']},'transaction':tx};save(out/'private-request.json',params)
   cg=Path('/sys/fs/cgroup')/subprocess.check_output(['systemctl','--user','show',unit,'-p','ControlGroup','--value'],text=True).strip().lstrip('/')
   start=time.perf_counter()
   def sample():
    while not done.is_set():
     p={'elapsed_seconds':time.perf_counter()-start}
     for f in ['memory.current','memory.peak','memory.swap.current','memory.events','cpu.stat']:
      try:p[f]=(cg/f).read_text().strip()
      except OSError:pass
     try:
      for pid in (cg/'cgroup.procs').read_text().split():
       proc=Path('/proc')/pid
       if (proc/'comm').read_text().startswith('starknet_transa'):
        for line in (proc/'status').read_text().splitlines():
         if line.startswith(('VmRSS:','VmHWM:','VmSwap:')):p[line.split(':')[0]+'_KiB']=int(line.split()[1])
     except OSError:pass
     samples.append(p);done.wait(.1)
   thread=threading.Thread(target=sample);thread.start()
   try:result=rpc('starknet_proveTransaction',params,url=f'http://127.0.0.1:{port}',timeout=300)
   except RuntimeError as e:
    if not expect_error:raise
    assert expect_error in str(e),str(e);v={'case':case,'expected_error':expect_error,'rejected':True,'elapsed_seconds':time.perf_counter()-start};save(out/'benchmark.json',v);save(out/'error.json',{'error':str(e)});return v
   assert expect_error is None,'invalid witness unexpectedly proved'
   seconds=time.perf_counter()-start;save(out/'public-response.json',result)
   proof=base64.b64decode(result['proof']);facts=result['proof_facts'];assert int(facts[0],16)==int.from_bytes(b'PROOF1','big');(out/'proof.bin').write_bytes(proof);(out/'proof.base64').write_text(result['proof']);(out/'proof-facts.txt').write_text(','.join(facts))
   done.set();thread.join()
   with (out/'local-verification.log').open('w') as f:vproc=subprocess.run([MANIFEST['verifier'],str(out)],stdout=f,stderr=subprocess.STDOUT)
   assert vproc.returncode==0,(out/'local-verification.log').read_text()
   import reference as ref
   message=result['l2_to_l1_messages'];assert len(message)==1 and [int(x,16) for x in message[0]['payload']]==[int(deploy['statement_class'],16),*public]
   assert int(message[0]['from_address'],16)==int(deploy['statement'],16) and int(message[0]['to_address'],16)==0
   digest=ref.hash_span([int(deploy['statement'],16),0,9,int(deploy['statement_class'],16),*public]);assert digest==int(facts[8],16)
   clean=re.sub(r'\x1b\[[0-9;]*m','',(out/'prover.log').read_text());v={'case':case,'startup_seconds':startup,'request_seconds':seconds,'proving_seconds':int(re.search(r'prove_duration_ms=(\d+)',clean)[1])/1000,'virtual_os_seconds':int(re.search(r'os_duration_ms=(\d+)',clean)[1])/1000,'proof_bytes':len(proof),'proof_sha256':hashlib.sha256(proof).hexdigest(),'peak_rss_gib':max(p.get('VmHWM_KiB',0) for p in samples)/1048576,'swap_peak_bytes':max(int(p.get('memory.swap.current',0)) for p in samples),'local_verification_passed':True,'public_binding_matches':True,'public_values':[hex(x) for x in public],'base_block':block['block_number'],'memory_cap_gib':16,'cores':4}
   save(out/'benchmark.json',v);print(json.dumps(v),flush=True);return v
  finally:
   done.set()
   if thread:thread.join()
   save(out/'resources.json',samples)
   props=subprocess.run(['systemctl','--user','show',unit,'-p','MemoryPeak,MemorySwapPeak,MemoryMax,MemorySwapMax,CPUAffinity,CPUUsageNSec,Result'],capture_output=True,text=True);(out/'cgroup.txt').write_text(props.stdout)
   subprocess.run(['systemctl','--user','stop',unit],capture_output=True);process.wait(timeout=20)
