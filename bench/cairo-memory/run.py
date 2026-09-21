"""Read-only, resource-capped replay of local private witnesses. Never submits transactions.

Private calldata is sent only to the loopback prover. Its upstream RPC performs
public state reads. This harness exports measurements and ZK proofs, not witnesses.
"""
from pathlib import Path
from rpc_cache import start_cache
import argparse,base64,csv,hashlib,json,os,re,subprocess,threading,time,urllib.request
H=Path(__file__).resolve().parent; ROOT=H.parent.parent
E=json.loads((H/'environment.json').read_text()); W=Path(E['work'])
RPC='https://api.zan.top/public/starknet-sepolia/rpc/v0_10'
FIXTURES={
 'ordinary':('controlled-push-e2e','ordinary-payment'),
 'controlled':('controlled-push-e2e','controlled-payment'),
 '8-8-4':('native-counted-shapes','shape-8-8-4'),
 'return':('return-note-e2e','upstream-ekubo-swap'),
 'invalid-intent':('return-note-e2e','tampered-intent-statement'),
}
def rpc(method,params,url=RPC,timeout=45):
 req=urllib.request.Request(url,json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':params}).encode(),{'Content-Type':'application/json'})
 with urllib.request.urlopen(req,timeout=timeout) as r:out=json.load(r)
 if 'error' in out:raise RuntimeError(json.dumps(out['error']))
 return out['result']
def save(path,value):path.write_text(json.dumps(value,indent=2)+'\n')
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def main():
 ap=argparse.ArgumentParser(description=__doc__)
 ap.add_argument('--variant',choices=['stock','baseline','cached','staged','staged-release'],required=True)
 ap.add_argument('--fixture',choices=FIXTURES,default='ordinary')
 ap.add_argument('--cap',type=int,default=16);ap.add_argument('--threads',type=int,default=4)
 ap.add_argument('--requests',type=int,default=1);ap.add_argument('--name',required=True)
 ap.add_argument('--native-allocator',action='store_true',help='Diagnostic glibc arena/trim tuning; not portable to WASM');ap.add_argument('--trace-spans',action='store_true');ap.add_argument('--block',type=int);ap.add_argument('--no-coefficients',action='store_true')
 ap.add_argument('--keep-cairo-trees',action='store_true',help='Disable Cairo commitment recomputation for an in-build baseline')
 a=ap.parse_args(); assert re.fullmatch('[a-zA-Z0-9_-]+',a.name)
 out=H/'results'/a.name;out.mkdir(exist_ok=False)
 package,case=FIXTURES[a.fixture]
 run=Path(json.loads((ROOT/'bench'/package/'run-location.json').read_text())['runtime'])
 src=run/'cases'/case
 params=json.loads((src/'private-request.json').read_text())
 cache_server,read_rpc=start_cache(W/'public-rpc-cache',RPC)
 block=rpc('starknet_getBlockWithTxHashes',{'block_id':{'block_number':a.block} if a.block else 'latest'},read_rpc)
 save(out/'base-block.json',{k:v for k,v in block.items() if k!='transactions'})
 params['block_id']={'block_number':block['block_number']}
 expected=json.loads((src/'public-response.json').read_text()) if (src/'public-response.json').exists() else None
 assert expected is not None or a.fixture=='invalid-intent'
 binary=Path(E['stock_prover']) if a.variant=='stock' else Path(E['baseline_prover']) if a.variant=='baseline' else W/'bin'/('low-memory-prover' if a.variant=='staged-release' else 'profiled-prover')
 summary={'variant':a.variant,'fixture':a.fixture,'cap_gib':a.cap,'rayon_threads':a.threads,'cache_cairo_coefficients':not a.no_coefficients,'recompute_cairo_commitments':a.variant.startswith('staged') and not a.keep_cairo_trees,'cpu_cores':4,'trace_spans':a.trace_spans,'native_allocator_tuning':a.native_allocator,'base_block':block['block_number'],'binary_sha256':sha(binary),'verifier_sha256':sha(E['verifier']),'private_request_sha256':hashlib.sha256(json.dumps(params,sort_keys=True).encode()).hexdigest(),'public_rpc_cache':True,'scope':'native replay on larger host; no settlement, browser or physical-desktop qualification','requests':[]}
 save(out/'summary.json',summary)
 unit='templar-memory-'+a.name+'-'+str(time.time_ns());port=31461;local=f'http://127.0.0.1:{port}'
 env={'RPC_URL':read_rpc,'CHAIN_ID':'SN_SEPOLIA','PROVER_IP':'127.0.0.1','PROVER_PORT':str(port),'MAX_CONCURRENT_REQUESTS':'1','MAX_QUEUED_REQUESTS':'0','COMPILED_CLASS_CACHE_SIZE':'16','PREFETCH_STATE':'false','RAYON_NUM_THREADS':str(a.threads),'TOKIO_WORKER_THREADS':str(a.threads),'RUST_LOG':'warn,starknet_transaction_prover=info,privacy_prove=info,stwo_cairo_prover=info,circuit_prover=info','PATH':'/usr/bin:/home/broody/.cargo/bin:/bin','TEMPLAR_CAIRO_COEFFICIENTS':'0' if a.no_coefficients else '1','TEMPLAR_LOW_MEMORY':'1' if (a.variant.startswith('staged') or a.variant=='baseline') else '0','TEMPLAR_MEMORY_PROFILE':str(out/'heap.csv')}
 env['TEMPLAR_RECOMPUTE_CAIRO_COMMITMENTS']='0' if a.keep_cairo_trees else '1'
 if a.native_allocator:env.update(MALLOC_ARENA_MAX='1',MALLOC_TRIM_THRESHOLD_='131072')
 if a.trace_spans:env.update(TEMPLAR_TRACE_SPANS='1',RUST_LOG=env['RUST_LOG']+',stwo=info')
 cmd=['systemd-run','--user','--wait','--pipe','--unit='+unit,'-p','WorkingDirectory='+E['sequencer_original'],'-p',f'MemoryMax={a.cap}G','-p','MemorySwapMax=0','-p','CPUQuota=400%','-p','CPUAffinity=0 1 2 3','-p','RuntimeMaxSec=600']+['--setenv='+k+'='+v for k,v in env.items()]+['/usr/bin/time','-v',str(binary)]
 samples=[];stop=threading.Event();thread=None;start=time.perf_counter();cg=None
 with (out/'prover.log').open('w') as log:
  process=subprocess.Popen(cmd,stdout=log,stderr=subprocess.STDOUT)
  try:
   for _ in range(100):
    cgp=subprocess.check_output(['systemctl','--user','show',unit,'-p','ControlGroup','--value'],text=True).strip()
    if cgp:cg=Path('/sys/fs/cgroup')/cgp.lstrip('/');break
    if process.poll() is not None:raise RuntimeError('Service failed to start')
    time.sleep(.05)
   assert cg is not None
   def sample():
    while not stop.is_set():
     p={'unix_ms':time.time_ns()//1_000_000,'elapsed_seconds':time.perf_counter()-start}
     for name in ['memory.current','memory.peak','memory.swap.current','memory.events','memory.stat','cpu.stat']:
      try:p[name]=(cg/name).read_text().strip()
      except OSError:pass
     try:
      for pid in (cg/'cgroup.procs').read_text().split():
       proc=Path('/proc')/pid
       if (proc/'exe').resolve() == binary.resolve():
        for line in (proc/'status').read_text().splitlines():
         if line.startswith(('VmRSS:','VmHWM:','VmSwap:')):p[line.split(':')[0]+'_KiB']=int(line.split()[1])
     except OSError:pass
     samples.append(p);stop.wait(.025)
   thread=threading.Thread(target=sample);thread.start()
   for _ in range(160):
    try:rpc('starknet_specVersion',{},local,1);break
    except Exception:
     if process.poll() is not None:raise RuntimeError('Prover startup failed')
     time.sleep(.1)
   else:raise RuntimeError('Startup timeout')
   summary['startup_seconds']=time.perf_counter()-start
   for i in range(a.requests):
    started=time.perf_counter();started_ms=time.time_ns()//1_000_000
    result=rpc('starknet_proveTransaction',params,local,300)
    record={'request_seconds':time.perf_counter()-started,'start_unix_ms':started_ms,'end_unix_ms':time.time_ns()//1_000_000}
    assert expected is not None,'Invalid witness unexpectedly proved'
    assert result['l2_to_l1_messages']==expected['l2_to_l1_messages'],'Public statement changed'
    assert result['proof_facts'][0]==expected['proof_facts'][0],'Proof version changed'
    assert result['proof_facts'][2]==expected['proof_facts'][2],'Verifier program changed'
    assert len(result['proof_facts'])==len(expected['proof_facts']),'Proof-fact layout changed'
    assert int(result['proof_facts'][8],16)==int(expected['proof_facts'][8],16),'Proven message digest changed'
    folder=out/f'proof-{i}';folder.mkdir();proof=base64.b64decode(result['proof'])
    (folder/'proof.bin').write_bytes(proof);(folder/'proof-facts.txt').write_text(','.join(result['proof_facts']))
    save(folder/'public-messages.json',result['l2_to_l1_messages'])
    with (folder/'verification.log').open('w') as vlog:
     v=subprocess.run([E['verifier'],str(folder)],stdout=vlog,stderr=subprocess.STDOUT,timeout=60)
    assert v.returncode==0,'Independent verification failed'
    record.update(proof_bytes=len(proof),proof_sha256=hashlib.sha256(proof).hexdigest(),public_binding_matches=True,verification_and_three_mutation_rejections=True)
    summary['requests'].append(record);save(out/'summary.json',summary)
    print(json.dumps({'name':a.name,'request':i,**record}),flush=True)
   summary['status']='PASS'
  except Exception as exc:
   summary['error']=str(exc);summary['status']='REJECTED' if a.fixture=='invalid-intent' and 'BINDING' in str(exc) else 'FAILED'
  finally:
   time.sleep(.15);stop.set()
   if thread:thread.join()
   save(out/'resources.json',samples)
   props=subprocess.run(['systemctl','--user','show',unit,'-p','MemoryPeak,MemorySwapPeak,MemoryMax,MemorySwapMax,CPUAffinity,CPUUsageNSec,Result'],capture_output=True,text=True)
   (out/'cgroup.txt').write_text(props.stdout)
   summary['cgroup_peak_gib']=max((int(p.get('memory.peak',0)) for p in samples),default=0)/2**30
   summary['peak_rss_gib']=max((p.get('VmHWM_KiB',0) for p in samples),default=0)/2**20 or None
   summary['swap_peak_bytes']=max((int(p.get('memory.swap.current',0)) for p in samples),default=0)
   summary['oom_kill']=max((int(dict(x.split() for x in p.get('memory.events','').splitlines()).get('oom_kill',0)) for p in samples),default=0)
   if (out/'heap.csv').exists():
    with (out/'heap.csv').open() as h:rows=list(csv.DictReader(h))
    summary['peak_requested_gib']=max((int(r['peak_requested_bytes']) for r in rows),default=0)/2**30
    if rows:summary['final_live_requested_gib']=int(rows[-1]['live_requested_bytes'])/2**30
   save(out/'summary.json',summary)
   subprocess.run(['systemctl','--user','stop',unit],capture_output=True)
   process.wait(timeout=20)
   cache_server.shutdown();cache_server.server_close()
 print(json.dumps(summary,indent=2),flush=True)
 if summary['status']=='FAILED':raise SystemExit(1)
if __name__=='__main__':main()
