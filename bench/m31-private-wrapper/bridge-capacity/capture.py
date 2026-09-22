"""Capture one authenticated local virtual-OS execution for repeatable capacity tests."""
from pathlib import Path
import argparse,hashlib,importlib.util,json,subprocess,sys,time
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
spec=importlib.util.spec_from_file_location('outer_helpers',HERE.parent/'run_server_outer.py');helpers=importlib.util.module_from_spec(spec);spec.loader.exec_module(helpers)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--fixture',type=Path,required=True);ap.add_argument('--request',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();a.output.mkdir(parents=True,exist_ok=False)
 fixture=a.fixture.resolve();request=a.request.resolve();out=a.output.resolve();port=helpers.free_port()
 binary=ROOT/'target/m31-private-wrapper/capacity-capture-build-v3/capture'
 command=['systemd-run','--user','--wait','--pipe','--unit=templar-capture-'+str(time.time_ns()),'-p','WorkingDirectory='+str(helpers.UPSTREAM),'-p','MemoryMax=16G','-p','MemorySwapMax=0','-p','CPUQuota=400%','-p','CPUAffinity=0 1 2 3','-p','RuntimeMaxSec=180','--setenv=RAYON_NUM_THREADS=4','--setenv=TOKIO_WORKER_THREADS=4','/usr/bin/time','-v',str(binary),f'http://127.0.0.1:{port}',str(request),str(out)]
 with (out/'fixture.log').open('w') as log:
  p=subprocess.Popen([sys.executable,str(HERE.parent.parent/'m31-append/fixture_server.py'),'--fixture',str(fixture),'--sha256',sha(fixture),'--port',str(port),'--log',str(out/'rpc.jsonl')],stdout=log,stderr=subprocess.STDOUT)
  try:
   helpers.ready(p,port)
   start=time.monotonic()
   with (out/'capture.log').open('w') as stream:r=subprocess.run(command,stdout=stream,stderr=subprocess.STDOUT)
   result={'command':command,'fixture_sha256':sha(fixture),'request_sha256':sha(request),'binary_sha256':sha(binary),'exit_code':r.returncode,'elapsed_seconds':time.monotonic()-start}
   (out/'execution.json').write_text(json.dumps(result,indent=2)+'\n')
   assert r.returncode==0,(out/'capture.log').read_text()[-3000:]
   produced=json.loads((out/'capture.json').read_text())
   expected=json.loads((HERE.parent/'results/server-circuit/outer-input.json').read_text())['public_values']
   anchor=json.loads(fixture.read_text());msg=produced['l2_to_l1_messages'];assert len(msg)==1
   def number(v):return int(v,16) if isinstance(v,str) else int(v)
   assert [number(x) for x in msg[0]['payload']]==[number(anchor['authority']['statement_class']),*map(number,expected)]
   assert number(msg[0]['from_address'])==number(anchor['authority']['statement']) and number(msg[0]['to_address'])==0
   result.update(exact_message_verified=True,pie_sha256=sha(out/'os.pie.zip'));(out/'execution.json').write_text(json.dumps(result,indent=2)+'\n')
  finally:p.terminate();p.wait(timeout=10)
if __name__=='__main__':main()
