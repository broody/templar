"""Loopback cache of public Starknet reads for reproducible block-pinned replays.
Never accepts proving requests, calls, signatures, or transaction submission.
"""
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
import hashlib,json,os,threading,urllib.request

def start_cache(directory,upstream):
 directory=Path(directory);directory.mkdir(parents=True,exist_ok=True,mode=0o700)
 class Handler(BaseHTTPRequestHandler):
  def do_POST(self):
   v={}
   try:
    v=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
    method=v['method'];params=v.get('params',{})
    assert method.startswith('starknet_get') or method in ['starknet_specVersion','starknet_chainId','starknet_blockNumber'],'Not a permitted public read'
    key=json.dumps({'method':method,'params':params},sort_keys=True)
    cacheable='latest' not in key and 'pending' not in key and method!='starknet_blockNumber'
    path=directory/(hashlib.sha256(key.encode()).hexdigest()+'.json')
    if cacheable and path.exists():result=json.loads(path.read_text())['response']
    else:
     req=urllib.request.Request(upstream,json.dumps(v).encode(),{'Content-Type':'application/json'})
     with urllib.request.urlopen(req,timeout=45) as r:result=json.load(r)
     if cacheable and 'result' in result:
      temp=path.with_suffix('.'+str(threading.get_ident())+'.tmp')
      temp.write_text(json.dumps({'request':json.loads(key),'response':result}));os.replace(temp,path)
    result['id']=v['id'];payload=json.dumps(result).encode();self.send_response(200)
   except Exception as e:
    payload=json.dumps({'jsonrpc':'2.0','id':v.get('id') if isinstance(v,dict) else None,'error':{'code':-32000,'message':str(e)}}).encode();self.send_response(200)
   self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(payload)));self.end_headers();self.wfile.write(payload)
  def log_message(self,*args):pass
 server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
 thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
 return server,f'http://127.0.0.1:{server.server_port}'
