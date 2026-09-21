"""Test the privacy boundary of the benchmark's public-read cache."""
import json,tempfile,threading,unittest,urllib.request
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from rpc_cache import start_cache

class CacheTests(unittest.TestCase):
 def setUp(self):
  self.reads=[];reads=self.reads
  class Upstream(BaseHTTPRequestHandler):
   def do_POST(self):
    v=json.loads(self.rfile.read(int(self.headers['Content-Length'])));reads.append(v)
    payload=json.dumps({'jsonrpc':'2.0','id':v['id'],'result':{'count':len(reads)}}).encode()
    self.send_response(200);self.end_headers();self.wfile.write(payload)
   def log_message(self,*args):pass
  self.upstream=ThreadingHTTPServer(('127.0.0.1',0),Upstream)
  threading.Thread(target=self.upstream.serve_forever,daemon=True).start()
  self.tmp=tempfile.TemporaryDirectory()
  self.server,self.url=start_cache(self.tmp.name,f'http://127.0.0.1:{self.upstream.server_port}')
 def tearDown(self):
  for server in [self.server,self.upstream]:server.shutdown();server.server_close()
  self.tmp.cleanup()
 def call(self,method,params,id=1):
  req=urllib.request.Request(self.url,json.dumps({'jsonrpc':'2.0','id':id,'method':method,'params':params}).encode(),{'Content-Type':'application/json'})
  with urllib.request.urlopen(req) as r:return json.load(r)
 def test_private_or_mutating_requests_never_forwarded(self):
  for method in ['starknet_proveTransaction','starknet_call','starknet_addInvokeTransaction']:
   self.assertIn('error',self.call(method,{'sensitive':'TEST PRIVATE SENTINEL'}))
  self.assertEqual(self.reads,[])
  self.assertEqual(list(Path(self.tmp.name).iterdir()),[])
 def test_pinned_reads_cached_and_response_ids_updated(self):
  p={'block_id':{'block_number':123},'contract_address':'0x1'}
  first=self.call('starknet_getClassAt',p,1);second=self.call('starknet_getClassAt',p,19)
  self.assertEqual(first['result'],second['result']);self.assertEqual(second['id'],19)
  self.assertEqual(len(self.reads),1)
 def test_latest_not_cached(self):
  first=self.call('starknet_getBlockWithTxHashes',{'block_id':'latest'})
  second=self.call('starknet_getBlockWithTxHashes',{'block_id':'latest'})
  self.assertNotEqual(first['result'],second['result']);self.assertEqual(len(self.reads),2)
if __name__=='__main__':unittest.main()
