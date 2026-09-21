"""Read-only final chain/source checks and local-validation evidence."""
from common import *
import hashlib

summary=json.loads((RUN/'results/summary.json').read_text());assert summary['status']=='PASS'
d=summary['deployment'];snapshot=json.loads((RUN/'source-snapshot.json').read_text())
for name,digest in snapshot['source_hashes'].items():
 assert hashlib.sha256((HERE/name).read_bytes()).hexdigest()==digest,name
assert hashlib.sha256((HERE/'cairo/Scarb.lock').read_bytes()).hexdigest()==snapshot['scarb_lock_sha256']
raw=subprocess.check_output(['scarb','metadata','--format-version','1'],cwd=HERE/'cairo',env=ENV,text=True)
metadata=json.loads(raw[raw.index('{'):])
sources={}
for package in metadata['packages']:
 if package['name'] in ['ekubo_swap_anonymizer','vesu_lending_anonymizer']:
  assert d['upstream_revision'] in package['source'],package['source']
  name=package['name'];source=Path(package['manifest_path']).parent/'src'/(name+'.cairo')
  original=subprocess.check_output(['git','-C',str(HERE.parents[2]/'starknet-privacy'),
      'show',d['upstream_revision']+':packages/'+name+'/src/'+name+'.cairo'])
  assert source.read_bytes()==original,'Upstream adapter source modified'
  sources[name]={'revision':d['upstream_revision'],'sha256':hashlib.sha256(original).hexdigest(),'unchanged':True}
assert len(sources)==2
save(RUN/'results/upstream-source-check.json',sources)
block=rpc('starknet_getBlockWithTxHashes',{'block_id':'latest'});bid={'block_hash':block['block_hash']}
assert call(d['pool'],'get_verifier',block=bid)==[int(d['verifier'],16)]
assert call(d['pool'],'get_leaf_count',block=bid)==[5]
for name in ['pool','statement','verifier','adapter']:
 expected={'pool':'Pool','statement':'StatementAccount','verifier':'NativeProofVerifier','adapter':'EkuboSwapAnonymizer'}[name]
 assert int(rpc('starknet_getClassHashAt',{'block_id':bid,'contract_address':d[name]}),16)==int(d['classes'][expected],16)
for name in ['core','router','positions']:
 assert int(rpc('starknet_getClassHashAt',{'block_id':bid,'contract_address':d['ekubo'][name]['address']}),16)==int(d['ekubo'][name]['class_hash'],16)
for token,expected in [('token_a',4000),('token_b',summary['return_amount'])]:
 assert call(d[token],'balance_of',[d['pool']],block=bid)==[expected,0]
 assert call(d[token],'balance_of',[d['adapter']],block=bid)==[0,0]
save(RUN/'results/final-chain-check.json',{'passed':True,'block_number':block['block_number'],
 'block_hash':block['block_hash'],'leaf_count':5,'source_snapshot_unchanged':True,
 'classes_match':True,'pool_funding_reconciles':True,'adapter_balances_zero':True})
print('Final chain, funding and source checks passed.')
