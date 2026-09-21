"""Read-only failure drills using the actual Sepolia checkpoint and ciphertexts."""
from common import *
from protocol import Address,FullView,Wallet,CHAIN,ciphertext_hash
from recovery import recover,RecoveryError
from sync import canonical_checkpoint,read_at,SECONDARY
from dataclasses import replace

d=json.loads((RUN/'deployment.json').read_text())
a=json.loads((RUN/'backups/bob/address.json').read_text())
address=Address(a['chain'],a['pool'],a['receiver'],bytes.fromhex(a['encryption_key']))
view=FullView.load(json.loads((RUN/'backups/bob/full-view.json').read_text()),expected_address=address)
report,archive,checkpoint,metadata=canonical_checkpoint(d,view)
assert report.history_complete
incoming=recover(view.incoming,archive,checkpoint)
assert incoming.balances is None and incoming.received_totals=={int(d['token'],16):1160}
missing=recover(view,replace(archive,events=archive.events[:-1]),checkpoint)
assert missing.balances is None and not missing.history_complete
retried=recover(view,archive,checkpoint)
assert retried.balances==report.balances
events=list(archive.events);data=bytearray(events[-1].ciphertext);data[-1]^=1
events[-1]=replace(events[-1],ciphertext=bytes(data),digest=ciphertext_hash(bytes(data)))
def rejection(candidate,minimum=0):
    try:recover(view,candidate,checkpoint,minimum_block=minimum)
    except RecoveryError as e:return str(e)
    raise AssertionError('invalid recovery accepted')
tampered=rejection(replace(archive,events=tuple(events)))
stale=rejection(archive,checkpoint.block_number+1)
reordered=recover(view,replace(archive,events=tuple(reversed(archive.events))+archive.events),checkpoint)
assert reordered.balances==report.balances
reconciled={}
for name,expected in [('alice',400),('bob',0),('carol',250),('dave',500)]:
    seed=bytes.fromhex((RUN/'backups'/name/'seed.txt').read_text().strip())
    capability=Wallet.restore(seed,CHAIN,int(d['pool'],16)).full_view
    notes=capability.scan(archive.events);spent=set()
    for index,note in notes.items():
        nf=capability.nullifier(note,index)
        values=[read_at(url,d['pool'],'get_nullifier_spent',[nf],{'block_hash':checkpoint.block_hash}) for url in [RPC,SECONDARY]]
        assert values[0]==values[1] and values[0] in [[0],[1]]
        if values[0]==[1]:spent.add(nf)
    recovered=recover(capability,archive,replace(checkpoint,spent_nullifiers=frozenset(spent)))
    assert recovered.balances=={int(d['token'],16):expected}
    reconciled[name]=expected
for url in [RPC,SECONDARY]:
    canonical=rpc('starknet_getBlockWithTxHashes',{'block_id':{'block_number':checkpoint.block_number}},url=url)
    assert canonical['block_hash']==checkpoint.block_hash
assert sum(reconciled.values())==1150
save(RUN/'results/recovery-drills.json',{
    'scope':'read-only mutation of actual downloaded Sepolia history; no chain reorganization performed',
    'block_number':checkpoint.block_number,'block_hash':checkpoint.block_hash,
    'complete':report.summary(),'incoming_only':incoming.summary(),
    'missing_payload':missing.summary(),'retry':retried.summary(),
    'tampered_with_recomputed_digest_rejected':tampered,'checkpoint_below_requested_height_rejected':stale,
    'reordered_and_duplicate_deliveries_deduplicated':True,
    'reconciled_private_balances':reconciled,'total_private_balance_matches_pool':1150})
print('Live-history recovery failure drills passed.')
