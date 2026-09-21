"""Cold recovery with two explicitly trusted RPC providers, pinned to one block.

This verifies payload hashes and reconstructed roots against contract state;
it is not a consensus light client or a cryptographic state-proof verifier.
No seed, note opening, or viewing secret is sent to either provider.
"""
from common import *
from protocol import VERSION,CHAIN,Event,ciphertext_hash,FullView,Tree
from recovery import Archive,Receipt,TrustedCheckpoint,RecoveryError,recover
from encoding import parse_publication
import time

SECONDARY='https://api.cartridge.gg/x/starknet/sepolia/rpc/v0_10'

def read_at(url,address,method,data,block):
    return [int(x,16) for x in rpc('starknet_call',{'block_id':block,'request':{
        'contract_address':address,'entry_point_selector':selector(method),
        'calldata':[hex(x) if isinstance(x,int) else x for x in data]}},url=url)]

def event_pages(deploy,block):
    events=[];token=None;seen=set();pages=0
    while True:
        query={'from_block':{'block_number':deploy['start_block']},'to_block':block,
               'address':deploy['pool'],'keys':[[selector('NotePublished')]],'chunk_size':2}
        if token is not None: query['continuation_token']=token
        page=rpc('starknet_getEvents',{'filter':query});pages+=1
        events.extend(page['events']);token=page.get('continuation_token')
        if not token: return events,pages
        if token in seen: raise RecoveryError('repeated event continuation token')
        seen.add(token)

def canonical_checkpoint(deploy,view,*,minimum_block=0):
    start=time.perf_counter()
    for url in [RPC,SECONDARY]:
        assert int(rpc('starknet_chainId',{},url=url),16)==CHAIN
    block=rpc('starknet_getBlockWithTxHashes',{'block_id':'latest'})
    assert block['status'] in ['ACCEPTED_ON_L2','ACCEPTED_ON_L1']
    height,block_hash=block['block_number'],block['block_hash']
    if height<minimum_block: raise RecoveryError('checkpoint older than required block')
    bid={'block_hash':block_hash}
    confirm=rpc('starknet_getBlockWithTxHashes',{'block_id':{'block_number':height}},url=SECONDARY)
    if confirm['block_hash']!=block_hash: raise RecoveryError('RPC providers disagree on canonical block')
    for url in [RPC,SECONDARY]:
        klass=rpc('starknet_getClassHashAt',{'block_id':bid,'contract_address':deploy['pool']},url=url)
        if int(klass,16)!=int(deploy['classes']['Pool'],16): raise RecoveryError('unexpected pool class')
    def agreed(method,data=()):
        with ThreadPoolExecutor(max_workers=2) as executor:
            values=list(executor.map(lambda url:read_at(url,deploy['pool'],method,data,bid),[RPC,SECONDARY]))
        if values[0]!=values[1]: raise RecoveryError('RPC providers disagree on '+method)
        return values[0]
    root=agreed('get_root')[0];count=agreed('get_leaf_count')[0]
    raw,pages=event_pages(deploy,bid)
    # The RPC event list is untrusted discovery. Integrity and completeness are
    # checked against independently read immutable commitments and digests.
    indexed={};raw_by_index={}
    for e in raw:
        if int(e['from_address'],16)!=int(deploy['pool'],16): raise RecoveryError('wrong event source')
        if not deploy['start_block']<=e['block_number']<=height: raise RecoveryError('event outside snapshot')
        if [int(x,16) for x in e['keys']]!=[int(selector('NotePublished'),16)]: raise RecoveryError('event keys')
        event=parse_publication([int(x,16) for x in e['data']])
        if event.index in indexed and indexed[event.index]!=event: raise RecoveryError('conflicting duplicate event')
        if event.index>=count: raise RecoveryError('unexpected event index')
        indexed[event.index]=event;raw_by_index[event.index]=e
    # Query every funded position: omissions remain visible even if both event
    # and its metadata were dropped by an archive. Small-pool pathfinding only.
    def manifest_entry(index):
        return Receipt(agreed('get_node',[0,index])[0],agreed('get_delivery_digest',[index])[0])
    with ThreadPoolExecutor(max_workers=4) as executor: manifest=tuple(executor.map(manifest_entry,range(count)))
    archive=Archive(block_hash,tuple(indexed[i] for i in sorted(indexed)))
    anchor='two trusted RPC providers agree on block/class/state; no consensus or state-proof verification'
    checkpoint=TrustedCheckpoint(VERSION,CHAIN,int(deploy['pool'],16),height,block_hash,root,count,manifest,frozenset(),anchor)
    # Validate complete tree and every payload before using decrypted note data.
    preliminary=recover(view,archive,checkpoint,minimum_block=minimum_block)
    spent=set()
    if isinstance(view,FullView):
        def status(item):
            index,note=item;nf=view.nullifier(note,index);value=agreed('get_nullifier_spent',[nf])
            if value not in [[0],[1]]: raise RecoveryError('invalid spent flag')
            return nf,bool(value[0])
        with ThreadPoolExecutor(max_workers=4) as executor:
            for nf,used in executor.map(status,preliminary.notes.items()):
                if used: spent.add(nf)
        checkpoint=replace(checkpoint,spent_nullifiers=frozenset(spent))
    # Recheck canonical identity after synchronization, detecting a mid-scan reorg.
    for url in [RPC,SECONDARY]:
        current=rpc('starknet_getBlockWithTxHashes',{'block_id':{'block_number':height}},url=url)
        if current['block_hash']!=block_hash: raise RecoveryError('canonical block changed during recovery')
    report=recover(view,archive,checkpoint,minimum_block=minimum_block)
    metadata={'seconds':time.perf_counter()-start,'event_pages':pages,'event_count':len(raw),
              'unique_payloads':len(indexed),'ciphertext_bytes':304*len(indexed),'leaf_count':count,
              'providers':[RPC,SECONDARY],'block_number':height,'block_hash':block_hash,
              'anchor':anchor,'privacy_limit':'RPC providers see requested leaf positions and candidate nullifiers',
              'pool_class':deploy['classes']['Pool'],'raw_events':raw}
    return report,archive,checkpoint,metadata

from dataclasses import replace
