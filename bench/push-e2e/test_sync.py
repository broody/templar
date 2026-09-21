import unittest
from unittest.mock import patch
from dataclasses import replace
from protocol import *
from recovery import RecoveryError
from encoding import chunks,unchunks,parse_publication,encode_spend
from test_recovery import scenario
import sync

class Encoding(unittest.TestCase):
    def test_all_bytes_roundtrip(self):
        for data in [bytes(304),bytes([255])*304,bytes(range(256))+bytes(range(48))]:
            self.assertEqual(unchunks(chunks(data)),data)
    def test_noncanonical_words_rejected(self):
        for words in [[0]*9,[0]*11,[2**248]+[0]*9,[0]*9+[2**200],[-1]+[0]*9]:
            with self.assertRaises(ValueError): unchunks(words)
    def test_publication_length_and_index_checked(self):
        for data in [[0,1,1,9]+[0]*10,[2**32,1,1,10]+[0]*10,[0,1,1,10]+[0]*9]:
            with self.assertRaises(ValueError): parse_publication(data)

class ChainRecovery(unittest.TestCase):
    def setUp(self):
        _,self.bob,_,self.ledger,_,_,self.cp,self.archive=scenario()
        self.deploy={'pool':hex(POOL),'classes':{'Pool':'0x99'},'start_block':100}
        self.block={'block_number':101,'block_hash':'0xabc','status':'ACCEPTED_ON_L2'}
        self.events=[{'from_address':hex(POOL),'block_number':101,'block_hash':'0xabc',
                     'transaction_hash':'0x1','keys':['0x123'],
                     'data':[hex(x) for x in [e.index,e.commitment,e.digest,10,*chunks(e.ciphertext)]]}
                    for e in self.archive.events]
        self.other_root=False;self.class_hash='0x99';self.fork=False;self.seen_blocks=0
    def rpc(self,method,params,url=None):
        if method=='starknet_chainId':return hex(CHAIN)
        if method=='starknet_getBlockWithTxHashes':
            self.seen_blocks+=1
            return dict(self.block,block_hash='0xdef') if self.fork and self.seen_blocks>2 else self.block
        if method=='starknet_getClassHashAt':return self.class_hash
        raise AssertionError(method)
    def read(self,url,address,method,data,block):
        self.assertEqual(block,{'block_hash':'0xabc'})
        if method=='get_root':return [self.cp.root+int(self.other_root and url==sync.SECONDARY)]
        if method=='get_leaf_count':return [self.cp.leaf_count]
        if method=='get_node':return [self.cp.receipts[data[1]].commitment]
        if method=='get_delivery_digest':return [self.cp.receipts[data[0]].delivery_digest]
        if method=='get_nullifier_spent':return [int(data[0] in self.cp.spent_nullifiers)]
        raise AssertionError(method)
    def run_sync(self,minimum=0):
        with patch.object(sync,'rpc',self.rpc),patch.object(sync,'read_at',self.read),\
             patch.object(sync,'selector',return_value='0x123'),\
             patch.object(sync,'event_pages',return_value=(self.events,2)):
            return sync.canonical_checkpoint(self.deploy,self.bob.full_view,minimum_block=minimum)
    def test_live_adapter_uses_pinned_state_for_balance(self):
        report,_,_,meta=self.run_sync()
        self.assertEqual(report.balances,{TOKEN:40})
        self.assertEqual(meta['leaf_count'],3)
    def test_missing_payload_stays_incomplete(self):
        self.events.pop()
        self.assertIsNone(self.run_sync()[0].balances)
    def test_archive_cannot_rehash_tampered_payload(self):
        e=self.archive.events[2];data=bytearray(e.ciphertext);data[-1]^=1
        digest=ciphertext_hash(bytes(data));self.events[2]['data']=[hex(x) for x in [2,e.commitment,digest,10,*chunks(bytes(data))]]
        with self.assertRaisesRegex(RecoveryError,'authenticated receipt'):self.run_sync()
    def test_provider_disagreement_rejected(self):
        self.other_root=True
        with self.assertRaisesRegex(RecoveryError,'disagree'):self.run_sync()
    def test_unexpected_class_rejected(self):
        self.class_hash='0x98'
        with self.assertRaisesRegex(RecoveryError,'pool class'):self.run_sync()
    def test_reorg_mid_scan_rejected(self):
        self.fork=True
        with self.assertRaisesRegex(RecoveryError,'changed during recovery'):self.run_sync()
    def test_stale_checkpoint_rejected(self):
        with self.assertRaisesRegex(RecoveryError,'older than required'):self.run_sync(102)
    def test_wrong_event_source_rejected(self):
        self.events[0]['from_address']='0x999'
        with self.assertRaisesRegex(RecoveryError,'event source'):self.run_sync()

if __name__=='__main__': unittest.main(verbosity=2)
