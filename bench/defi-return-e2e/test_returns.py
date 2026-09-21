"""Ordinary-note return format, ownership, recovery and authorization checks."""
import copy
import unittest
from dataclasses import replace
from protocol import *
from recovery import Archive, TrustedCheckpoint, Receipt, recover, RecoveryError


class Returns(unittest.TestCase):
    def setUp(self):
        self.seed=bytes(range(32)); self.wallet=Wallet.restore(self.seed)
        self.other=Wallet.restore(bytes(range(1,33)))
        self.inner,self.cipher=prepare_return(self.wallet.address,0x99,rho=123)

    def event(self,amount=77):
        cm=H([tag('DFI_NOTE_V1'),CHAIN,POOL,0x99,amount,0,0,self.inner])
        e=Event(cm,self.cipher,0,0,amount)
        return replace(e,digest=event_digest(e))

    def checkpoint(self,e,spent=()):
        tree=Tree();tree.insert(e.commitment)
        return TrustedCheckpoint(VERSION,CHAIN,POOL,10,'test-checkpoint',tree.root(),1,
            (Receipt(e.commitment,e.digest),),frozenset(spent))

    def test_actual_amount_can_change_after_receipt_preparation(self):
        self.assertEqual(self.wallet.view.receive(self.event(77)).amount,77)
        self.assertEqual(self.wallet.view.receive(self.event(83)).amount,83)

    def test_return_requires_settled_amount(self):
        with self.assertRaises(ValueError): self.wallet.view.receive(replace(self.event(),settled_amount=0))

    def test_wrong_amount_even_with_new_digest_cannot_match_commitment(self):
        e=replace(self.event(),settled_amount=78);e=replace(e,digest=event_digest(e))
        with self.assertRaises(ValueError): self.wallet.view.receive(e)

    def test_untrusted_archive_cannot_change_amount(self):
        e=self.event();bad=replace(e,settled_amount=78)
        with self.assertRaises(RecoveryError): recover(self.wallet.full_view,Archive('test-checkpoint',(bad,)),self.checkpoint(e))

    def test_wrong_receiver_cannot_decrypt_or_spend(self):
        e=self.event();self.assertEqual(self.other.view.scan([e]),{})
        n=self.wallet.view.receive(e)
        with self.assertRaises(ValueError):n.nullifier(self.other.spend_key,0)

    def test_fresh_seed_restore_viewing_and_respend(self):
        e=self.event();fresh=Wallet.restore(self.seed);cp=self.checkpoint(e)
        report=recover(fresh.full_view,Archive('test-checkpoint',(e,)),cp)
        self.assertEqual(report.balances,{0x99:77})
        incoming=recover(fresh.view,Archive('test-checkpoint',(e,)),cp)
        self.assertEqual(incoming.received_totals,{0x99:77});self.assertIsNone(incoming.balances)
        n=report.notes[0];case=make_case([(n,fresh.spend_key,0)],[],[(0x123,77)],report.tree)
        validate_case(case)
        cp_spent=self.checkpoint(e,[case['nullifiers'][0]])
        self.assertEqual(recover(fresh.full_view,Archive('test-checkpoint',(e,)),cp_spent).balances,{0x99:0})

    def test_missing_history_is_not_a_zero_balance(self):
        e=self.event();r=recover(self.wallet.full_view,Archive('test-checkpoint',()),self.checkpoint(e))
        self.assertFalse(r.history_complete);self.assertIsNone(r.balances)

    def test_normal_push_receipt_still_works(self):
        n,e=send(self.wallet.address,TOKEN,50,rho=111)
        self.assertEqual(self.wallet.view.receive(e),n)

    def test_intent_is_bound_by_ownership_statement(self):
        n,e=send(self.wallet.address,TOKEN,100,rho=456);tree=Tree();tree.insert(n.commitment)
        c=make_case([(n,self.wallet.spend_key,0)],[],[(0xaaa,100)],tree,intent=789)
        validate_case(c);bad=copy.deepcopy(c);bad['witness'][10]=790
        with self.assertRaisesRegex(ValueError,'binding'):validate_case(bad)

    def test_every_swap_field_changes_authorization(self):
        fields=dict(adapter=0xaaa,out_token=0x99,amount=100,minimum=70,expiry=1000,
                    inner=self.inner,policy=0,ciphertext=self.cipher,route=[42])
        base=swap_hash(CHAIN,POOL,TOKEN,0,**fields)
        for name in fields:
            v=dict(fields)
            v[name]=[43] if name=='route' else (bytes([self.cipher[0]^1])+self.cipher[1:] if name=='ciphertext' else v[name]+1)
            with self.subTest(field=name):self.assertNotEqual(base,swap_hash(CHAIN,POOL,TOKEN,0,**v))


if __name__=='__main__':unittest.main()
