import copy
import hashlib
import json
import unittest
from dataclasses import replace

from protocol import *
from recovery import Archive, Receipt, RecoveryError, TrustedCheckpoint, recover


def scenario():
    seed = hashlib.sha256(b'PUBLIC recovery/viewing fixture Bob').digest()
    bob = Wallet.restore(seed)
    carol = Wallet.restore(hashlib.sha256(b'PUBLIC recovery/viewing fixture Carol').digest())
    ledger = Ledger()
    initial = send(bob.address,TOKEN,100)
    index = ledger.fund(*initial)
    before = TrustedCheckpoint.from_model(ledger,bob.address,100,'fixture-before')
    archive_before = Archive(before.block_hash,tuple(ledger.events))
    to_carol, change = send(carol.address,TOKEN,60), send(bob.address,TOKEN,40)
    case = make_case([(initial[0],bob.spend_key,index)],[to_carol,change],[],ledger.tree)
    ledger.apply(case,[to_carol[1],change[1]])
    after = TrustedCheckpoint.from_model(ledger,bob.address,101,'fixture-after')
    archive_after = Archive(after.block_hash,tuple(ledger.events))
    return seed,bob,carol,ledger,before,archive_before,after,archive_after


class ViewingAndRecovery(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        (cls.seed,cls.bob,cls.carol,cls.ledger,cls.before,cls.archive_before,
         cls.after,cls.archive_after) = scenario()
        cls.export = cls.bob.full_view.export()

    def viewer(self):
        return FullView.load(json.loads(json.dumps(self.export)),expected_address=self.bob.address)

    def test_seed_restore_matches_full_view_balance(self):
        restored = Wallet.restore(self.seed)
        full = recover(self.viewer(),self.archive_after,self.after)
        owner = recover(restored.full_view,self.archive_after,self.after)
        self.assertEqual(full.balances,{TOKEN:40})
        self.assertEqual(owner.balances,full.balances)
        self.assertEqual(full.spent_indices,(0,))

    def test_incoming_receipts_are_not_a_balance(self):
        report = recover(self.bob.view,self.archive_after,self.after)
        self.assertEqual(report.received_totals,{TOKEN:140})
        self.assertIsNone(report.balances)
        self.assertIsNone(report.spent_indices)

    def test_viewing_export_contains_no_spending_secret_or_seed(self):
        values = json.dumps(self.export)
        self.assertNotIn(str(self.bob.spend_key),values)
        self.assertNotIn(self.seed.hex(),values)
        self.assertFalse(hasattr(self.viewer(),'spend_key'))

    def test_export_cannot_choose_a_different_nullifier_key(self):
        data = copy.deepcopy(self.export)
        data['nullifier_secret'] = (data['nullifier_secret']+1) % P
        with self.assertRaisesRegex(ValueError,'does not match address'):
            FullView.load(data,expected_address=self.bob.address)

    def test_export_cannot_choose_a_different_authority(self):
        data = copy.deepcopy(self.export)
        data['authority'] = (data['authority']+1) % P
        with self.assertRaisesRegex(ValueError,'does not match address'):
            FullView.load(data,expected_address=self.bob.address)

    def test_export_cannot_choose_a_different_decryption_key(self):
        data = copy.deepcopy(self.export)
        data['incoming_secret'] = self.carol.view.decryption_key.hex()
        with self.assertRaisesRegex(ValueError,'decryption key'):
            FullView.load(data,expected_address=self.bob.address)

    def test_other_wallet_export_does_not_impersonate_bob(self):
        with self.assertRaisesRegex(ValueError,'unexpected receiving address'):
            FullView.load(self.carol.full_view.export(),expected_address=self.bob.address)

    def test_full_view_nullifier_agrees_with_spender(self):
        report = recover(self.viewer(),self.archive_after,self.after)
        for index,note in report.notes.items():
            self.assertEqual(self.viewer().nullifier(note,index),note.nullifier(self.bob.spend_key,index))

    def test_viewing_secrets_cannot_substitute_for_spending_secret(self):
        note = self.bob.view.receive(self.archive_after.events[2])
        for key in [self.viewer().authority,self.viewer().nullifier_secret,
                    int.from_bytes(self.bob.view.decryption_key,'big') % P]:
            with self.assertRaisesRegex(ValueError,'not the owner'):
                note.nullifier(key,2)

    def test_recovered_owner_can_build_a_spend(self):
        restored = Wallet.restore(self.seed)
        report = recover(restored.full_view,self.archive_after,self.after)
        case = make_case([(report.notes[2],restored.spend_key,2)],[],[(0x9876,40)],report.tree)
        validate_case(case)

    def test_missing_payload_never_reports_a_complete_balance(self):
        archive = replace(self.archive_after,events=self.archive_after.events[:2])
        report = recover(self.viewer(),archive,self.after)
        self.assertFalse(report.history_complete)
        self.assertEqual(report.missing_indices,(2,))
        self.assertEqual(report.known_unspent,{TOKEN:0})
        self.assertIsNone(report.balances)  # Not a false complete zero.

    def test_missing_another_wallets_payload_is_still_incomplete(self):
        # Until decrypted we cannot know whose missing ciphertext it was.
        archive = replace(self.archive_after,events=(self.archive_after.events[0],self.archive_after.events[2]))
        report = recover(self.viewer(),archive,self.after)
        self.assertEqual(report.known_unspent,{TOKEN:40})
        self.assertIsNone(report.balances)

    def test_empty_archive_is_not_zero_balance(self):
        report = recover(self.viewer(),Archive(self.after.block_hash,()),self.after)
        self.assertEqual(report.missing_indices,(0,1,2))
        self.assertIsNone(report.balances)

    def test_retry_other_archive_recovers_the_missing_payment(self):
        broken = recover(self.viewer(),Archive(self.after.block_hash,()),self.after)
        fixed = recover(self.viewer(),self.archive_after,self.after)
        self.assertFalse(broken.history_complete)
        self.assertEqual(fixed.balances,{TOKEN:40})

    def test_modified_ciphertext_rejected_even_when_archive_rehashes_it(self):
        events = list(self.archive_after.events)
        data = bytearray(events[2].ciphertext);data[-1] ^= 1
        events[2] = replace(events[2],ciphertext=bytes(data),digest=ciphertext_hash(bytes(data)))
        with self.assertRaisesRegex(RecoveryError,'authenticated receipt'):
            recover(self.viewer(),replace(self.archive_after,events=tuple(events)),self.after)

    def test_corruption_without_rehashed_metadata_rejected(self):
        events = list(self.archive_after.events)
        data = bytearray(events[2].ciphertext);data[-1] ^= 1
        events[2] = replace(events[2],ciphertext=bytes(data))
        with self.assertRaisesRegex(RecoveryError,'ciphertext differs'):
            recover(self.viewer(),replace(self.archive_after,events=tuple(events)),self.after)

    def test_truncated_ciphertext_rejected(self):
        events = list(self.archive_after.events)
        events[2] = replace(events[2],ciphertext=b'')
        with self.assertRaisesRegex(RecoveryError,'damaged ciphertext'):
            recover(self.viewer(),replace(self.archive_after,events=tuple(events)),self.after)

    def test_receipt_or_leaf_omission_cannot_match_checkpoint(self):
        with self.assertRaisesRegex(RecoveryError,'incomplete checkpoint'):
            recover(self.viewer(),self.archive_after,replace(self.after,receipts=self.after.receipts[:2]))
        receipts = list(self.after.receipts)
        receipts[0] = replace(receipts[0],commitment=(receipts[0].commitment+1)%P)
        with self.assertRaisesRegex(RecoveryError,'tree root'):
            recover(self.viewer(),self.archive_after,replace(self.after,receipts=tuple(receipts)))

    def test_duplicate_and_out_of_order_event_delivery(self):
        archive = replace(self.archive_after,events=tuple(reversed(self.archive_after.events))+self.archive_after.events)
        self.assertEqual(recover(self.viewer(),archive,self.after).balances,{TOKEN:40})

    def test_conflicting_duplicate_rejected(self):
        altered = replace(self.archive_after.events[2],digest=1)
        archive = replace(self.archive_after,events=self.archive_after.events+(altered,))
        with self.assertRaisesRegex(RecoveryError,'conflicting duplicate'):
            recover(self.viewer(),archive,self.after)

    def test_extra_or_unconfirmed_event_rejected(self):
        for index in [None,3,-1]:
            archive = replace(self.archive_after,events=self.archive_after.events+(replace(self.archive_after.events[0],index=index),))
            with self.assertRaisesRegex(RecoveryError,'unexpected event index'):
                recover(self.viewer(),archive,self.after)

    def test_stale_snapshot_not_accepted_as_current(self):
        with self.assertRaisesRegex(RecoveryError,'pinned canonical block'):
            recover(self.viewer(),self.archive_before,self.after)
        with self.assertRaisesRegex(RecoveryError,'older than required'):
            recover(self.viewer(),self.archive_before,self.before,minimum_block=101)

    def test_reorg_rebuild_discards_orphaned_spend_and_change(self):
        first = recover(self.viewer(),self.archive_after,self.after)
        self.assertEqual(first.balances,{TOKEN:40})
        # New canonical branch has no spend; a fresh scan must not retain old state.
        fork = replace(self.before,block_number=102,block_hash='fixture-reorg')
        archive = replace(self.archive_before,block_hash=fork.block_hash)
        next_report = recover(self.viewer(),archive,fork)
        self.assertEqual(next_report.balances,{TOKEN:100})
        self.assertEqual(next_report.spent_indices,())

    def test_fully_spent_wallet_reports_true_zero_with_complete_history(self):
        _,bob,_,ledger,_,_,_,archive = scenario()
        change = bob.view.receive(archive.events[2])
        ledger.apply(make_case([(change,bob.spend_key,2)],[],[(0x9876,40)],ledger.tree),[])
        checkpoint = TrustedCheckpoint.from_model(ledger,bob.address,102,'fixture-fully-spent')
        report = recover(bob.full_view,Archive(checkpoint.block_hash,tuple(ledger.events)),checkpoint)
        self.assertTrue(report.history_complete)
        self.assertEqual(report.balances,{TOKEN:0})

    def test_exported_keys_are_not_reused_on_other_networks_or_pools(self):
        for chain,pool in [(CHAIN+1,POOL),(CHAIN,POOL+1)]:
            other = Wallet.restore(self.seed,chain,pool)
            self.assertNotEqual(other.address.receiver,self.bob.address.receiver)
            self.assertNotEqual(other.view.decryption_key,self.bob.view.decryption_key)
            self.assertNotEqual(other.full_view.nullifier_secret,self.bob.full_view.nullifier_secret)
            _,event = send(other.address,TOKEN,42)
            with self.assertRaises(CryptoError):
                SealedBox(PrivateKey(self.bob.view.decryption_key)).decrypt(event.ciphertext)

    def test_wrong_network_or_pool_rejected(self):
        for cp in [replace(self.after,chain=CHAIN+1),replace(self.after,pool=POOL+1)]:
            with self.assertRaisesRegex(RecoveryError,'checkpoint context'):
                recover(self.viewer(),self.archive_after,cp)

    def test_old_valid_checkpoint_is_only_a_historical_balance(self):
        report = recover(self.viewer(),self.archive_before,self.before)
        self.assertEqual(report.balances,{TOKEN:100})
        self.assertEqual(report.summary()['as_of_block'],100)


if __name__ == '__main__':
    unittest.main(verbosity=2)
