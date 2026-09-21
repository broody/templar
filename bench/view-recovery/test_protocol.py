import unittest
from dataclasses import replace
from concurrent.futures import ThreadPoolExecutor
from nacl.exceptions import CryptoError
from nacl.public import PublicKey, SealedBox
from protocol import *


class PushReceiving(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bob_seed = hashlib.sha256(b"PUBLIC TEST FIXTURE Bob").digest()
        cls.bob = Wallet.restore(cls.bob_seed)
        cls.alice = Wallet.restore(hashlib.sha256(b"PUBLIC TEST FIXTURE Alice").digest())
        cls.note, cls.event = send(cls.bob.address, TOKEN, 600)
        cls.event = replace(cls.event, index=0)

    def test_address_only_send_and_seed_restore(self):
        restored = Wallet.restore(self.bob_seed)
        note = restored.view.receive(self.event)
        self.assertEqual(note, self.note)
        self.assertEqual(note.nullifier(restored.spend_key, 0), self.note.nullifier(self.bob.spend_key, 0))

    def test_sender_cannot_spend(self):
        with self.assertRaisesRegex(ValueError, "not the owner"):
            self.note.nullifier(self.alice.spend_key, 0)

    def test_incoming_view_can_read_but_key_cannot_spend(self):
        note = self.bob.view.receive(self.event)
        attempted_key = int.from_bytes(self.bob.view.decryption_key, "big") % P
        with self.assertRaisesRegex(ValueError, "not the owner"):
            note.nullifier(attempted_key, 0)

    def test_wrong_wallet_cannot_decrypt(self):
        with self.assertRaises(CryptoError):
            self.alice.view.receive(self.event)

    def test_concurrent_senders_need_no_recipient_counter(self):
        with ThreadPoolExecutor(max_workers=4) as executor:
            deliveries = list(executor.map(lambda _: send(self.bob.address, TOKEN, 10), range(12)))
        self.assertEqual(len({n.commitment for n, _ in deliveries}), 12)
        self.assertEqual(len({n.nullifier(self.bob.spend_key, i) for i, (n, _) in enumerate(deliveries)}), 12)
        self.assertEqual(len(self.bob.view.scan([replace(e, index=i) for i, (_, e) in enumerate(deliveries)])), 12)

    def test_ciphertext_is_fixed_size_and_randomized(self):
        n, e = send(self.bob.address, TOKEN, 600, rho=self.note.rho)
        self.assertEqual(n.commitment, self.note.commitment)
        self.assertNotEqual(e.ciphertext, self.event.ciphertext)
        self.assertEqual(len(e.ciphertext), 304)

    def test_tampering_rejects_even_with_recomputed_digest(self):
        data = bytearray(self.event.ciphertext)
        data[-1] ^= 1
        e = replace(self.event, ciphertext=bytes(data), digest=ciphertext_hash(bytes(data)))
        with self.assertRaises(CryptoError):
            self.bob.view.receive(e)

    def test_wrong_committed_digest_rejects(self):
        with self.assertRaisesRegex(ValueError, "delivery digest"):
            self.bob.view.receive(replace(self.event, digest=(self.event.digest+1) % P))

    def test_ciphertext_substitution_rejects(self):
        _, other = send(self.bob.address, TOKEN, 7)
        with self.assertRaisesRegex(ValueError, "wrong commitment"):
            self.bob.view.receive(replace(other, commitment=self.event.commitment))

    def test_other_chain_and_pool_reject(self):
        for address in [replace(self.bob.address, chain=CHAIN+1), replace(self.bob.address, pool=POOL+1)]:
            _, e = send(address, TOKEN, 600)
            with self.assertRaisesRegex(ValueError, "context"):
                self.bob.view.receive(e)

    def test_encryption_key_substitution_does_not_change_owner(self):
        wrong = replace(self.bob.address, encryption_key=self.alice.address.encryption_key)
        n, e = send(wrong, TOKEN, 12)
        with self.assertRaisesRegex(ValueError, "not the owner"):
            n.nullifier(self.alice.spend_key, 0)
        self.assertEqual(self.bob.view.scan([e]), {})  # Availability lost; address authentication matters.

    def test_duplicate_deliveries_count_once(self):
        _, repeated = send(self.bob.address, TOKEN, 600, rho=self.note.rho)
        repeated = replace(repeated, index=0)
        self.assertEqual(len(self.bob.view.scan([self.event, self.event, repeated])), 1)

    def test_same_commitment_at_two_funded_positions_remains_spendable(self):
        second = replace(self.event, index=1)
        self.assertEqual(len(self.bob.view.scan([self.event, second])), 2)
        self.assertNotEqual(self.note.nullifier(self.bob.spend_key, 0), self.note.nullifier(self.bob.spend_key, 1))

    def test_unconfirmed_delivery_is_not_credited(self):
        self.assertEqual(self.bob.view.scan([replace(self.event, index=None)]), {})

    def test_same_randomness_different_amount_has_distinct_nullifier(self):
        other = replace(self.note, amount=601)
        self.assertNotEqual(self.note.nullifier(self.bob.spend_key, 0), other.nullifier(self.bob.spend_key, 0))

    def test_missing_data_is_not_recoverable_from_seed(self):
        self.assertEqual(Wallet.restore(self.bob_seed).view.scan([]), {})

    def test_malformed_plaintext_does_not_poison_scan(self):
        payload = bytearray(self.note.encode())
        payload[-1] = 1
        data = SealedBox(PublicKey(self.bob.address.encryption_key)).encrypt(bytes(payload))
        malformed = Event(self.note.commitment, data, ciphertext_hash(data), 1)
        self.assertEqual(len(self.bob.view.scan([malformed, self.event])), 1)

    def test_noncanonical_fields_and_amounts_reject(self):
        for field, value in [('rho', 0), ('receiver', P), ('amount', 2**128), ('amount', 0)]:
            with self.assertRaises(ValueError):
                replace(self.note, **{field: value}).encode()

    def test_view_cannot_determine_spent_status(self):
        # The same public delivery decrypts after spend. Incoming view is not a full viewing key.
        self.assertEqual(self.bob.view.receive(self.event), self.note)
        self.assertFalse(hasattr(self.bob.view, 'spend_key'))

    def test_local_settlement_recomputes_delivery_digest_and_rejects_replay(self):
        ledger = Ledger()
        index = ledger.fund(self.note, self.event)
        outgoing = send(self.alice.address, TOKEN, 550)
        case = make_case([(self.note,self.bob.spend_key,index)], [outgoing], [(0x9876,50)], ledger.tree)
        # Onchain emission must use its own computed digest, never untrusted metadata.
        ledger.apply(case, [replace(outgoing[1],digest=0)])
        self.assertEqual(self.alice.view.receive(ledger.events[-1]).amount, 550)
        before = (ledger.tree.root(), ledger.spent.copy(), len(ledger.events))
        with self.assertRaisesRegex(ValueError, 'replay'):
            ledger.apply(case, [outgoing[1]])
        self.assertEqual(before, (ledger.tree.root(), ledger.spent, len(ledger.events)))

    def test_local_settlement_missing_delivery_is_atomic(self):
        ledger = Ledger()
        index = ledger.fund(self.note, self.event)
        outgoing = send(self.alice.address, TOKEN, 600)
        case = make_case([(self.note,self.bob.spend_key,index)], [outgoing], [], ledger.tree)
        before = (ledger.tree.root(), ledger.spent.copy(), len(ledger.events))
        with self.assertRaisesRegex(ValueError, 'delivery'):
            ledger.apply(case, [])
        self.assertEqual(before, (ledger.tree.root(), ledger.spent, len(ledger.events)))


if __name__ == '__main__':
    unittest.main(verbosity=2)
