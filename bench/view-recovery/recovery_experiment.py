"""Readable recovery scenarios using public fixture keys and a local ledger."""
import hashlib
import json
from dataclasses import replace

from protocol import FullView, Ledger, ROOT, TOKEN, Wallet, ciphertext_hash, make_case, send
from recovery import Archive, RecoveryError, TrustedCheckpoint, recover


def run():
    seed = hashlib.sha256(b'PUBLIC recovery demo Bob').digest()
    bob = Wallet.restore(seed)
    carol = Wallet.restore(hashlib.sha256(b'PUBLIC recovery demo Carol').digest())
    ledger = Ledger()
    note,event = send(bob.address,TOKEN,100)
    index = ledger.fund(note,event)
    before = TrustedCheckpoint.from_model(ledger,bob.address,100,'public-fixture-before')
    archive_before = Archive(before.block_hash,tuple(ledger.events))
    exported = bob.full_view.export()
    expected_address = bob.address
    payment,change = send(carol.address,TOKEN,60),send(bob.address,TOKEN,40)
    ledger.apply(make_case([(note,bob.spend_key,index)],[payment,change],[],ledger.tree),
                 [payment[1],change[1]])
    after = TrustedCheckpoint.from_model(ledger,bob.address,101,'public-fixture-after')
    archive = Archive(after.block_hash,tuple(ledger.events))
    incoming = recover(bob.view,archive,after)
    del bob, note, event, payment, change  # Discard owner wallet and note cache.
    view = FullView.load(exported,expected_address=expected_address)
    watched = recover(view,archive,after)
    restored = Wallet.restore(seed)
    owner = recover(restored.full_view,archive,after)
    assert incoming.received_totals == {TOKEN:140} and incoming.balances is None
    assert watched.balances == owner.balances == {TOKEN:40}
    incomplete = recover(view,replace(archive,events=archive.events[:2]),after)
    assert incomplete.known_unspent == {TOKEN:0} and incomplete.balances is None
    retried = recover(view,archive,after)
    assert retried.balances == {TOKEN:40}
    rejected = {}
    def must_reject(name,events,checkpoint,minimum_block=0):
        try:
            recover(view,events,checkpoint,minimum_block=minimum_block)
        except RecoveryError as e:
            rejected[name] = str(e)
        else:
            raise AssertionError(name+' accepted')
    must_reject('stale_archive',archive_before,after)
    must_reject('old_checkpoint_below_requested_height',archive_before,before,101)
    altered = bytearray(archive.events[2].ciphertext)
    altered[-1] ^= 1
    events = list(archive.events)
    events[2] = replace(events[2],ciphertext=bytes(altered),digest=ciphertext_hash(bytes(altered)))
    must_reject('modified_payload_with_self_consistent_digest',replace(archive,events=tuple(events)),after)
    fork = replace(before,block_number=102,block_hash='public-fixture-new-canonical-branch')
    reorg = recover(view,replace(archive_before,block_hash=fork.block_hash),fork)
    assert reorg.balances == {TOKEN:100}
    spend = make_case([(owner.notes[2],restored.spend_key,2)],[],[(0x9876,40)],owner.tree)
    ledger.apply(spend,[])
    final = TrustedCheckpoint.from_model(ledger,expected_address,102,'public-fixture-fully-spent')
    zero = recover(view,replace(archive,block_hash=final.block_hash),final)
    assert zero.balances == {TOKEN:0} and zero.history_complete
    report = {'scope':'local fixture ledger and explicitly trusted checkpoints; no RPC authentication',
              'keys_are_public_test_fixtures':True,
              'incoming':incoming.summary(),'full_view':watched.summary(),'seed_restore':owner.summary(),
              'missing_change_payload':incomplete.summary(),'retry_with_complete_archive':retried.summary(),
              'rejected':rejected,'reorg_rebuilt':reorg.summary(),'actual_final_spend':zero.summary()}
    (ROOT/'results/recovery.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))


if __name__ == '__main__':
    run()
