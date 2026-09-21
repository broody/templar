"""Recovery against an explicitly trusted canonical checkpoint.

This models authenticated node/receipt/state data. It does NOT authenticate RPC
responses or implement a Starknet light client. The archive may be untrusted.
"""
from dataclasses import dataclass
from protocol import Address, Event, FullView, IncomingView, Tree, VERSION, ciphertext_hash, felt


class RecoveryError(ValueError):
    pass


@dataclass(frozen=True)
class Receipt:
    commitment: int
    delivery_digest: int


@dataclass(frozen=True)
class TrustedCheckpoint:
    version: int
    chain: int
    pool: int
    block_number: int
    block_hash: str
    root: int
    leaf_count: int
    receipts: tuple[Receipt, ...]
    spent_nullifiers: frozenset[int]
    anchor: str = 'trusted local test fixture; not an authenticated live RPC snapshot'

    @classmethod
    def from_model(cls, ledger, address, block_number, block_hash):
        """TEST ONLY: substitutes local model state for a verified chain anchor."""
        return cls(VERSION,address.chain,address.pool,block_number,block_hash,
                   ledger.tree.root(),ledger.tree.count,
                   tuple(Receipt(e.commitment,e.digest) for e in ledger.events),
                   frozenset(ledger.spent))

    def validate(self, address, minimum_block):
        if (self.version,self.chain,self.pool) != (VERSION,address.chain,address.pool):
            raise RecoveryError('wrong checkpoint context')
        if type(self.block_number) is not int or self.block_number < minimum_block:
            raise RecoveryError('checkpoint older than required block')
        if type(self.leaf_count) is not int or not 0 <= self.leaf_count <= 2**32:
            raise RecoveryError('checkpoint leaf count')
        if len(self.receipts) != self.leaf_count:
            raise RecoveryError('incomplete checkpoint receipt manifest')
        if not isinstance(self.block_hash,str) or not self.block_hash:
            raise RecoveryError('checkpoint block identity')
        felt(self.root)
        for r in self.receipts:
            felt(r.commitment,True)
            felt(r.delivery_digest,True)
        for nf in self.spent_nullifiers:
            felt(nf,True)


@dataclass(frozen=True)
class Archive:
    block_hash: str
    events: tuple[Event, ...]


@dataclass
class RecoveryReport:
    checkpoint: TrustedCheckpoint
    notes: dict
    tree: Tree
    missing_indices: tuple[int, ...]
    received_totals: dict[int, int]
    spent_indices: tuple[int, ...] | None
    known_unspent: dict[int, int] | None

    @property
    def history_complete(self):
        return not self.missing_indices

    @property
    def balances(self):
        # An incoming-only key, or incomplete history, must never produce an
        # apparently complete wallet balance (including a false zero).
        return self.known_unspent if self.history_complete else None

    def summary(self):
        def tokens(v):
            return None if v is None else {hex(k):n for k,n in v.items()}
        return {'as_of_block':self.checkpoint.block_number,'block_hash':self.checkpoint.block_hash,
                'anchor':self.checkpoint.anchor,
                'history_complete':self.history_complete,'missing_payload_indices':list(self.missing_indices),
                'received_indices':sorted(self.notes),'received_totals':tokens(self.received_totals),
                'spent_indices':None if self.spent_indices is None else list(self.spent_indices),
                'known_unspent':tokens(self.known_unspent),'balances':tokens(self.balances),
                'balance_scope':'recoverable protocol-published notes for this receiving address'}


def recover(view, archive, checkpoint, *, minimum_block=0):
    if not isinstance(view,(IncomingView,FullView)):
        raise TypeError('expected incoming or full viewing capability')
    view.validate()
    checkpoint.validate(view.address,minimum_block)
    if archive.block_hash != checkpoint.block_hash:
        raise RecoveryError('archive is not from the pinned canonical block')

    # The tree root authenticates commitments/positions, not ciphertext bytes.
    # Delivery digests additionally come from trusted transaction receipts.
    tree = Tree()
    for receipt in checkpoint.receipts:
        tree.insert(receipt.commitment)
    if tree.root() != checkpoint.root:
        raise RecoveryError('commitment manifest does not match tree root')

    indexed = {}
    for event in archive.events:
        if type(event.index) is not int or not 0 <= event.index < checkpoint.leaf_count:
            raise RecoveryError('unexpected event index')
        old = indexed.get(event.index)
        if old is not None and old != event:
            raise RecoveryError('conflicting duplicate event')
        receipt = checkpoint.receipts[event.index]
        if (event.commitment,event.digest) != (receipt.commitment,receipt.delivery_digest):
            raise RecoveryError('event differs from authenticated receipt')
        try:
            digest = ciphertext_hash(event.ciphertext)
        except (ValueError,TypeError) as e:
            raise RecoveryError('damaged ciphertext') from e
        if digest != receipt.delivery_digest:
            raise RecoveryError('ciphertext differs from authenticated receipt')
        indexed[event.index] = event

    missing = tuple(i for i in range(checkpoint.leaf_count) if i not in indexed)
    notes = view.scan(indexed.values())
    received_totals = {}
    for note in notes.values():
        received_totals[note.token] = received_totals.get(note.token,0)+note.amount
    spent, unspent = None, None
    if isinstance(view,FullView):
        spent, unspent = [], {token:0 for token in received_totals}
        for index,note in notes.items():
            if view.nullifier(note,index) in checkpoint.spent_nullifiers:
                spent.append(index)
            else:
                unspent[note.token] += note.amount
        spent = tuple(sorted(spent))
    return RecoveryReport(checkpoint,notes,tree,missing,received_totals,spent,unspent)
