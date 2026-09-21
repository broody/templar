"""Experimental push-note model V2 with full viewing. Not audited or production.

No RPC, signing, or submission. The existing Poseidon/tree reference is reused;
Cairo executes the new statement independently. Encryption uses libsodium boxes.
"""
from dataclasses import dataclass, replace
import hashlib
import hmac
import importlib.util
from pathlib import Path
import secrets

from nacl.exceptions import CryptoError
from nacl.public import PrivateKey, PublicKey, SealedBox

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("felt_reference", ROOT.parent / "stwo-e2e/reference.py")
ref = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ref)
H, P, Tree = ref.hash_span, ref.P, ref.SparseTree
VERSION = int.from_bytes(b"TEMPLAR_PUSH_POC2", "big")
CHAIN, POOL, TOKEN = int.from_bytes(b"SN_SEPOLIA", "big"), 0x1234, 0x5678

def tag(s):
    return int.from_bytes(s.encode(), "big")

def felt(x, nonzero=False):
    if type(x) is not int or not (int(nonzero) <= x < P):
        raise ValueError("noncanonical felt")
    return x

def scalar():
    return secrets.randbelow(P - 1) + 1

def receiver_key(spend_key):
    return H([tag("PUSH_OWNER_V2"), authority_key(spend_key), nullifier_key(spend_key)])

def authority_key(spend_key):
    return felt(H([tag("PUSH_AUTH_V2"), felt(spend_key, True)]), True)

def nullifier_key(spend_key):
    return felt(H([tag("PUSH_NK_V2"), felt(spend_key, True)]), True)

@dataclass(frozen=True)
class Address:
    chain: int
    pool: int
    receiver: int
    encryption_key: bytes

    def validate(self):
        for x in [self.chain, self.pool, self.receiver]:
            felt(x, True)
        if len(self.encryption_key) != 32:
            raise ValueError("encryption key length")

@dataclass(frozen=True)
class Note:
    chain: int
    pool: int
    token: int
    amount: int
    receiver: int
    rho: int
    controller: int = 0
    policy: int = 0

    def validate(self):
        for x in [self.chain, self.pool, self.token, self.receiver, self.rho]:
            felt(x, True)
        if type(self.amount) is not int or not 0 < self.amount < 2**128:
            raise ValueError("amount range")
        if self.controller != 0 or self.policy != 0:
            raise ValueError("prototype supports ordinary notes only")

    @property
    def inner(self):
        self.validate()
        return H([tag("PUSH_INNER_V2"), self.receiver, self.rho])

    @property
    def commitment(self):
        return H([tag("PUSH_NOTE_V2"), self.chain, self.pool, self.token,
                  self.amount, self.controller, self.policy, self.inner])

    def nullifier(self, spend_key, leaf_index):
        if receiver_key(spend_key) != self.receiver:
            raise ValueError("not the owner")
        if type(leaf_index) is not int or not 0 <= leaf_index < 2**32:
            raise ValueError("leaf index")
        return H([tag("PUSH_NF_V2"), nullifier_key(spend_key), self.commitment, leaf_index])

    def encode(self):
        self.validate()
        # Fixed 256-byte plaintext: 4-byte version, seven 32-byte fields,
        # u128 amount, and twelve zero padding bytes. Canonical big endian.
        fields = [self.chain, self.pool, self.token, self.receiver, self.rho,
                  self.controller, self.policy]
        return (2).to_bytes(4, "big") + b"".join(x.to_bytes(32, "big") for x in fields) + self.amount.to_bytes(16, "big") + bytes(12)

    @classmethod
    def decode(cls, data):
        if len(data) != 256 or data[:4] != (2).to_bytes(4, "big") or data[-12:] != bytes(12):
            raise ValueError("plaintext encoding")
        v = [int.from_bytes(data[4+i*32:36+i*32], "big") for i in range(7)]
        n = cls(v[0], v[1], v[2], int.from_bytes(data[228:244], "big"), v[3], v[4], v[5], v[6])
        n.validate()
        return n

def ciphertext_hash(data):
    if len(data) != 304:
        raise ValueError("ciphertext length")
    # Length plus <=31-byte chunks is injective; no reduction of byte strings.
    return H([tag("PUSH_DELIVERY_V2"), len(data)] +
             [int.from_bytes(data[i:i+31], "big") for i in range(0, len(data), 31)])

@dataclass(frozen=True)
class Event:
    commitment: int
    ciphertext: bytes
    digest: int
    index: int | None = None

def send(address, token, amount, *, rho=None):
    """Sender receives only Address. It never receives Bob's private keys."""
    address.validate()
    n = Note(address.chain, address.pool, token, amount, address.receiver,
             scalar() if rho is None else rho)
    c = SealedBox(PublicKey(address.encryption_key)).encrypt(n.encode())
    return n, Event(n.commitment, c, ciphertext_hash(c))

@dataclass(frozen=True)
class IncomingView:
    address: Address
    decryption_key: bytes

    def validate(self):
        self.address.validate()
        if bytes(PrivateKey(self.decryption_key).public_key) != self.address.encryption_key:
            raise ValueError("decryption key does not match address")

    def receive(self, event):
        self.validate()
        if len(event.ciphertext) != 304:
            raise ValueError("ciphertext length")
        n = Note.decode(SealedBox(PrivateKey(self.decryption_key)).decrypt(event.ciphertext))
        if ciphertext_hash(event.ciphertext) != event.digest:
            raise ValueError("delivery digest")
        if (n.chain, n.pool, n.receiver) != (self.address.chain, self.address.pool, self.address.receiver):
            raise ValueError("wrong recipient or context")
        if n.commitment != event.commitment:
            raise ValueError("wrong commitment")
        return n

    def scan(self, events):
        found = {}
        for event in events:
            if type(event.index) is not int or not 0 <= event.index < 2**32:
                continue  # Decryption alone is not evidence of a funded tree leaf.
            try:
                n = self.receive(event)
                # Repeated delivery of one leaf counts once; separate funded leaves
                # remain spendable even if a sender reused the same note opening.
                found.setdefault(event.index, n)
            except (ValueError, CryptoError):
                continue
        return found

@dataclass(frozen=True)
class FullView:
    """Sensitive read-only capability. Does not contain seed or spending secret.

    Reveals received-note nullifiers, not all outgoing destinations or memos.
    Key/address consistency is checked; statement validity still requires sk.
    """
    incoming: IncomingView
    authority: int
    nullifier_secret: int

    @property
    def address(self):
        return self.incoming.address

    def validate(self):
        self.incoming.validate()
        ak = felt(self.authority, True)
        nk = felt(self.nullifier_secret, True)
        if H([tag("PUSH_OWNER_V2"), ak, nk]) != self.address.receiver:
            raise ValueError("full viewing key does not match address")

    def scan(self, events):
        self.validate()
        return self.incoming.scan(events)

    def nullifier(self, note, leaf_index):
        self.validate()
        if (note.chain, note.pool, note.receiver) != (self.address.chain, self.address.pool, self.address.receiver):
            raise ValueError("note outside viewing scope")
        if type(leaf_index) is not int or not 0 <= leaf_index < 2**32:
            raise ValueError("leaf index")
        return H([tag("PUSH_NF_V2"), self.nullifier_secret, note.commitment, leaf_index])

    def export(self):
        """Returns sensitive plaintext for an explicit key transfer, not for logs.

        Only synthetic test keys are exported by this prototype's harness.
        Encryption/authentication of real key transfers is not implemented here.
        """
        self.validate()
        a = self.address
        return {'format':'templar-full-view-poc2',
                'address':{'chain':a.chain,'pool':a.pool,'receiver':a.receiver,
                           'encryption_key':a.encryption_key.hex()},
                'incoming_secret':self.incoming.decryption_key.hex(),
                'authority':self.authority,'nullifier_secret':self.nullifier_secret}

    @classmethod
    def load(cls, data, *, expected_address):
        # Authenticate the expected address independently; a self-consistent key
        # for somebody else's wallet is not an audit credential for this wallet.
        if data.get('format') != 'templar-full-view-poc2':
            raise ValueError("view format")
        a = data['address']
        address = Address(a['chain'],a['pool'],a['receiver'],bytes.fromhex(a['encryption_key']))
        if address != expected_address:
            raise ValueError("unexpected receiving address")
        view = cls(IncomingView(address,bytes.fromhex(data['incoming_secret'])),
                   data['authority'],data['nullifier_secret'])
        view.validate()
        return view

@dataclass(frozen=True)
class Wallet:
    spend_key: int
    view: IncomingView

    @property
    def address(self):
        return self.view.address

    @property
    def full_view(self):
        view = FullView(self.view,authority_key(self.spend_key),nullifier_key(self.spend_key))
        view.validate()
        return view

    @classmethod
    def restore(cls, seed, chain=CHAIN, pool=POOL):
        """POC seed scheme, deliberately not a finalized wallet derivation standard."""
        if len(seed) != 32:
            raise ValueError("seed length")
        # Exported secrets cannot be scoped by software checks alone. Derive
        # different key material per network/pool so disclosure stays in scope.
        context = felt(chain,True).to_bytes(32,'big') + felt(pool,True).to_bytes(32,'big')
        # Rejection sampling rather than modulo reduction for the felt spend key.
        i = 0
        while True:
            sk = int.from_bytes(hmac.digest(seed, b"templar/push-poc2/spend/" + context + i.to_bytes(4, "big"), "sha256"), "big")
            if 0 < sk < P:
                break
            i += 1
        vk = hmac.digest(seed, b"templar/push-poc2/incoming/" + context, "sha256")
        address = Address(chain, pool, receiver_key(sk), bytes(PrivateKey(vk).public_key))
        return cls(sk, IncomingView(address, vk))

def binding(chain, pool, root, token, nfs, outputs, withdrawals):
    pre = [tag("PUSH_BIND_V2"), VERSION, chain, pool, root, token, len(nfs)]
    pre += nfs + [0] * (4-len(nfs))
    pre += [len(outputs)]
    for cm, digest in outputs + [(0, 0)] * (4-len(outputs)):
        pre += [cm, digest]
    pre += [len(withdrawals)]
    for recipient, amount in withdrawals + [(0, 0)] * (2-len(withdrawals)):
        pre += [recipient, amount]
    return H(pre)

def make_case(inputs, outputs, withdrawals, tree):
    """inputs=(note, spend key, index); outputs=(note, encrypted public event)."""
    token = inputs[0][0].token
    chain, pool = inputs[0][0].chain, inputs[0][0].pool
    nfs = [n.nullifier(sk, idx) for n, sk, idx in inputs]
    out = [(n.commitment, e.digest) for n, e in outputs]
    b = binding(chain, pool, tree.root(), token, nfs, out, withdrawals)
    w = [VERSION, chain, pool, tree.root(), token, b, len(inputs), len(outputs), len(withdrawals)]
    for (n, sk, idx), nf in zip(inputs, nfs):
        w += [sk, n.rho, n.amount, nf, idx, *tree.path(idx)]
    for n, e in outputs:
        w += [n.receiver, n.rho, n.amount, n.commitment, e.digest]
    for to, amt in withdrawals:
        w += [to, amt]
    return {"witness": w, "public": [VERSION, chain, pool, tree.root(), 0, 0, 0, b],
            "nullifiers": nfs, "outputs": out, "withdrawals": withdrawals}

def validate_case(case):
    """Python reference statement, not a proof verifier."""
    it = iter(case["witness"])
    def take():
        return felt(next(it))
    version, chain, pool, root, token, expected, ni, no, nw = [take() for _ in range(9)]
    if version != VERSION or not (1 <= ni <= 4 and 0 <= no <= 4 and 0 <= nw <= 2 and no+nw > 0):
        raise ValueError("shape/version")
    nfs, outs, wds, total_in, total_out = [], [], [], 0, 0
    for _ in range(ni):
        sk, rho, amt, nf, index = [take() for _ in range(5)]
        if index >= 2**32:
            raise ValueError("index range")
        leaf_index = index
        n = Note(chain, pool, token, amt, receiver_key(sk), rho)
        cur = n.commitment
        for _ in range(32):
            sibling = take()
            cur = H([sibling, cur] if index % 2 else [cur, sibling])
            index //= 2
        if cur != root or n.nullifier(sk, leaf_index) != nf or nf == 0 or nf in nfs:
            raise ValueError("membership/nullifier")
        nfs.append(nf)
        total_in += amt
    for _ in range(no):
        receiver, rho, amt, cm, digest = [take() for _ in range(5)]
        n = Note(chain, pool, token, amt, receiver, rho)
        if n.commitment != cm or cm == 0 or digest == 0:
            raise ValueError("output")
        outs.append((cm, digest))
        total_out += amt
    for _ in range(nw):
        to, amt = take(), take()
        if not 0 < to < 2**251 or not 0 < amt < 2**128:
            raise ValueError("withdrawal")
        wds.append((to, amt))
        total_out += amt
    if next(it, None) is not None or total_in != total_out:
        raise ValueError("conservation/trailing witness")
    if expected != binding(chain, pool, root, token, nfs, outs, wds):
        raise ValueError("binding")
    if case["public"] != [VERSION, chain, pool, root, 0, 0, 0, expected]:
        raise ValueError("public output")
    return nfs, outs, wds

class Ledger:
    """Local state model only: no ERC20 or cryptographic proof acceptance here."""
    def __init__(self):
        self.tree, self.spent, self.events = Tree(), set(), []
        self.roots = {self.tree.root()}

    def fund(self, note, event):
        assert event.commitment == note.commitment
        index = self.tree.insert(note.commitment)
        self.events.append(replace(event, index=index, digest=ciphertext_hash(event.ciphertext)))
        self.roots.add(self.tree.root())
        return index

    def apply(self, case, events):
        nfs, outputs, wds = validate_case(case)
        if case["public"][3] not in self.roots or any(nf in self.spent for nf in nfs):
            raise ValueError("unknown root/replay")
        actual = [(e.commitment, ciphertext_hash(e.ciphertext)) for e in events]
        if outputs != actual:
            raise ValueError("changed or missing delivery")
        self.spent.update(nfs)
        indices = [self.tree.insert(cm) for cm, _ in outputs]
        self.events.extend(replace(e, index=i, digest=digest)
                           for e, i, (_, digest) in zip(events, indices, outputs))
        self.roots.add(self.tree.root())
        return indices
