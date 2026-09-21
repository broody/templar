#!/usr/bin/env python3
"""M2 statement fixture generator (V3 derivations + ADR-0014 bundle shape).

Builds two bundles — an ordinary 2-in/2-out/1-withdrawal and a controlled
1-in/1-out/1-withdrawal — over a reference sparse Merkle tree, computing the
padded statement binding and (for the controlled case) the transition
commitment exactly as spend.cairo and the circuit do. The golden derivations
are asserted byte-equal against the contract vectors in
packages/pool/src/tests/test_hashes.cairo — this file and the Cairo test suite
are the circuit<->contract agreement target.
"""
import hashlib, json

P = 2**251 + 17*2**192 + 1

def ark(idx):
    return int(hashlib.sha256(f"Hades{idx}".encode()).hexdigest(), 16) % P

def hades(v):
    ri = 0
    def rnd(vals, full, ri):
        vals = [(x + ark(3*ri + j)) % P for j, x in enumerate(vals)]
        if full:
            vals = [pow(x, 3, P) for x in vals]
        else:
            vals[-1] = pow(vals[-1], 3, P)
        a, b, c = vals
        return [(3*a + b + c) % P, (a - b + c) % P, (a + b - 2*c) % P]
    for _ in range(4): v = rnd(v, True, ri); ri += 1
    for _ in range(83): v = rnd(v, False, ri); ri += 1
    for _ in range(4): v = rnd(v, True, ri); ri += 1
    assert ri == 91
    return v

def hash_span(span):
    """core::poseidon::poseidon_hash_span — absorb pairs; odd tail is a single
    permutation (s0+x, s1+1, s2); even tail finalizes (s0+1, s1, s2). Validated
    byte-for-byte against the contract golden vectors (incl. odd lengths)."""
    s0, s1, s2 = 0, 0, 0
    i, n = 0, len(span)
    while n - i >= 2:
        s0, s1, s2 = hades([(s0 + span[i]) % P, (s1 + span[i+1]) % P, s2])
        i += 2
    if n - i == 1:
        s0, s1, s2 = hades([(s0 + span[i]) % P, (s1 + 1) % P, s2])
    else:
        s0, s1, s2 = hades([(s0 + 1) % P, s1, s2])
    return s0

def f(tag):
    return int.from_bytes(tag.encode(), "big")

TAGS = {
    "NOTE_SECRET": f("NOTE_SECRET_TAG:V3"),
    "NOTE_INNER": f("NOTE_INNER_TAG:V3"),
    "NOTE_ID": f("NOTE_ID_TAG:V3"),
    "COMMITMENT": f("COMMITMENT_TAG:V3"),
    "NULLIFIER": f("NULLIFIER_TAG:V3"),
    "TRANSITION": f("TRANSITION_COMMIT_TAG:V2"),
    "TX_BIND": f("TX_BIND_TAG:V2"),
}

# --- §3.1 derivations (contract parity, V3) ---------------------------------
def note_secret(salt, owner_priv):
    return hash_span([TAGS["NOTE_SECRET"], salt, owner_priv])

def inner(ns):
    return hash_span([TAGS["NOTE_INNER"], ns])

def commitment(token, amount, controller, policy, inn):
    return hash_span([TAGS["COMMITMENT"], token, amount, controller, policy, inn])

def nullifier(ns):
    return hash_span([TAGS["NULLIFIER"], ns])

# --- tree (port of packages/pool/src/tree.cairo) ----------------------------
TREE_DEPTH = 32
MAX_IN, MAX_OUT, MAX_WD = 4, 4, 2
Z = [0]
for _ in range(TREE_DEPTH):
    Z.append(hash_span([Z[-1], Z[-1]]))

def hash_pair(a, b):
    return hash_span([a, b])

class SparseTree:
    def __init__(self):
        self.nodes = {}
        self.count = 0
    def insert(self, leaf):
        idx = self.count
        self.nodes[(0, idx)] = leaf
        cur, i = leaf, idx
        for level in range(TREE_DEPTH):
            sib = self.nodes.get((level, i + 1 if i % 2 == 0 else i - 1), Z[level])
            cur = hash_pair(cur, sib) if i % 2 == 0 else hash_pair(sib, cur)
            i //= 2
            self.nodes[(level + 1, i)] = cur
        self.count += 1
        return idx
    def root(self):
        return self.nodes.get((TREE_DEPTH, 0), Z[TREE_DEPTH])
    def path(self, leaf_index):
        p, i = [], leaf_index
        for level in range(TREE_DEPTH):
            p.append(self.nodes.get((level, i + 1 if i % 2 == 0 else i - 1), Z[level]))
            i //= 2
        return p

# --- bundle shapes (ADR-0014) ------------------------------------------------
VERSION = int.from_bytes(b"TEMPLAR_V2", "big")
CHAIN = int.from_bytes(b"SN_SEPOLIA", "big")  # representative; SDK pins real chain
POOL = 0xdeadbeef
ACTIONS_HASH = 0xfeedface

def pad(xs, n, zero=0):
    return list(xs) + [zero] * (n - len(xs))

def statement_binding(root, nullifiers, commitments, withdrawals, controller, deadline, tc):
    """Padded binding, mirrors spend.cairo compute_statement_binding:
    withdrawals flatten as (token, low, high)."""
    pre = [TAGS["TX_BIND"], VERSION, CHAIN, POOL, root, len(nullifiers)]
    pre += pad(nullifiers, MAX_IN)
    pre.append(len(commitments))
    pre += pad(commitments, MAX_OUT)
    pre.append(len(withdrawals))
    for (token, amount) in pad(withdrawals, MAX_WD, (0, 0)):
        pre += [token, amount, 0]
    pre += [controller, deadline, tc, ACTIONS_HASH]
    return hash_span(pre)

def transition_commitment(nullifiers, in_amounts, commitments, out_amounts,
                          withdrawals, controller, deadline, nonce):
    pre = [TAGS["TRANSITION"], VERSION, CHAIN, POOL, len(nullifiers)]
    for nf, amt in zip(pad(nullifiers, MAX_IN), pad(in_amounts, MAX_IN)):
        pre += [nf, amt]
    pre.append(len(commitments))
    for cm, amt in zip(pad(commitments, MAX_OUT), pad(out_amounts, MAX_OUT)):
        pre += [cm, amt]
    pre.append(len(withdrawals))
    for (token, amount) in pad(withdrawals, MAX_WD, (0, 0)):
        pre += [token, amount, 0]
    pre += [controller, deadline, nonce]
    return hash_span(pre)

def golden_checks():
    """Byte-equality against packages/pool/src/tests/test_hashes.cairo."""
    ns = note_secret(0x5678, 0x321)
    assert ns == 0x2ac748d34723f39a5488c586bd85eeef4f7d41c47adff1eca9d27b4a45eb64e, hex(ns)
    inn = inner(ns)
    assert inn == 0x3f3e2dbc6518d40c8db0da9adb4cc53697135e0f18b15c8733d632cc2a4c47a, hex(inn)
    assert hash_span([TAGS["NOTE_ID"], ns]) == 0x8aa719bc987c504a483f1ab2876889495b62b0839f781a7cc890cf56b26c01
    assert commitment(0x1234, 1000, 0, 0, inn) == 0x7577d1d0bc46c70917153f1a172e86656c328370dd2dbb0db553428b0f22a6e
    assert commitment(0x1234, 1000, 0x4242, 0x99, inn) == 0x4208e9724102fc6677ead30cb1a7a373b24c785fdc8603f886c357d4d32066b
    assert nullifier(ns) == 0x18c6c60531f57833d29b3c497fd84fcf8258e52c8d91a6b0fbc04b66d9e2ca
    print("golden derivations match the contract vectors byte-for-byte")

def note(token, amount, owner, salt, ctrl=0, policy=0):
    ns = note_secret(salt, owner)
    return {
        "secret": ns, "token": token, "amount": amount, "owner": owner,
        "salt": salt, "ctrl": ctrl, "policy": policy,
        "leaf": commitment(token, amount, ctrl, policy, inner(ns)),
        "nullifier": nullifier(ns),
    }

def note_json(n):
    return {
        "salt": hex(n["salt"]), "owner_priv": hex(n["owner"]), "token": hex(n["token"]),
        "amount": n["amount"], "controller": n["ctrl"], "policy": n["policy"],
        "leaf": hex(n["leaf"]), "nullifier": hex(n["nullifier"]),
    }

def invoice_json(n):
    # Exactly what the paying wallet receives; no salt, secret or owner key.
    return {"inner": hex(inner(n["secret"])), "token": hex(n["token"]),
            "amount": n["amount"], "controller": n["ctrl"], "policy": n["policy"],
            "leaf": hex(n["leaf"])}

def main():
    golden_checks()
    token = 0x1234

    # ---- ordinary bundle: 2 in (700 + 400) / 2 out (600 + 460) / 1 wd (40) --
    in0 = note(token, 700, owner=0x321, salt=0x5678)
    in1 = note(token, 400, owner=0x321, salt=0x111)
    tree = SparseTree()
    idx0 = tree.insert(in0["leaf"])
    idx1 = tree.insert(in1["leaf"])
    root = tree.root()
    paths = [tree.path(idx0), tree.path(idx1)]

    out0 = note(token, 600, owner=0x777, salt=0x9999)
    out1 = note(token, 460, owner=0x888, salt=0xaaaa)
    wds = [(token, 40)]
    binding = statement_binding(
        root, [in0["nullifier"], in1["nullifier"]], [out0["leaf"], out1["leaf"]],
        wds, controller=0, deadline=0, tc=0,
    )
    ordinary = {
        "tree_root": hex(root), "leaf_indices": [idx0, idx1],
        "paths": [[hex(x) for x in p] for p in paths],
        "inputs": [note_json(in0), note_json(in1)],
        "outputs": [invoice_json(out0), invoice_json(out1)],
        "withdrawals": [{"token": hex(t), "amount": a} for (t, a) in wds],
        "controller": 0, "deadline": 0, "nonce": 0, "transition_commitment": "0x0",
        "binding": {
            "protocol_version": hex(VERSION), "chain_id": hex(CHAIN),
            "pool_address": hex(POOL), "actions_hash": hex(ACTIONS_HASH),
            "value": hex(binding),
        },
    }

    # ---- controlled bundle: 1 in (1000) / 1 out (600) / 1 wd (400) ----------
    ctrl, policy, deadline, nonce = 0x4242, 0x99, 1000000, 7
    cin0 = note(token, 1000, owner=0x321, salt=0x2222, ctrl=ctrl, policy=policy)
    ctree = SparseTree()
    cidx0 = ctree.insert(cin0["leaf"])
    croot = ctree.root()
    cout0 = note(token, 600, owner=0x321, salt=0x3333, ctrl=ctrl, policy=policy)
    cwds = [(token, 400)]
    ctc = transition_commitment(
        [cin0["nullifier"]], [1000], [cout0["leaf"]], [600], cwds,
        ctrl, deadline, nonce,
    )
    cbinding = statement_binding(
        croot, [cin0["nullifier"]], [cout0["leaf"]], cwds,
        controller=ctrl, deadline=deadline, tc=ctc,
    )
    controlled = {
        "tree_root": hex(croot), "leaf_indices": [cidx0],
        "paths": [[hex(x) for x in ctree.path(cidx0)]],
        "inputs": [note_json(cin0)],
        "outputs": [invoice_json(cout0)],
        "withdrawals": [{"token": hex(t), "amount": a} for (t, a) in cwds],
        "controller": ctrl, "deadline": deadline, "nonce": nonce,
        "transition_commitment": hex(ctc),
        "binding": {
            "protocol_version": hex(VERSION), "chain_id": hex(CHAIN),
            "pool_address": hex(POOL), "actions_hash": hex(ACTIONS_HASH),
            "value": hex(cbinding),
        },
    }

    json.dump({"ordinary": ordinary, "controlled": controlled},
              open("fixture.json", "w"), indent=1)
    print(f"fixture.json written: ordinary_root={hex(root)} controlled_root={hex(croot)}")

if __name__ == "__main__":
    main()
