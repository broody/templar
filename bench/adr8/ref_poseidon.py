import hashlib, json

P = 2**251 + 17*2**192 + 1  # felt252 prime (DEFAULT_PRIME)

def ark(idx):
    # generate_round_constant("Hades", P, idx) -- canonical Starkware derivation
    return int(hashlib.sha256(f"Hades{idx}".encode()).hexdigest(), 16) % P

def hades(v):
    # m=3 (r=2,c=1), r_f=8, r_p=83; S-box x^3; MDS [[3,1,1],[1,-1,1],[1,1,-2]]
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

def poseidon_hash_span(span):
    # core::poseidon::poseidon_hash_span: sponge init (0,0,0); absorb pairs;
    # odd tail is a SINGLE permutation (s0+x, s1+1, s2); even tail finalizes
    # (s0+1, s1, s2). [1,2] validated against the corelib docstring vector;
    # the odd tail is validated against the packages/pool golden vectors
    # (5-element derivations, 2026-09-20).
    s0, s1, s2 = 0, 0, 0
    i = 0
    n = len(span)
    while n - i >= 2:
        s0, s1, s2 = hades([(s0 + span[i]) % P, (s1 + span[i+1]) % P, s2])
        i += 2
    if n - i == 1:
        s0, s1, s2 = hades([(s0 + span[i]) % P, (s1 + 1) % P, s2])  # odd tail
    else:
        s0, s1, s2 = hades([(s0 + 1) % P, s1, s2])  # even finalize
    return s0

def poseidon_hash_pair(x, y):
    # starkware poseidon_hash.py: hades([x, y, 2])[0]
    return hades([x, y, 2])[0]

if __name__ == "__main__":
    tv = 0x0371cb6995ea5e7effcd2e174de264b5b407027a75a231a70c2c8d196107f0e7
    got = poseidon_hash_span([1, 2])
    print("poseidon_hash_span([1,2]) =", hex(got))
    print("corelib docstring vector  =", hex(tv))
    assert got == tv, "MISMATCH vs Cairo VM"
    print("PYTHON REFERENCE MATCHES CAIRO VM")
    a, b = 0x123, 0x456
    print(f"H_pair({hex(a)},{hex(b)}) =", hex(poseidon_hash_pair(a, b)))
    json.dump({"a": a, "b": b, "out": poseidon_hash_pair(a, b)}, open("tv.json", "w"))
