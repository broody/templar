"""Inspect only frozen public proof bytes; extract exact authenticated hash work.

This is a layout/authentication inspector, not an AIR/FRI proof verifier.
Candidate Blake messages are cost fixtures, not valid replacement proof roots.
"""
from collections import Counter
from pathlib import Path
import hashlib
import json
import struct

HERE = Path(__file__).resolve().parent
CLIENT = HERE.parent / 'm31-private-e2e/client'
OLD_PREFIX = b'Templar-private-membership-BCS-v1'
NEW_PREFIX = b'Templar-private-membership-BLAKE2S-v1'


def frame(tag, parts, prefix=OLD_PREFIX):
    return prefix + struct.pack('<Q', len(tag)) + tag + struct.pack('<Q', len(parts)) + b''.join(
        struct.pack('<Q', len(part)) + part for part in parts)


def shake(tag, parts):
    return hashlib.shake_256(frame(tag, parts)).digest(96)


def inspect(public_path, proof_path):
    public = json.loads(public_path.read_text())
    proof = proof_path.read_bytes()
    magic = proof[:8]
    assert magic in (b'TMPZK001', b'TMPZK002')
    modern = magic == b'TMPZK002'
    digest_size, salt_size = (32, 96) if modern else (96, 192)
    prefix = NEW_PREFIX if modern else OLD_PREFIX
    client = HERE.parent / 'm31-private-blake/client' if modern else CLIENT
    hash_message = (lambda msg: hashlib.blake2s(msg).digest()) if modern else (lambda msg: hashlib.shake_256(msg).digest(96))
    oracle = lambda tag, parts: hash_message(frame(tag, parts, prefix))
    names = ['air.rs', 'hash.rs', 'constants.rs', 'poly.rs', 'crypto.rs', 'proof.rs']
    circuit = oracle(b'circuit', [(client / 'src' / name).read_bytes() for name in names])
    x = magic + circuit + json.dumps(public, separators=(',', ':')).encode()
    roots = [proof[8 + digest_size * i:8 + digest_size * (i + 1)] for i in range(15)]
    sigma = oracle(b'public', [x])
    for phase, root in enumerate(roots):
        sigma = oracle(b'state', [struct.pack('<I', phase), root, sigma])
    assert sigma == proof[8 + digest_size * 15:8 + digest_size * 16]
    coins = b''.join(oracle(b'coins', [x, sigma, struct.pack('<I', 15), struct.pack('<I', k)]) for k in range(480 // digest_size))
    queries = sorted({word & 8191 for word in struct.unpack('<120I', coins)})
    # Pinned S-two domain: bit reversed +- (G_16384 + j*G_4096), group order 2^31.
    exponents = []
    for i in range(8192):
        j = int(f'{i:013b}'[::-1], 2)
        e = (1 << 17) + (j % 4096) * (1 << 19)
        exponents.append((e if j < 4096 else -e) % (1 << 31))
    positions = {e: i for i, e in enumerate(exponents)}
    trace = sorted(set(queries) | {positions[(exponents[i] - (1 << 24)) % (1 << 31)] for i in queries})
    jobs, unique = [], {}
    offset = 8 + digest_size * 16

    def record(key, kind, tag, parts):
        message = frame(tag, parts, prefix)
        entry = {'key': key, 'kind': kind, 'message': message, 'tag': tag, 'parts': parts}
        if key in unique:
            assert unique[key]['message'] == message, 'inconsistent shared authentication node'
        else:
            unique[key] = entry
        jobs.append(entry)
        return hash_message(message)

    def opening(tree, index, logn, width):
        nonlocal offset
        fields = proof[offset:offset + width * 4]
        assert len(fields) == width * 4
        assert all(v < 0x7fffffff for v in struct.unpack('<' + 'I' * width, fields))
        offset += width * 4
        salt = proof[offset:offset + salt_size]
        offset += salt_size
        kind = 'base' if width == 1191 else 'claims' if width == 9544 else 'small'
        h = record((tree, -1, index), kind, b'leaf', [struct.pack('<I', tree), struct.pack('<Q', index), fields, salt])
        at = index
        for depth in range(logn):
            sibling = proof[offset:offset + digest_size]
            offset += digest_size
            a, b = (h, sibling) if at % 2 == 0 else (sibling, h)
            h = record((tree, depth, at // 2), 'node', b'node', [struct.pack('<I', tree), struct.pack('<I', depth), a, b])
            at //= 2
        assert h == roots[tree], f'authentication mismatch tree {tree}, index {index}'

    opening(2, 0, 0, 9544)
    opening(14, 0, 0, 4)
    for i in trace:
        opening(0, i, 13, 1191)
    for tree in (1, 3):
        for i in queries:
            opening(tree, i, 13, 4)
    for layer in range(10):
        for i in sorted({((q >> layer) & ~1) + bit for q in queries for bit in (0, 1)}):
            opening(4 + layer, i, 13 - layer, 4)
    assert offset == len(proof), 'layout/trailing bytes mismatch'
    return jobs, list(unique.values()), {
        'format': magic.decode(), 'digest_bytes': digest_size, 'salt_bytes': salt_size,
        'proof_sha256': hashlib.sha256(proof).hexdigest(), 'proof_bytes': len(proof),
        'unique_queries': len(queries), 'trace_leaves': len(trace),
        'uncached_counts': dict(Counter(j['kind'] for j in jobs)),
        'cached_counts': dict(Counter(j['kind'] for j in unique.values())),
        'uncached_shake_permutations': sum(len(j['message']) // 136 + 1 for j in jobs),
        'cached_shake_permutations': sum(len(j['message']) // 136 + 1 for j in unique.values()),
        'uncached_blake_compressions': sum((len(j['message']) + 63) // 64 for j in jobs),
        'cached_blake_compressions': sum((len(j['message']) + 63) // 64 for j in unique.values()),
    }


def candidate_message(job, salt_bytes=192):
    parts = list(job['parts'])
    if job['kind'] == 'node':
        # Fixed public stand-ins of the candidate digest width. These are NOT
        # asserted to be children of an authenticated Blake proof tree.
        parts[2:] = [hashlib.blake2s(p).digest() for p in parts[2:]]
    else:
        parts[-1] = parts[-1][:salt_bytes]
    return frame(job['tag'], parts, NEW_PREFIX)


def packed(message):
    padding = message + b'\0' * (-len(message) % 4)
    return list(struct.unpack('<' + 'I' * (len(padding) // 4), padding))


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--public', type=Path, required=True)
    parser.add_argument('--proof', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    jobs, unique, report = inspect(args.public, args.proof)
    report['candidate_cost_only'] = report['format'] == 'TMPZK001'
    report['inspection_scope'] = 'transcript/layout/authentication only; no AIR/FRI verification'
    if report['format'] == 'TMPZK002':
        del report['uncached_shake_permutations']
        del report['cached_shake_permutations']
    report['candidate_prefix'] = NEW_PREFIX.decode()
    report['candidate_salts'] = {}
    for salt in ((64, 96, 128, 192) if report['format'] == 'TMPZK001' else ()):
        report['candidate_salts'][str(salt)] = {
            'message_lengths': {j['kind']: len(candidate_message(j, salt)) for j in unique},
            'uncached_compressions': sum((len(candidate_message(j, salt)) + 63) // 64 for j in jobs),
            'cached_compressions': sum((len(candidate_message(j, salt)) + 63) // 64 for j in unique),
        }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
