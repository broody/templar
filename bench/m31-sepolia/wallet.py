"""Wallet helpers for the Sepolia run: keys, notes, deliveries and R0 proofs, via the Rust
`wallet` example (client-port) and the reference Poseidon. Secrets never leave the private
runtime directory chosen by the caller."""
from pathlib import Path
import importlib.util, json, os, secrets, subprocess

ROOT = Path(__file__).resolve().parents[2]
CLIENT = ROOT / 'bench/m31-private-wrapper/client-port'
WALLET = CLIENT / 'target/release/examples/wallet'
P = 2**31 - 1
_spec = importlib.util.spec_from_file_location('ref_poseidon', ROOT / 'bench/adr8/ref_poseidon.py')
ref = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ref)


def run(*args):
    out = subprocess.run([str(WALLET), *map(str, args)], capture_output=True, text=True, check=True).stdout
    return json.loads(out.strip().splitlines()[-1])


def random_digest():
    return [secrets.randbelow(P - 1) + 1 for _ in range(9)]


def keys(sk):
    return run('keys', json.dumps(sk))


def inner(receiver, rho):
    return run('inner', json.dumps(receiver), json.dumps(rho))


def commitment(chain, pool, token, amount, inner_digest):
    return run('commitment', hex(chain), hex(pool), hex(token), amount, json.dumps(inner_digest))


def ciphertext(tag):
    """A synthetic 304-byte payload in the pool's word format (nine 31-byte words + one 25-byte
    word). The run checks delivery binding, not encryption."""
    return [int.from_bytes(secrets.token_bytes(31), 'big') for _ in range(9)] + [int.from_bytes(secrets.token_bytes(25), 'big')]


def delivery_digest(ct):
    assert len(ct) == 10
    s = lambda b: int.from_bytes(b, 'big')
    return ref.poseidon_hash_span([s(b'CTRL_DELIVERY_V1'), 304, *ct])


def prove(spend, out, max_fri_columns=16):
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    (out / 'spend.json').write_text(json.dumps(spend))
    env = dict(os.environ, RAYON_NUM_THREADS='4')
    r = subprocess.run(['/usr/bin/time', '-v', 'taskset', '-c', '0-3', str(WALLET), 'prove', str(out / 'spend.json'), str(out),
                        str(max_fri_columns)], capture_output=True, text=True, env=env)
    if r.returncode:
        raise RuntimeError(r.stderr[-2000:])
    # The spend (secrets included) stays in the private runtime only.
    report = json.loads((out / 'report.json').read_text())
    rss = [l for l in r.stderr.splitlines() if 'Maximum resident' in l]
    report['max_rss_gib'] = int(rss[-1].split()[-1]) / 2**20
    return report
