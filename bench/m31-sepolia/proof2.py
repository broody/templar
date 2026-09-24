"""Server side of a spend: execute the statement account's `__execute__` on the client proof in
the pinned virtual OS against real Sepolia state (the local node), prove the PIE through the
PROOF2 large path, and write the transaction's `proof.base64` and `proof-facts.txt`."""
from sepolia import *
import base64, hashlib, importlib.util, sys

CAPTURE = ROOT / 'target/m31-private-wrapper/capacity-capture-build-v3/capture'
PROVE = ROOT / 'bench/m31-private-wrapper/proof2-large/run.sh'
TAG = int.from_bytes(b'TMPZR0_PAYMENT_V3', 'big')
_spec = importlib.util.spec_from_file_location('ref_poseidon', ROOT / 'bench/adr8/ref_poseidon.py')
ref = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ref)
sys.path.insert(0, str(ROOT / 'bench/m31-private-wrapper/client-port'))
from validate_bridge_r0 import binding  # noqa: E402  (the bridge's independent V3 reference)


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def serve(client_dir, out, d):
    """client_dir holds the wallet's `cairo-arguments.json` and `public.json`. Returns the
    benchmark record; checkpointed on `out/benchmark.json`."""
    out = Path(out)
    if (out / 'benchmark.json').exists():
        return load(out / 'benchmark.json')
    out.mkdir(parents=True, exist_ok=True)
    public = load(client_dir / 'public.json')
    chain, pool = int(public['chain'], 16), int(public['pool'], 16)
    assert chain == CHAIN and pool == int(d['pool'], 16)
    bind = binding(public)
    # The base block must already contain the root the proof opens (and the statement account).
    block = rpc('starknet_getBlockWithTxHashes', ['latest'])
    base = block['block_number']
    assert call(d['pool'], 'root_is_known', [9, *public['root']], {'block_number': base}) == [1], 'root unknown at base block'
    save(out / 'base-block.json', {k: v for k, v in block.items() if k != 'transactions'})
    nonce = rpc('starknet_getNonce', [{'block_number': base}, d['statement']])
    tx = {'type': 'INVOKE', 'version': '0x3', 'sender_address': d['statement'],
          'calldata': load(client_dir / 'cairo-arguments.json'), 'signature': [], 'nonce': nonce,
          'resource_bounds': {g: {'max_amount': '0x3b9aca00' if g == 'l2_gas' else '0x0', 'max_price_per_unit': '0x0'}
                              for g in ('l1_gas', 'l2_gas', 'l1_data_gas')},
          'tip': '0x0', 'paymaster_data': [], 'account_deployment_data': [],
          'nonce_data_availability_mode': 'L1', 'fee_data_availability_mode': 'L1'}
    save(out / 'capture-request.json', {'block_id': {'block_number': base}, 'transaction': tx})
    cap = out / 'capture'
    start = time.monotonic()
    with (out / 'capture.log').open('w') as log:
        r = subprocess.run(['systemd-run', '--user', '--wait', '--pipe', f'--unit=templar-m31-sepolia-capture-{time.time_ns()}',
                            '-p', 'MemoryMax=16G', '-p', 'MemorySwapMax=0', '-p', 'CPUQuota=400%', '-p', 'CPUAffinity=0 1 2 3',
                            '-p', 'RuntimeMaxSec=900', '--setenv=RAYON_NUM_THREADS=4', '--setenv=TOKIO_WORKER_THREADS=4',
                            '/usr/bin/time', '-v', str(CAPTURE), RPC, str(out / 'capture-request.json'), str(cap)],
                           stdout=log, stderr=subprocess.STDOUT)
    capture_seconds = time.monotonic() - start
    assert r.returncode == 0, (out / 'capture.log').read_text()[-3000:]
    produced = load(cap / 'capture.json')
    messages = produced['l2_to_l1_messages']
    num = lambda v: int(v, 16) if isinstance(v, str) else int(v)
    assert len(messages) == 1 and num(messages[0]['from_address']) == int(d['statement'], 16)
    payload = [num(x) for x in messages[0]['payload']]
    assert payload == [int(d['classes']['statement'], 16), TAG, chain, pool, bind], payload
    # PROOF2, 4 pinned workers under a 115 GiB cap.
    start = time.monotonic()
    r = subprocess.run(['bash', str(PROVE), str(cap / 'os.pie.zip'), str(out / 'proof2'), '115G'], capture_output=True, text=True)
    prove_seconds = time.monotonic() - start
    summary = load(out / 'proof2/summary.json')
    assert r.returncode == 0 and summary and summary['verified'], r.stdout[-2000:] + r.stderr[-2000:]
    preimage = load(out / 'proof2/output-preimage.json')
    facts = [hex(int.from_bytes(b'PROOF2', 'big')), hex(int.from_bytes(b'VIRTUAL_SNOS', 'big')), *preimage]
    assert len(facts) == 9 and int(facts[2], 16) == int(d['os_program'], 16) and int(facts[4], 16) == base
    message = ref.poseidon_hash_span([int(d['statement'], 16), 0, 5, *payload])
    assert int(facts[7], 16) == 1 and int(facts[8], 16) == message
    proof = (out / 'proof2/proof.bin').read_bytes()
    (out / 'proof.base64').write_text(base64.b64encode(proof).decode())
    (out / 'proof-facts.txt').write_text(','.join(facts))
    rss = [l for l in (out / 'proof2/run.log').read_text().splitlines() if 'Maximum resident' in l]
    v = {'base_block': base, 'binding': hex(bind), 'message_hash': hex(message), 'facts': facts,
         'capture_seconds': capture_seconds, 'os_resources': produced['resources'], 'proof2_wall_seconds': prove_seconds,
         'proof2': summary, 'proof2_max_rss_gib': int(rss[-1].split()[-1]) / 2**20 if rss else None,
         'proof_bytes': len(proof), 'proof_sha256': hashlib.sha256(proof).hexdigest(), 'pie_sha256': sha(cap / 'os.pie.zip')}
    save(out / 'benchmark.json', v)
    print(json.dumps({k: v[k] for k in ('base_block', 'capture_seconds', 'proof2_wall_seconds', 'proof_bytes')}), flush=True)
    return v
