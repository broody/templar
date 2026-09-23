"""Server log20 study, lever 1: other points on the FRI security line (pow + blowup x queries
>= 96). Per configuration, all local (synthetic fixture, nothing on chain):
  1. an R0 V2 transfer proved by the wallet, bounded and normal (client memory and time);
  2. the bridge and account built for that proof's manifest; bridge validation;
  3. the account executed in the virtual OS (local fixture), giving a PIE;
  4. that PIE's component log sizes (`capacity trace`) and Blake attribution.
Usage: sweep.py OUT LOG_BLOWUP,N_QUERIES[,POW] ..."""
from pathlib import Path
import json, os, subprocess, sys, time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
CLIENT = HERE.parent / 'client-port'
sys.path.insert(0, str(ROOT / 'bench/m31-sepolia'))
os.environ.setdefault('TEMPLAR_SEPOLIA_RUN', '/nonexistent')
import wallet  # noqa: E402

CAPACITY = ROOT / 'target/m31-private-wrapper/capacity-build-original-v3/capacity'
BLAKE_SITES = ROOT / 'target/m31-private-wrapper/attribution-build/blake_sites'
CHAIN = int.from_bytes(b'SN_SEPOLIA', 'big')
POOL, TOKEN = 0x1234abcd, 0x5678ef
LIMIT = 20


def spend():
    alice, bob = wallet.random_digest(), wallet.random_digest()
    a, b = wallet.keys(alice), wallet.keys(bob)
    notes = []
    for amount in (600, 400):
        rho = wallet.random_digest()
        notes.append({'sk': alice, 'rho': rho, 'amount': str(amount),
                      'cm': wallet.commitment(CHAIN, POOL, TOKEN, amount, wallet.inner(a['receiver'], rho))})
    ct = [wallet.ciphertext('bob'), wallet.ciphertext('change')]
    return {'chain': hex(CHAIN), 'pool': hex(POOL), 'token': hex(TOKEN), 'leaves': [n['cm'] for n in notes],
            'inputs': [{'sk': n['sk'], 'rho': n['rho'], 'amount': n['amount'], 'position': i} for i, n in enumerate(notes)],
            'outputs': [{'active': True, 'receiver': b['receiver'], 'rho': wallet.random_digest(), 'amount': '700',
                         'delivery': hex(wallet.delivery_digest(ct[0]))},
                        {'active': True, 'receiver': a['receiver'], 'rho': wallet.random_digest(), 'amount': '300',
                         'delivery': hex(wallet.delivery_digest(ct[1]))}],
            'withdrawal': {'recipient': '0x0', 'amount': '0'}}


def run(cfg, out, body):
    out.mkdir(parents=True, exist_ok=True)
    if (out / 'result.json').exists():
        return json.loads((out / 'result.json').read_text())
    os.environ['TEMPLAR_FRI'] = cfg
    r = {'fri': cfg}
    r['client_bounded'] = wallet.prove(body, out / 'client', 16)
    r['client_normal'] = wallet.prove(body, out / 'client-normal', 1 << 20)
    manifest = out / 'client/trusted-config.json'
    work = out / 'bridge'
    if not work.exists():
        subprocess.run([sys.executable, str(CLIENT / 'build_bridge_arith.py'), str(manifest), str(work)], cwd=CLIENT, check=True,
                       stdout=open(out / 'bridge-build.log', 'w'), stderr=subprocess.STDOUT)
    rec = json.loads((work / 'build-record.json').read_text())
    r['account_casm_felts'] = rec.get('account_casm_felts')
    v = subprocess.run([sys.executable, str(CLIENT / 'validate_bridge_r0.py'), str(work), str(out / 'client'), str(out / 'bridge-validation')],
                       cwd=CLIENT, capture_output=True, text=True)
    lines = [json.loads(l) for l in v.stdout.splitlines() if l.startswith('{')]
    r['bridge'] = {'passed': sum(l['passed'] for l in lines), 'cases': len(lines), 'steps': lines[0].get('steps') if lines else None}
    assert v.returncode == 0, v.stdout[-2000:] + v.stderr[-2000:]
    sierra = next((work / 'target/contract').glob('*PaymentVerifierAccount.contract_class.json'))
    cap = out / 'os'
    if not (cap / 'os.pie.zip').exists():
        subprocess.run([sys.executable, str(CLIENT / 'capture_os.py'), '--sierra', str(sierra), '--proof-dir', str(out / 'client'),
                        '--public', str(out / 'client/public.json'), '--output', str(cap), '--tag-version', 'R0'],
                       cwd=CLIENT, check=True, stdout=open(out / 'capture.log', 'w'), stderr=subprocess.STDOUT)
    r['os'] = json.loads((cap / 'capture.json').read_text())['resources']
    subprocess.run([str(CAPACITY), 'trace', str(cap / 'os.pie.zip'), str(out / 'trace')], check=True,
                   stdout=open(out / 'trace.log', 'w'), stderr=subprocess.STDOUT)
    boot = json.loads((out / 'trace/boot.json').read_text())
    claim = json.loads((out / 'trace/claim.json').read_text())
    sizes = {}

    def walk(x, path):
        if isinstance(x, dict):
            for k, v in x.items():
                walk(v, path + [k])
        elif isinstance(x, list):
            for i, v in enumerate(x):
                walk(v, path + [str(i)])
        elif isinstance(x, int) and path and path[-1] == 'log_size':
            sizes['/'.join(path[:-1])] = x
    walk(claim, [])
    over = {k: v for k, v in sizes.items() if v > LIMIT}
    subprocess.run([str(BLAKE_SITES), str(cap / 'os.pie.zip'), str(out / 'blake')], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    b = json.loads((out / 'blake/blake-sites.json').read_text())
    seg = {k: sum(v) for k, v in b['blake_by_pc_segment_[compress,finalize]'].items()}
    poseidon = boot['builtin_segments']['poseidon_builtin']
    r.update(max_log=max(sizes.values()), over_log20=over, blake_total=boot['blake_compressions'],
             blake_by_segment={'bootloader': seg.get('0'), 'os': seg.get('14'), 'account': seg.get('19')},
             poseidon_instances=(poseidon['stop_ptr'] - poseidon['begin_addr']) // 6,
             calldata_felts=len(json.loads((out / 'client/cairo-arguments.json').read_text())),
             fits_log20=not over, component_log_sizes=sizes)
    (out / 'result.json').write_text(json.dumps(r, indent=1) + '\n')
    return r


def main():
    out = Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)
    body_path = out / 'spend.json'
    if not body_path.exists():
        body_path.write_text(json.dumps(spend()))
    body = json.loads(body_path.read_text())
    for cfg in sys.argv[2:]:
        t = time.time()
        r = run(cfg, out / cfg.replace(',', '-'), body)
        print(json.dumps({'fri': cfg, 'fits_log20': r['fits_log20'], 'over': r['over_log20'], 'blake': r['blake_total'],
                          'blake_by_segment': r['blake_by_segment'], 'poseidon': r['poseidon_instances'], 'calldata': r['calldata_felts'],
                          'account_casm': r['account_casm_felts'], 'bridge': r['bridge'],
                          'client_bounded_gib': round(r['client_bounded']['max_rss_gib'], 2),
                          'client_normal_gib': round(r['client_normal']['max_rss_gib'], 2),
                          'client_s': [round(r['client_bounded']['proving_seconds'], 2), round(r['client_normal']['proving_seconds'], 2)],
                          'blinding': r['client_bounded']['blinding_rows'], 'trace_log': r['client_bounded']['trace_log_size'],
                          'wall_s': round(time.time() - t)}), flush=True)


if __name__ == '__main__':
    main()
