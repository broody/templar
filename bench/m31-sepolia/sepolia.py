"""Bounded Sepolia transport for the option-A R0 run, adapted from the PROOF1 run's
`controlled-push-e2e/common.py`: reads through the local node, bounded fees, checkpointed steps
that are never retried blindly, and proof transactions signed by sncast against a local capture
server, then posted to the gateway. The runtime directory (note secrets, state) stays outside
the repository; `report.py` copies an allowlist into `results/`."""
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json, os, subprocess, threading, time, urllib.error, urllib.request

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
RUN = Path(os.environ.get('TEMPLAR_SEPOLIA_RUN') or json.loads((HERE / 'run-location.json').read_text())['runtime'])
# v0.10 throughout: sncast needs it for proof fields, and the pinned virtual-OS runner for its
# block headers (`state_diff_commitment`).
RPC = 'http://127.0.0.1:9545/rpc/v0_10'
# The local node cannot simulate declarations (internal error on Sierra 1.8 classes); they go
# through the public endpoint the PROOF1 run used.
DECLARE_RPC = 'https://api.zan.top/public/starknet-sepolia/rpc/v0_10'
GATEWAY = 'https://alpha-sepolia.starknet.io/gateway/add_transaction'
ACCOUNT = '0x54f2b25070d70d49f1c1f7c10ef2639889fdac15894d3fba1a03caf5603eca3'
ACCOUNT_NAME = 'account-1'
ACCOUNTS_FILE = '/home/broody/.starknet_accounts/starknet_open_zeppelin_accounts.json'
SNCAST = '/home/broody/.asdf/installs/starknet-foundry/0.63.0/bin/sncast'
SCARB = '/home/broody/.asdf/installs/scarb/2.18.0/bin/scarb'
ENV = os.environ.copy()
ENV['PATH'] = '/home/broody/.asdf/installs/scarb/2.18.0/bin:' + ENV['PATH']
CHAIN = int.from_bytes(b'SN_SEPOLIA', 'big')
# Hard ceilings on one transaction's maximum fee, in fri. Declarations cost 40,960 L2 gas per
# class felt (Sierra + CASM): about 3.5-3.7B L2 gas for the pool and the statement account.
# Actual fees are charged at the block's price, below the bound.
MAX_FEE_FRI = 25 * 10**18
MAX_DECLARE_FEE_FRI = 200 * 10**18
L2_PRICE_BOUND = 40_000_000_000


def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + '\n')


def load(path, default=None):
    path = Path(path)
    return json.loads(path.read_text()) if path.exists() else default


def rpc(method, params, url=RPC, timeout=60):
    req = urllib.request.Request(url, json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode(),
                                 {'Content-Type': 'application/json'})
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                v = json.load(r)
            break
        except (urllib.error.URLError, TimeoutError):
            if attempt == 2:
                raise
            time.sleep(1)
    if 'error' in v:
        raise RuntimeError(json.dumps(v['error']))
    return v['result']


def selector(name):
    return subprocess.check_output([SNCAST, 'utils', 'selector', name], text=True, env=ENV).split()[-1]


def call(address, name, data=(), block='latest'):
    req = {'contract_address': h(address), 'entry_point_selector': selector(name), 'calldata': [h(x) for x in data]}
    return [int(x, 16) for x in rpc('starknet_call', [req, block])]


def h(x):
    return hex(x) if isinstance(x, int) else x


def bounds(l2, ceiling=MAX_FEE_FRI):
    """Explicit resource bounds: `l2` L2 gas at up to 40 gwei-fri, small L1 and L1 data caps."""
    b = [('l2-gas', l2), ('l2-gas-price', L2_PRICE_BOUND), ('l1-gas', 1), ('l1-gas-price', 200_000_000_000_000),
         ('l1-data-gas', 10_000), ('l1-data-gas-price', 1_000_000_000_000)]
    total = l2 * L2_PRICE_BOUND + 200_000_000_000_000 + 10_000 * 1_000_000_000_000
    assert total <= ceiling, f'fee bound {total / 1e18} STRK exceeds the ceiling'
    return [a for k, v in b for a in (f'--{k}', str(v))]


def sncast(name, args, cwd, expected_error=False):
    out = RUN / 'steps' / name
    out.mkdir(parents=True, exist_ok=True)
    cmd = [SNCAST, '--account', ACCOUNT_NAME, '--accounts-file', ACCOUNTS_FILE, '--json', *args]
    (out / 'command.json').write_text(json.dumps(cmd))
    with (out / 'stdout.jsonl').open('w') as so, (out / 'stderr.log').open('w') as se:
        p = subprocess.run(cmd, cwd=cwd, env=ENV, stdout=so, stderr=se)
    rows = []
    for line in (out / 'stdout.jsonl').read_text().splitlines():
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    if p.returncode and not expected_error:
        raise RuntimeError(f'{name}: ' + (out / 'stderr.log').read_text()[-1500:] + str(rows)[-1500:])
    return rows


def receipt(tx, path, expected='SUCCEEDED'):
    path = Path(path)
    v = load(path)
    if v is None:
        for _ in range(120):
            try:
                v = rpc('starknet_getTransactionReceipt', [tx])
            except RuntimeError as e:
                if 'not found' not in str(e).lower():
                    raise
                time.sleep(3)
                continue
            if v.get('finality_status') in ('ACCEPTED_ON_L2', 'ACCEPTED_ON_L1'):
                save(path, v)
                break
            time.sleep(3)
        else:
            raise RuntimeError(f'receipt pending for {tx}; inspect before resubmitting')
    assert v['execution_status'] == expected, (tx, v.get('execution_status'), v.get('revert_reason'))
    print(json.dumps({'tx': tx, 'status': v['execution_status'], 'block': v.get('block_number'),
                      'fee_STRK': int(v['actual_fee']['amount'], 16) / 1e18, 'revert_reason': v.get('revert_reason')}), flush=True)
    return v


def normal_tx(name, args, cwd, url=RPC):
    """One checkpointed transaction: a recorded response is reused; an incomplete prior attempt
    stops the run for manual reconciliation."""
    path = RUN / 'steps' / name / 'response.json'
    v = load(path)
    if v is None:
        if (path.parent / 'stdout.jsonl').exists():
            raise RuntimeError(f'inspect incomplete prior transaction {name} before retrying')
        rows = sncast(name, args + ['--url', url], cwd)
        v = next(x for x in rows if 'transaction_hash' in x)
        save(path, v)
    receipt(v['transaction_hash'], path.parent / 'receipt.json')
    return v


def invoke(name, address, fn, calldata, l2, cwd):
    return normal_tx(name, ['invoke', '--contract-address', h(address), '--function', fn,
                            '--calldata', *[h(x) for x in calldata], *bounds(l2)], cwd)


def proof_invoke(name, address, fn, calldata, proof_dir, l2, cwd, expected='SUCCEEDED', reason=None):
    """Sign an invoke carrying `proof_dir/{proof.base64, proof-facts.txt}` with sncast against a
    local capture server (reads forwarded to the node; the add-transaction request captured, not
    sent), check it, then post it to the gateway. A captured or posted attempt is never
    re-signed automatically."""
    out = RUN / 'steps' / name
    out.mkdir(parents=True, exist_ok=True)
    response_path = out / 'gateway-response.json'
    response = load(response_path)
    if response is None:
        captured = out / 'signed-request.json'
        if captured.exists():
            raise RuntimeError(f'inspect prior capture for {name}; no automatic retry')

        class Capture(BaseHTTPRequestHandler):
            def do_POST(self):
                v = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                with (out / 'rpc-methods.log').open('a') as t:
                    t.write(v['method'] + '\n')
                if v['method'] == 'starknet_addInvokeTransaction':
                    save(captured, v)
                    res = {'jsonrpc': '2.0', 'id': v['id'], 'error': {'code': -32603, 'message': 'captured locally; not forwarded'}}
                else:
                    assert v['method'].startswith(('starknet_get', 'starknet_spec', 'starknet_chain', 'starknet_block', 'starknet_estimate')) \
                        or v['method'] == 'starknet_call', v['method']
                    try:
                        res = {'jsonrpc': '2.0', 'id': v['id'], 'result': rpc(v['method'], v.get('params', {}))}
                    except RuntimeError as e:
                        res = {'jsonrpc': '2.0', 'id': v['id'], 'error': json.loads(str(e))}
                payload = json.dumps(res).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *a):
                pass

        server = ThreadingHTTPServer(('127.0.0.1', 0), Capture)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            sncast('capture-' + name, ['invoke', '--url', f'http://127.0.0.1:{server.server_port}', '--contract-address', h(address),
                                       '--function', fn, '--calldata', *[h(x) for x in calldata],
                                       '--proof-file', str(proof_dir / 'proof.base64'), '--proof-facts-file', str(proof_dir / 'proof-facts.txt'),
                                       *bounds(l2)], cwd, expected_error=True)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
        tx = json.loads(captured.read_text())['params']['invoke_transaction']
        assert tx['proof'] and tx['proof_facts'], 'proof missing from the signed request'
        assert int(tx['proof_facts'][0], 16) == int.from_bytes(b'PROOF2', 'big')
        assert tx['calldata'][-len(calldata):] == [h(x) for x in calldata]
        fee = sum(int(x['max_amount'], 16) * int(x['max_price_per_unit'], 16) for x in tx['resource_bounds'].values())
        assert fee <= MAX_FEE_FRI, fee
        tx['type'] = 'INVOKE_FUNCTION'
        tx['resource_bounds'] = {k.upper(): v for k, v in tx['resource_bounds'].items()}
        tx['nonce_data_availability_mode'] = 0
        tx['fee_data_availability_mode'] = 0
        save(out / 'gateway-request.json', tx)
        req = urllib.request.Request(GATEWAY, json.dumps(tx).encode(), {'Content-Type': 'application/json'})
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                response = json.load(r)
        except urllib.error.HTTPError as e:
            response = json.loads(e.read())
        save(response_path, response)
    if response.get('code') != 'TRANSACTION_RECEIVED':
        raise RuntimeError(f'gateway rejected {name}: {json.dumps(response)[:1500]}')
    v = receipt(response['transaction_hash'], out / 'receipt.json', expected)
    if reason:
        assert reason in v.get('revert_reason', ''), v.get('revert_reason')
    return v
