"""Upgrade the relayer (`account-1`, Argent 0.3.1, Sierra 1.4) to Argent 0.5.0 (Sierra 1.7), so
calls it makes are billed in Sierra gas rather than Cairo steps. Signs the upgrade and a
follow-up transaction with sncast against a local capture server, simulates both in sequence
with validation, and submits the exact simulated upgrade only with `--submit`."""
from sepolia import *
import sys

NEW_CLASS = '0x73414441639dcd11d1846f287650a00c60c416b9d3ba45d31c651672125b2c2'  # Argent 0.5.0, Sierra 1.7
OUT = RUN / 'steps' / 'upgrade-account'
OUT.mkdir(parents=True, exist_ok=True)


def sign(name, address, fn, calldata, nonce, l2):
    """A signed INVOKE v3 from `account-1`, captured and not sent."""
    captured = OUT / f'{name}-signed.json'
    if captured.exists():
        return load(captured)['params']['invoke_transaction']

    class Capture(BaseHTTPRequestHandler):
        def do_POST(self):
            v = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            if v['method'] == 'starknet_addInvokeTransaction':
                save(captured, v)
                res = {'jsonrpc': '2.0', 'id': v['id'], 'error': {'code': -32603, 'message': 'captured locally; not forwarded'}}
            else:
                assert v['method'] != 'starknet_addDeclareTransaction'
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
        sncast('upgrade-account-sign-' + name, ['invoke', '--url', f'http://127.0.0.1:{server.server_port}', '--contract-address', h(address),
                                                '--function', fn, '--calldata', *[h(x) for x in calldata], '--nonce', h(nonce), *bounds(l2)],
               HERE, expected_error=True)
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
    return load(captured)['params']['invoke_transaction']


before = {'class': rpc('starknet_getClassHashAt', ['latest', ACCOUNT]), 'version': call(ACCOUNT, 'get_version'),
          'owner': [hex(x) for x in call(ACCOUNT, 'get_owner')]}
save(OUT / 'before.json', before)
if int(before['class'], 16) == int(NEW_CLASS, 16):
    print('already upgraded', json.dumps(before))
    sys.exit(0)
nonce = int(rpc('starknet_getNonce', ['latest', ACCOUNT]), 16)
# upgrade(new_implementation, calldata: Array<felt252>) on the account itself; empty calldata.
up = sign('upgrade', ACCOUNT, 'upgrade', [NEW_CLASS, 0], nonce, 60_000_000)
# Follow-up signed as sncast normally signs: a zero approve on the test token.
d = load(RUN / 'deployment.json')
follow = sign('follow-up', d['token'], 'approve', [d['pool'], 0, 0], nonce + 1, 20_000_000)
sim = rpc('starknet_simulateTransactions', ['latest', [up, follow], []], timeout=300)
save(OUT / 'simulation.json', sim)
for label, r in zip(['upgrade', 'follow-up'], sim):
    ex = r['transaction_trace']['execute_invocation']
    print(label, 'REVERTED ' + ex['revert_reason'][:600] if 'revert_reason' in ex else 'SUCCEEDED',
          'l2_gas', r['transaction_trace']['execution_resources']['l2_gas'])
    assert 'revert_reason' not in ex, label
if '--submit' in sys.argv:
    resp = load(OUT / 'response.json') or rpc('starknet_addInvokeTransaction', [up])
    save(OUT / 'response.json', resp)
    receipt(resp['transaction_hash'], OUT / 'receipt.json')
    after = {'class': rpc('starknet_getClassHashAt', ['latest', ACCOUNT]), 'version': call(ACCOUNT, 'get_version'),
             'owner': [hex(x) for x in call(ACCOUNT, 'get_owner')]}
    save(OUT / 'after.json', after)
    print(json.dumps({'before': before, 'after': after}))
    assert int(after['class'], 16) == int(NEW_CLASS, 16) and after['owner'] == before['owner']
