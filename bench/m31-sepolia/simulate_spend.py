"""Re-sign a case's proof-carrying `apply_spend` from the relayer (sncast against a local
capture server, nothing sent) and simulate it with validation at the latest block. Used to
price a spend when the gateway does not accept PROOF2."""
from sepolia import *
import sys

name, label = sys.argv[1], sys.argv[2]
case = load(RUN / 'cases' / name / 'case.json')
folder = RUN / 'cases' / name / 'server'
out = RUN / 'steps' / f'simulate-{name}-{label}'
out.mkdir(parents=True, exist_ok=True)
captured = out / 'signed.json'
if not captured.exists():
    class Capture(BaseHTTPRequestHandler):
        def do_POST(self):
            v = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            if v['method'] == 'starknet_addInvokeTransaction':
                save(captured, v)
                res = {'jsonrpc': '2.0', 'id': v['id'], 'error': {'code': -32603, 'message': 'captured locally; not forwarded'}}
            else:
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
        sncast(f'simulate-{name}-{label}-sign', ['invoke', '--url', f'http://127.0.0.1:{server.server_port}', '--contract-address', load(RUN / 'deployment.json')['pool'],
                                                 '--function', 'apply_spend', '--calldata', *[h(x) for x in case['calldata']],
                                                 '--proof-file', str(folder / 'proof.base64'), '--proof-facts-file', str(folder / 'proof-facts.txt'),
                                                 *bounds(550_000_000)], HERE, expected_error=True)
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
tx = load(captured)['params']['invoke_transaction']
r = rpc('starknet_simulateTransactions', ['latest', [tx], []], timeout=300)[0]
save(RUN / 'results' / f'simulation-{name}-{label}.json', r)
t = r['transaction_trace']
ex = t['execute_invocation']
assert 'revert_reason' not in ex, ex['revert_reason'][:800]
res = {'account_class': rpc('starknet_getClassHashAt', ['latest', ACCOUNT]), 'total_l2_gas': t['execution_resources']['l2_gas'],
       'l1_data_gas': t['execution_resources']['l1_data_gas'], 'validate_l2_gas': t['validate_invocation']['execution_resources']['l2_gas'],
       'account_execute_l2_gas': ex['execution_resources']['l2_gas'], 'apply_spend_l2_gas': ex['calls'][0]['execution_resources']['l2_gas'],
       'fee_STRK': int(r['fee_estimation']['overall_fee'], 16) / 1e18, 'l2_gas_price': int(r['fee_estimation']['l2_gas_price'], 16)}
save(RUN / 'results' / f'simulation-{name}-{label}-summary.json', res)
print(json.dumps(res, indent=1))
