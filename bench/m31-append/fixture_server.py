"""Read-only RPC transport for a separately reviewed, authenticated public fixture.

This transports precomputed canonical data. It does not calculate state roots,
verify proofs, register facts, or forward requests to any other service.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import argparse
import hashlib
import json
import threading


class RpcError(Exception):
    def __init__(self, code, message):
        self.code, self.message = code, message


def felt(value):
    return hex(int(value, 16) if isinstance(value, str) else int(value))


class FixtureRpc:
    def __init__(self, path, expected_sha):
        raw = path.read_bytes()
        actual = hashlib.sha256(raw).hexdigest()
        if actual != expected_sha:
            raise ValueError('fixture file does not match the externally pinned SHA256')
        self.data = json.loads(raw)
        self.sha256 = actual

    def block_id(self, value):
        block = self.data['block']
        accepted = value == 'latest' or value == {'block_number': block['block_number']}
        if isinstance(value, dict) and 'block_hash' in value:
            accepted = felt(value['block_hash']) == felt(block['block_hash'])
        if not accepted:
            raise RpcError(24, 'Block not found in immutable synthetic fixture')

    def contract(self, address, required=True):
        entry = self.data['contracts'].get(felt(address))
        if entry is None and required:
            raise RpcError(20, 'Contract not found')
        return entry

    def dispatch(self, method, params):
        if params == []:
            params = {}
        if not isinstance(params, dict):
            raise RpcError(-32602, 'Named parameters required')
        if method == 'starknet_specVersion':
            return '0.10.0'
        if method == 'starknet_chainId':
            return self.data['chain_id']
        if method == 'starknet_blockNumber':
            return self.data['block']['block_number']
        if method == 'starknet_blockHashAndNumber':
            return {k: self.data['block'][k] for k in ('block_hash', 'block_number')}
        if method == 'starknet_getCompiledCasm':
            entry = self.data['classes'].get(felt(params['class_hash']))
            if entry is None:
                raise RpcError(28, 'Class hash not found')
            return entry['casm']
        if method in ('starknet_getBlockWithTxHashes', 'starknet_getBlockWithTxs',
                      'starknet_getClass', 'starknet_getClassAt', 'starknet_getClassHashAt',
                      'starknet_getNonce', 'starknet_getStorageAt', 'starknet_getStorageProof'):
            self.block_id(params['block_id'])
        else:
            raise RpcError(-32601, 'Method unavailable on read-only synthetic fixture')
        if method in ('starknet_getBlockWithTxHashes', 'starknet_getBlockWithTxs'):
            return self.data['block']
        if method == 'starknet_getClass':
            entry = self.data['classes'].get(felt(params['class_hash']))
            if entry is None:
                raise RpcError(28, 'Class hash not found')
            return entry['rpc_class']
        if method == 'starknet_getStorageProof':
            proof = self.data['storage_proof']
            addresses = params.get('contract_addresses', [])
            leaves = []
            for address in addresses:
                entry = self.contract(address, required=False)
                leaves.append(entry['leaf'] if entry else {
                    'class_hash': '0x0', 'nonce': '0x0', 'storage_root': '0x0'})
            storage_nodes = []
            for query in params.get('contracts_storage_keys', []):
                entry = self.contract(query['contract_address'], required=False)
                storage_nodes.append(entry['storage_proof'] if entry else [])
            return {'classes_proof': proof['classes_proof'],
                    'contracts_proof': {'nodes': proof['contracts_proof']['nodes'],
                                        'contract_leaves_data': leaves},
                    'contracts_storage_proofs': storage_nodes,
                    'global_roots': proof['global_roots']}
        contract = self.contract(params['contract_address'])
        if method == 'starknet_getClassAt':
            return self.data['classes'][contract['leaf']['class_hash']]['rpc_class']
        if method == 'starknet_getClassHashAt':
            return contract['leaf']['class_hash']
        if method == 'starknet_getNonce':
            return contract['leaf']['nonce']
        if method == 'starknet_getStorageAt':
            return contract['storage'].get(felt(params['key']), '0x0')
        raise AssertionError(method)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--fixture', required=True, type=Path)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--port', required=True, type=int)
    parser.add_argument('--log', required=True, type=Path)
    args = parser.parse_args()
    fixture = FixtureRpc(args.fixture, args.sha256)
    args.log.parent.mkdir(parents=True, exist_ok=True)
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):
            length = int(self.headers.get('Content-Length', '0'))
            if length <= 0 or length > 8 * 1024 * 1024:
                self.send_error(413)
                return
            request = {}
            try:
                request = json.loads(self.rfile.read(length))
                result = fixture.dispatch(request['method'], request.get('params', {}))
                reply = {'jsonrpc': '2.0', 'id': request.get('id'), 'result': result}
            except RpcError as exc:
                reply = {'jsonrpc': '2.0', 'id': request.get('id'),
                         'error': {'code': exc.code, 'message': exc.message}}
            except (KeyError, ValueError, TypeError) as exc:
                reply = {'jsonrpc': '2.0', 'id': request.get('id'),
                         'error': {'code': -32602, 'message': str(exc)}}
            body = json.dumps(reply).encode()
            record = {'request': request, 'response_sha256': hashlib.sha256(body).hexdigest(),
                      'response_bytes': len(body), 'error': reply.get('error')}
            with lock, args.log.open('a') as log:
                log.write(json.dumps(record) + '\n')
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    print(json.dumps({'scope': 'synthetic local trust anchor; no network finality',
                      'fixture_sha256': fixture.sha256, 'port': args.port}), flush=True)
    ThreadingHTTPServer(('127.0.0.1', args.port), Handler).serve_forever()


if __name__ == '__main__':
    main()
