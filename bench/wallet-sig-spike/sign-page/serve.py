#!/usr/bin/env python3
"""P0b spike (throwaway): serve the signing page on localhost, plus a READ-ONLY JSON-RPC proxy.

The page's optional check calls starknet_getClassHashAt and the account's is_valid_signature
(starknet_call). The local pathfinder sends no CORS headers, so the browser cannot call it
directly; this server forwards same-origin POSTs to it instead. Only the read methods in ALLOWED
are forwarded (single requests, no batches), so nothing can be submitted through it.

  python3 serve.py                      # http://localhost:8000/
  python3 serve.py --port 8123 --sepolia-rpc http://127.0.0.1:9545/rpc/v0_9

Plain `python3 -m http.server 8000 --bind 127.0.0.1` also serves the page; only the read-only
check is then unavailable.
"""
import argparse
import functools
import http.server
import json
import os
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ALLOWED = {
    "starknet_chainId",
    "starknet_specVersion",
    "starknet_blockNumber",
    "starknet_getClassHashAt",
    "starknet_call",
}
MAX_BODY = 64 * 1024


class Handler(http.server.SimpleHTTPRequestHandler):
    extensions_map = {
        **http.server.SimpleHTTPRequestHandler.extensions_map,
        ".mjs": "text/javascript",
        ".js": "text/javascript",
        ".json": "application/json",
    }

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def _json(self, status, obj):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _rpc_error(self, status, rid, message):
        self._json(status, {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": message}})

    def do_POST(self):
        route = self.path.split("?", 1)[0]
        upstream = self.server.routes.get(route)
        if not upstream:
            return self._rpc_error(404, None, f"no RPC route {route}")
        origin = self.headers.get("Origin")
        if origin and origin not in self.server.allowed_origins:
            return self._rpc_error(403, None, f"origin {origin} not allowed")
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > MAX_BODY:
            return self._rpc_error(413, None, "empty or oversized body")
        try:
            req = json.loads(self.rfile.read(length))
        except ValueError:
            return self._rpc_error(400, None, "invalid JSON")
        if not isinstance(req, dict):
            return self._rpc_error(403, None, "batch requests are not forwarded")
        rid, method = req.get("id"), req.get("method")
        if method not in ALLOWED:
            return self._rpc_error(403, rid, f"method {method!r} is not allowed by the read-only proxy")
        fwd = json.dumps(
            {"jsonrpc": "2.0", "id": rid if rid is not None else 1, "method": method, "params": req.get("params", [])}
        ).encode()
        up = urllib.request.Request(upstream, data=fwd, headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(up, timeout=30) as r:
                status, body = r.status, r.read()
        except urllib.error.HTTPError as e:
            status, body = e.code, e.read()
        except (urllib.error.URLError, OSError) as e:
            return self._rpc_error(502, rid, f"upstream {upstream} unreachable: {e}")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--bind", default="127.0.0.1")
    ap.add_argument("--sepolia-rpc", default="http://127.0.0.1:9545/rpc/v0_9")
    ap.add_argument("--mainnet-rpc", default="http://127.0.0.1:9546/rpc/v0_9")
    a = ap.parse_args()
    srv = http.server.ThreadingHTTPServer((a.bind, a.port), functools.partial(Handler, directory=HERE))
    srv.routes = {"/rpc/sepolia": a.sepolia_rpc, "/rpc/mainnet": a.mainnet_rpc}
    srv.allowed_origins = {f"http://localhost:{a.port}", f"http://127.0.0.1:{a.port}"}
    print(f"Serving {HERE} on http://localhost:{a.port}/  (read-only RPC: {srv.routes})", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
