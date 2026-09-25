#!/usr/bin/env python3
"""Local server for the R0 V5 real-wallet signing page (spec §15 P3).

Serves index.html, a vendored starknet.js and the signing requests (kat/gen_sign_requests.cjs),
forwards a few read-only JSON-RPC methods to the local Sepolia pathfinder, and saves the results the
page posts. Binds to 127.0.0.1 only; sends nothing on chain.

Usage: serve.py REQUESTS.json RESULTS_DIR [PORT]
"""
import json
import re
import sys
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[4]
STARKNET_JS = REPO / "target/wallet-sig-spike/sign-live/starknet-10.8.0.global.js"
RPC = "http://127.0.0.1:9545/rpc/v0_9"
READ_ONLY = {"starknet_call", "starknet_getClassHashAt", "starknet_chainId", "starknet_blockNumber"}
REQUESTS = Path(sys.argv[1]).resolve()
RESULTS = Path(sys.argv[2]).resolve()
PORT = int(sys.argv[3]) if len(sys.argv) > 3 else 8766


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json"):
        self.send_response(code)
        self.send_header("content-type", ctype)
        self.send_header("cache-control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _local(self):
        """Refuse requests from other origins (AB-IP5): a DNS-rebinding page sends a foreign Host;
        a cross-site form or fetch sends a foreign Origin; only this page's JSON posts pass."""
        allowed = {f"localhost:{PORT}", f"127.0.0.1:{PORT}"}
        if self.headers.get("host") not in allowed:
            return False
        origin = self.headers.get("origin")
        return origin is None or origin in {f"http://{h}" for h in allowed}

    def do_GET(self):
        if not self._local():
            return self._send(403, b'{"error":"forbidden"}')
        if self.path in ("/", "/index.html"):
            self._send(200, (HERE / "index.html").read_bytes(), "text/html; charset=utf-8")
        elif self.path == "/starknet.js":
            self._send(200, STARKNET_JS.read_bytes(), "text/javascript")
        elif self.path == "/requests.json":
            self._send(200, REQUESTS.read_bytes())
        else:
            self._send(404, b"{}")

    def do_POST(self):
        if not self._local() or self.headers.get("content-type", "").split(";")[0].strip() != "application/json":
            return self._send(403, b'{"error":"forbidden"}')
        n = int(self.headers.get("content-length", 0))
        if n > 256 * 1024:
            return self._send(413, b'{"error":"too large"}')
        raw = self.rfile.read(n)
        try:
            req = json.loads(raw)
        except ValueError:
            return self._send(400, b'{"error":"bad json"}')
        if self.path == "/rpc":
            if req.get("method") not in READ_ONLY:
                return self._send(403, b'{"error":"method not allowed"}')
            fwd = urllib.request.Request(RPC, raw, {"content-type": "application/json"})
            with urllib.request.urlopen(fwd, timeout=30) as r:
                return self._send(200, r.read())
        if self.path == "/save":
            RESULTS.mkdir(parents=True, exist_ok=True)
            wallet = re.sub(r"[^A-Za-z0-9_-]", "", str(req.get("wallet", {}).get("id", "wallet")))[:32] or "wallet"
            acct = re.sub(r"[^0-9a-fx]", "", str(req.get("account", "")).lower())[:12]
            path = RESULTS / f"{wallet}-{acct}.json"
            path.write_text(json.dumps(req, indent=2) + "\n")
            print(f"saved {path}", flush=True)
            return self._send(200, json.dumps({"saved": str(path)}).encode())
        self._send(404, b"{}")

    def log_message(self, fmt, *args):
        sys.stderr.write("%s\n" % (fmt % args))


if __name__ == "__main__":
    print(f"http://localhost:{PORT}/", flush=True)
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
