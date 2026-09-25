#!/usr/bin/env python3
"""P0b spike (throwaway): tests for serve.py (static files + read-only RPC proxy).

  python3 bench/wallet-sig-spike/sign-page/test/test_serve.py [--live]

A recording fake upstream stands in for the node, so the test can prove that only the allowed
read methods are ever forwarded. --live also forwards one starknet_chainId to the local Sepolia
pathfinder (http://127.0.0.1:9545/rpc/v0_9), read-only.
"""
import http.server
import json
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
SERVE = os.path.join(os.path.dirname(HERE), "serve.py")
LIVE = "--live" in sys.argv

received = []


class FakeNode(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        received.append(body["method"])
        out = json.dumps({"jsonrpc": "2.0", "id": body["id"], "result": "0x534e5f5345504f4c4941"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):
        pass


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def post(url, obj, origin=None, raw=None):
    data = raw if raw is not None else json.dumps(obj).encode()
    headers = {"Content-Type": "application/json"}
    if origin:
        headers["Origin"] = origin
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def main():
    fake = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FakeNode)
    threading.Thread(target=fake.serve_forever, daemon=True).start()
    fake_url = f"http://127.0.0.1:{fake.server_address[1]}/rpc"
    port = free_port()
    sepolia = "http://127.0.0.1:9545/rpc/v0_9" if LIVE else fake_url
    proc = subprocess.Popen(
        [sys.executable, SERVE, "--port", str(port), "--sepolia-rpc", sepolia, "--mainnet-rpc", fake_url],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    base = f"http://127.0.0.1:{port}"
    try:
        for _ in range(50):
            try:
                urllib.request.urlopen(base + "/index.html", timeout=1)
                break
            except OSError:
                time.sleep(0.1)
        results = []

        def check(name, cond, detail=""):
            results.append(cond)
            print(f"{'ok  ' if cond else 'FAIL'} {name}{'  (' + detail + ')' if detail else ''}")

        with urllib.request.urlopen(base + "/index.html") as r:
            check("GET /index.html", r.status == 200 and "text/html" in r.headers["Content-Type"])
        with urllib.request.urlopen(base + "/sign-logic.mjs") as r:
            ct = r.headers["Content-Type"]
            check("GET /sign-logic.mjs is served as JavaScript", ct.startswith("text/javascript"), ct)

        # Allowed read method is forwarded (mainnet route -> fake node).
        st, body = post(base + "/rpc/mainnet", {"jsonrpc": "2.0", "id": 7, "method": "starknet_chainId", "params": []})
        check("allowed method forwarded", st == 200 and body.get("result") and received == ["starknet_chainId"], str(body))

        # Write / unknown methods are refused and never reach the node.
        before = list(received)
        for m in ["starknet_addInvokeTransaction", "starknet_addDeclareTransaction",
                  "starknet_addDeployAccountTransaction", "starknet_estimateFee", "starknet_getStorageAt", None]:
            st, body = post(base + "/rpc/mainnet", {"jsonrpc": "2.0", "id": 1, "method": m, "params": []})
            check(f"refused {m}", st == 403 and "error" in body)
        st, body = post(base + "/rpc/mainnet", [{"jsonrpc": "2.0", "id": 1, "method": "starknet_chainId"}])
        check("refused batch request", st == 403)
        st, body = post(base + "/rpc/mainnet", {"method": "starknet_chainId"}, origin="https://evil.example")
        check("refused foreign Origin", st == 403)
        st, body = post(base + "/rpc/mainnet", None, raw=b"{not json")
        check("refused invalid JSON", st == 400)
        st, body = post(base + "/rpc/other", {"method": "starknet_chainId"})
        check("unknown route 404", st == 404)
        check("nothing refused reached the node", received == before, str(received))

        st, body = post(base + "/rpc/mainnet", {"jsonrpc": "2.0", "id": 2, "method": "starknet_chainId"},
                        origin=f"http://localhost:{port}")
        check("same-origin (localhost) allowed", st == 200)

        if LIVE:
            st, body = post(base + "/rpc/sepolia", {"jsonrpc": "2.0", "id": 3, "method": "starknet_chainId", "params": []})
            check("live: /rpc/sepolia -> local pathfinder chain id", st == 200 and body.get("result") == "0x534e5f5345504f4c4941",
                  str(body.get("result")))

        print(f"\n{sum(results)} passed, {len(results) - sum(results)} failed")
        return 0 if all(results) else 1
    finally:
        proc.terminate()
        proc.wait(timeout=5)
        fake.shutdown()


if __name__ == "__main__":
    sys.exit(main())
