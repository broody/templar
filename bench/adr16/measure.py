#!/usr/bin/env python3
"""Measure an already-compiled circuit; retain raw logs and proof artifacts."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import time

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--project", type=Path, default=Path(__file__).resolve().parent)
parser.add_argument("--name", default="felt252_poseidon")
parser.add_argument("--runs", type=int, default=3)
args = parser.parse_args()
if args.runs < 1:
    parser.error("--runs must be positive")
project = args.project.resolve()
out = project / "results"
out.mkdir(exist_ok=True)
env = dict(os.environ, HARDWARE_CONCURRENCY="32")

def run(label, command):
    with (out / f"{label}.log").open("w") as log:
        start = time.monotonic()
        subprocess.run(command, cwd=project, env=env, stdout=log,
                       stderr=subprocess.STDOUT, check=True)
    return time.monotonic() - start

bytecode = project / "target" / f"{args.name}.json"
witness = project / "target/witness.gz"
common = ["-s", "ultra_honk", "--oracle_hash", "keccak"]
run("gates", ["bb", "gates", *common, "-b", str(bytecode)])
run("write_vk", ["bb", "write_vk", *common, "-b", str(bytecode), "-o", str(out)])
times = []
for index in range(args.runs):
    times.append(run(f"prove-{index + 1}", ["/usr/bin/time", "-v", "bb", "prove",
        *common, "-b", str(bytecode), "-w", str(witness), "-k", str(out / "vk"),
        "-o", str(out)]))
    run(f"verify-{index + 1}", ["bb", "verify", *common, "-v", "-k", str(out / "vk"),
        "-p", str(out / "proof"), "-i", str(out / "public_inputs")])
files = {name: {"bytes": (out / name).stat().st_size,
                "sha256": hashlib.sha256((out / name).read_bytes()).hexdigest()}
         for name in ("proof", "public_inputs", "vk")}
gate_log = (out / "gates.log").read_text()
gates, _ = json.JSONDecoder().raw_decode(gate_log[gate_log.index("{"):])
result = {
    "date_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "platform": platform.platform(), "threads": 32,
    "nargo": subprocess.check_output(["nargo", "--version"], text=True).strip(),
    "bb": subprocess.check_output(["bb", "--version"], text=True).strip(),
    "gates": gates,
    "prove_wall_seconds": times, "median_prove_wall_seconds": statistics.median(times),
    "timing_scope": "bb prove process including proving-key construction; excludes compilation, witness, write_vk and native verification; cached CRS",
    "files": files,
    "native_verification": "passed for every run",
    "bytecode_sha256": hashlib.sha256(bytecode.read_bytes()).hexdigest(),
}
(out / "summary.json").write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps(result, indent=2))
