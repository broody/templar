#!/usr/bin/env python3
"""Bounded native desktop benchmark. Linux systemd user manager is required."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
import uuid

ROOT = Path(__file__).resolve().parent

def stage(project, label, command, memory="6G", seconds=180):
    out = project / "results"
    out.mkdir(exist_ok=True)
    unit = "templar-bench-" + uuid.uuid4().hex[:12]
    args = ["systemd-run", "--user", "--wait", "--pipe", "--collect", "--unit", unit,
            "-p", f"WorkingDirectory={project}", "-p", f"MemoryMax={memory}",
            "-p", "MemorySwapMax=0", "-p", "CPUQuota=400%", "-p", "CPUAffinity=0 1 2 3",
            "-p", f"RuntimeMaxSec={seconds}", "--setenv=HARDWARE_CONCURRENCY=4",
            "--setenv=RAYON_NUM_THREADS=4", f"--setenv=PATH={os.environ['PATH']}",
            "/usr/bin/time", "-v", *command]
    start = time.monotonic()
    with (out / f"{label}.log").open("w") as log:
        result = subprocess.run(args, stdout=log, stderr=subprocess.STDOUT)
    log = (out / f"{label}.log").read_text()
    wall = re.search(r"Elapsed \(wall clock\) time \(h:mm:ss or m:ss\): ([\d:.]+)", log)
    wall_seconds = None
    if wall:
        wall_seconds = 0
        for part in wall[1].split(":"):
            wall_seconds = 60 * wall_seconds + float(part)
    rss = re.search(r"Maximum resident set size \(kbytes\): (\d+)", log)
    row = {"stage": label, "command": command, "exit_code": result.returncode,
           "wall_seconds": wall_seconds, "driver_wall_seconds": time.monotonic() - start,
           "max_rss_kib": int(rss[1]) if rss else None, "memory_limit": memory,
           "cpu_affinity": "0-3", "cpu_quota": "400%", "swap_limit": 0,
           "timeout_seconds": seconds,
           "systemd_result": (re.search(r"Finished with result: (\S+)", log)[1] if re.search(r"Finished with result: (\S+)", log) else None),
           "cgroup_peak": (re.search(r"Memory peak: ([^\n]+)", log)[1] if re.search(r"Memory peak: ([^\n]+)", log) else None)}
    print(json.dumps(row), flush=True)
    return row

def benchmark(project, name="bench", runs=3):
    project = Path(project).resolve()
    out = project / "results"
    out.mkdir(exist_ok=True)
    rows = []
    meta = {"project": str(project), "date_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "nargo": subprocess.check_output(["nargo", "--version"], text=True).strip(),
            "bb": subprocess.check_output(["bb", "--version"], text=True).strip(), "stages": rows}
    def record(label, cmd, memory="6G", seconds=180):
        row = stage(project, label, cmd, memory, seconds)
        rows.append(row)
        (out / "summary.json").write_text(json.dumps(meta, indent=2) + "\n")
        return row["exit_code"] == 0
    nargo, bb = shutil.which("nargo"), shutil.which("bb")
    artifact = project / "target" / f"{name}.json"
    common = ["-s", "ultra_honk", "--oracle_hash", "keccak"]
    # Compilation is an offline developer step with a separate, bounded budget.
    if not record("compile", [nargo, "compile", "--force"], "32G", 300):
        return meta
    if not record("witness", [nargo, "execute", "witness"]):
        return meta
    if not record("gates", [bb, "gates", *common, "-b", str(artifact)]):
        return meta
    gate_log = (out / "gates.log").read_text()
    meta["gates"], _ = json.JSONDecoder().raw_decode(gate_log[gate_log.index("{"):])
    if not record("write_vk", [bb, "write_vk", *common, "-b", str(artifact), "-o", str(out)]):
        return meta
    for i in range(1, runs + 1):
        if not record(f"prove-{i}", [bb, "prove", *common, "-b", str(artifact),
                "-w", str(project / "target/witness.gz"), "-k", str(out / "vk"), "-o", str(out)]):
            return meta
        if not record(f"verify-{i}", [bb, "verify", *common, "-v", "-k", str(out / "vk"),
                "-p", str(out / "proof"), "-i", str(out / "public_inputs")]):
            return meta
    meta["files"] = {p.name: {"bytes": p.stat().st_size,
        "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
        for p in [artifact, project / "target/witness.gz", out / "proof", out / "vk", out / "public_inputs"]}
    meta["completed"] = True
    (out / "summary.json").write_text(json.dumps(meta, indent=2) + "\n")
    return meta

if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("project", type=Path)
    p.add_argument("--name", default="bench")
    p.add_argument("--runs", type=int, default=3)
    args = p.parse_args()
    if args.runs < 1:
        p.error("--runs must be positive")
    result = benchmark(args.project, args.name, args.runs)
    raise SystemExit(0 if result.get("completed") else 1)
