#!/usr/bin/env python3
"""Create isolated reviewed sources, or validate existing copies without modifying them."""
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[3]
DEST = ROOT / "target/m31-tree"
PIN = "00fe0a985b398d3ef1f10d69543ca2b8f9f236da"


def inventory(directory):
    return {str(p.relative_to(directory)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(directory.rglob("*")) if p.is_file()}


def main():
    DEST.mkdir(parents=True, exist_ok=True)
    copied = {}
    for name in ["stwo", "stwo-cairo"]:
        source = ROOT / "target/wasm-membership" / name
        destination = DEST / name
        expected = inventory(source)
        if not destination.exists():
            shutil.copytree(source, destination)
        actual = inventory(destination)
        if actual != expected:
            raise SystemExit(f"Isolated {name} differs from its reviewed source")
        copied[name] = actual
    manifest = DEST / "copied-source-manifest.json"
    if manifest.exists():
        if json.loads(manifest.read_text()) != copied:
            raise SystemExit("Copied-source manifest mismatch")
    else:
        manifest.write_text(json.dumps(copied, indent=2) + "\n")

    upstream = DEST / "upstream-plonky3"
    if not upstream.exists():
        subprocess.run(["git", "clone", "https://github.com/Plonky3/Plonky3", str(upstream)], check=True)
        subprocess.run(["git", "-C", str(upstream), "checkout", "--detach", PIN], check=True)
    actual_pin = subprocess.check_output(["git", "-C", str(upstream), "rev-parse", "HEAD"], text=True).strip()
    if actual_pin != PIN:
        raise SystemExit(f"Wrong Plonky3 pin: {actual_pin}")

    reference = (upstream / "mersenne-31/src/poseidon2.rs").read_text()
    constants = (ROOT / "bench/m31-tree/client/src/constants.rs").read_text()
    for suffix, count in [("EXTERNAL_INITIAL", 96), ("EXTERNAL_FINAL", 96), ("INTERNAL", 22)]:
        source_section = reference.split(f"pub const MERSENNE31_POSEIDON2_RC_24_{suffix}:", 1)[1].split(";\n", 1)[0]
        local_section = constants.split(f"pub const {suffix}:", 1)[1].split(";\n", 1)[0]
        expected = [int(x, 16) for x in re.findall(r"0x[0-9a-fA-F]+", source_section)]
        actual = [int(x, 16) for x in re.findall(r"0x[0-9a-fA-F]+", local_section)]
        if len(expected) != count or actual != expected:
            raise SystemExit(f"Round constants mismatch: {suffix}")
    print("Reviewed copies, pinned Plonky3 checkout, and all 214 round constants match.")


if __name__ == "__main__":
    main()
