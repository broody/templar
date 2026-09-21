#!/usr/bin/env python3
"""Copy or verify the exact preserved native dependencies; never edit prior archives."""
from pathlib import Path
import hashlib
import json
import shutil

ROOT = Path(__file__).resolve().parents[3]
EXPECTED = json.loads(Path(__file__).with_name("dependency-source-manifest.json").read_text())
for family, files in EXPECTED.items():
    src = ROOT / "target/m31-tree" / family
    dst = ROOT / "target/m31-append" / family
    if not dst.exists():
        for relative, digest in files.items():
            source = src / relative
            assert hashlib.sha256(source.read_bytes()).hexdigest() == digest, source
        shutil.copytree(src, dst)
    for relative, digest in files.items():
        target = dst / relative
        assert hashlib.sha256(target.read_bytes()).hexdigest() == digest, target
print("Verified exact preserved stwo and stwo-cairo sources")
