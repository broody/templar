#!/usr/bin/env bash
# Usage: run.sh PIE OUT_DIR [MEMORY_MAX]
# Proves PIE through the PROOF2 large path under a cgroup cap with zero swap and 4 pinned workers.
set -euo pipefail
pie=$(realpath "$1"); out=$(realpath -m "$2"); cap=${3:-115G}
bin=/home/broody/development/templar/target/proof2-large/proving/target/release/examples/prove_large
mkdir -p "$out"
sha256sum "$pie" "$bin" > "$out/inputs.sha256"
unit=templar-proof2-large-$(date +%s)
set +e
systemd-run --user --wait --pipe --unit="$unit" \
  -p MemoryMax="$cap" -p MemorySwapMax=0 -p CPUQuota=400% -p "CPUAffinity=0 1 2 3" \
  --setenv=RAYON_NUM_THREADS=4 \
  /usr/bin/time -v "$bin" "$pie" "$out" > "$out/run.log" 2>&1
code=$?
set -e
echo "exit_code=$code cap=$cap" >> "$out/run.log"
grep -E "Maximum resident|Elapsed|Memory peak|Memory swap peak|exit_code|Killed|verified|rejects|proof_bytes|leaf_verifier|prove_seconds" "$out/run.log" || true
