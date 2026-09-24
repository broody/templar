#!/usr/bin/env bash
# Usage: run.sh PIE OUT_DIR [MEMORY_MAX]
# Proves PIE through the PROOF2 large path under a cgroup cap with zero swap and 4 pinned workers.
#
# Bounded-memory storage is on by default (FRI batches of 16 columns in both stages; `bounded/`),
# which gives byte-identical proofs at ~28 GiB instead of ~51 GiB peak. Override per stage with
# TEMPLAR_BOUNDED_CAIRO_COLUMNS / TEMPLAR_BOUNDED_CIRCUIT_COLUMNS (0 = default storage). The
# binary is the bounded server build (`target/proving-server-target`, built with
# RUSTFLAGS="-C target-cpu=native"; without it the prover is ~1.7x slower); TEMPLAR_PROOF2_BIN
# overrides it.
set -euo pipefail
pie=$(realpath "$1"); out=$(realpath -m "$2"); cap=${3:-115G}
bin=${TEMPLAR_PROOF2_BIN:-/home/broody/development/templar/target/proving-server-target/release/examples/prove_large}
cairo=${TEMPLAR_BOUNDED_CAIRO_COLUMNS:-16}
circuit=${TEMPLAR_BOUNDED_CIRCUIT_COLUMNS:-16}
mkdir -p "$out"
sha256sum "$pie" "$bin" > "$out/inputs.sha256"
unit=templar-proof2-large-$(date +%s)
set +e
systemd-run --user --wait --pipe --unit="$unit" \
  -p MemoryMax="$cap" -p MemorySwapMax=0 -p CPUQuota=400% -p "CPUAffinity=0 1 2 3" \
  --setenv=RAYON_NUM_THREADS=4 --setenv=TEMPLAR_BOUNDED_CAIRO_COLUMNS="$cairo" \
  --setenv=TEMPLAR_BOUNDED_CIRCUIT_COLUMNS="$circuit" \
  /usr/bin/time -v "$bin" "$pie" "$out" > "$out/run.log" 2>&1
code=$?
set -e
echo "exit_code=$code cap=$cap bounded_cairo=$cairo bounded_circuit=$circuit" >> "$out/run.log"
grep -E "Maximum resident|Elapsed|Memory peak|Memory swap peak|exit_code|Killed|verified|rejects|proof_bytes|leaf_verifier|prove_seconds" "$out/run.log" || true
