#!/bin/bash
# Serial native proof driver for the frozen v2 binary. Stop on first failure.
# No builds; one run at a time. Progress to target/kimi-m31/progress.json.
set -u
cd /home/broody/development/templar || exit 1
BIN=$PWD/target/m31-tree/client-target/release/templar-m31-tree
F=bench/m31-tree/client/fixtures
LOG=target/kimi-m31/native-driver.log
: > "$LOG"

prog() { python3 - "$1" "$2" <<'EOF'
import json, sys, time
p = 'target/kimi-m31/progress.json'
d = json.load(open(p))
d['updated'] = time.strftime('%Y-%m-%dT%H:%M:%S%z')
d['stage'] = 'step3-native-v2'
d.setdefault('runs', {})[sys.argv[1]] = sys.argv[2]
if sys.argv[2] != 'ok':
    d['blocker'] = f"{sys.argv[1]}: {sys.argv[2]}"
json.dump(d, open(p, 'w'), indent=2)
EOF
}

run() { # name cap_gib fixture scope
  local name=$1 cap=$2 fix=$3 scope=$4
  echo "=== $name start $(date -Is)" >> "$LOG"
  python3 bench/m31-tree/measure.py --name "$name" --cap-gib "$cap" --cpu-cores 1 --prover-workers 1 \
    --scope "$scope" -- "$BIN" "$F/$fix" "bench/m31-tree/results/$name/proof" >> "$LOG" 2>&1
  local rc=$?
  local files
  files=$(ls "bench/m31-tree/results/$name/proof" 2>/dev/null | wc -l)
  if [ "$rc" -ne 0 ] || [ "$files" -eq 0 ]; then
    prog "$name" "FAIL rc=$rc proof_files=$files"
    echo "=== STOP $name rc=$rc proof_files=$files $(date -Is)" >> "$LOG"
    exit 1
  fi
  prog "$name" "ok"
  echo "=== $name ok $(date -Is)" >> "$LOG"
}

run native-tree-v2-1g-r1 1 tree-only.json "tree-only native proof v2: 2 public depth-32 M31 paths, 130 permutations padded to 256 rows, lifting log 11; 1 GiB cgroup, no swap, 1 pinned CPU, 1 prover worker"
run native-tree-v2-1g-r2 1 tree-only.json "tree-only native proof v2 repeat 2; same fixture/caps as r1; deterministic-fixture runtime stability, not a PoW distribution"
run native-tree-v2-1g-r3 1 tree-only.json "tree-only native proof v2 repeat 3; same fixture/caps as r1"
run native-mixed-v2-3g-r1 3 mixed.json "mixed native proof v2: M31 tree plus 17 felt252 hash calls / 62 Hades permutations union workload, lifting log 23; 3 GiB cgroup, no swap, 1 pinned CPU, 1 prover worker"
run native-mixed-v2-3g-r2 3 mixed.json "mixed native proof v2 repeat 2; same fixture/caps as r1"
run native-mixed-v2-3g-r3 3 mixed.json "mixed native proof v2 repeat 3; same fixture/caps as r1"
run native-mixed-v2-2g-r1 2 mixed.json "mixed native proof v2 2 GiB probe r1; same workload, tighter cap"
run native-mixed-v2-2g-r2 2 mixed.json "mixed native proof v2 2 GiB probe r2; fresh-process repetition after r1 success"
echo "=== ALL NATIVE RUNS OK $(date -Is)" >> "$LOG"
