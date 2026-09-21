#!/bin/bash
# Serial browser proof driver (v2). Stop on first failure. One run at a time.
set -u
cd /home/broody/development/templar || exit 1
LOG=target/kimi-m31/browser-driver.log
: > "$LOG"

prog() { python3 - "$1" "$2" <<'EOF'
import json, sys, time
p = 'target/kimi-m31/progress.json'
d = json.load(open(p))
d['updated'] = time.strftime('%Y-%m-%dT%H:%M:%S%z')
d['stage'] = 'step4-browser-v2'
d.setdefault('runs', {})[sys.argv[1]] = sys.argv[2]
if sys.argv[2] != 'ok':
    d['blocker'] = f"{sys.argv[1]}: {sys.argv[2]}"
json.dump(d, open(p, 'w'), indent=2)
EOF
}

run() { # name cap repeats fixture reference
  local name=$1 cap=$2 rep=$3 fix=$4 ref=$5
  echo "=== $name start $(date -Is)" >> "$LOG"
  python3 bench/m31-tree/measure.py --name "$name" --cap-gib "$cap" --cpu-cores 4 --prover-workers 1 \
    --scope "headless Chrome WASM proof v2 ($rep request(s), one worker); browser+harness under ${cap} GiB cgroup, no swap, 4 CPU budget; not native/browser timing parity; no consumer-device qualification" \
    -- /usr/bin/node bench/m31-tree/run-browser.mjs "bench/m31-tree/results/$name/browser" "$rep" \
       target/m31-tree/pkg "bench/m31-tree/client/fixtures/$fix" "bench/m31-tree/results/$ref/proof/proof.bin" >> "$LOG" 2>&1
  local rc=$?
  if [ "$rc" -ne 0 ]; then
    prog "$name" "FAIL rc=$rc"
    echo "=== STOP $name rc=$rc $(date -Is)" >> "$LOG"
    exit 1
  fi
  prog "$name" "ok"
  echo "=== $name ok $(date -Is)" >> "$LOG"
}

run chrome-tree-v2-three-1g 1 3 tree-only.json native-tree-v2-1g-r1
run chrome-tree-v2-fresh-1g 1 1 tree-only.json native-tree-v2-1g-r1
run chrome-mixed-v2-three-3g 3 3 mixed.json native-mixed-v2-3g-r1
run chrome-mixed-v2-fresh-3g 3 1 mixed.json native-mixed-v2-3g-r1
echo "=== ALL BROWSER RUNS OK $(date -Is)" >> "$LOG"
