#!/bin/bash
# Serial Cairo cost-matrix driver: felt/m31 x cold/warm x 1/2/4/8.
# Frozen sources; explicit Scarb 2.18.0 / snforge 0.63.0; stop on failure.
set -u
ROOT=/home/broody/development/templar
cd "$ROOT/bench/m31-tree/cairo" || exit 1
export PATH="/home/broody/.asdf/installs/scarb/2.18.0/bin:$HOME/.local/bin:$PATH"
SNFORGE=/home/broody/.asdf/installs/starknet-foundry/0.63.0/bin/snforge
LOG=$ROOT/target/kimi-m31/cairo-driver.log
: > "$LOG"

prog() { python3 - "$1" "$2" <<'EOF'
import json, sys, time
p = '/home/broody/development/templar/target/kimi-m31/progress.json'
d = json.load(open(p))
d['updated'] = time.strftime('%Y-%m-%dT%H:%M:%S%z')
d['stage'] = 'step2-cairo-cost'
d.setdefault('runs', {})[sys.argv[1]] = sys.argv[2]
if sys.argv[2] != 'ok':
    d['blocker'] = f"{sys.argv[1]}: {sys.argv[2]}"
json.dump(d, open(p, 'w'), indent=2)
EOF
}

for type in felt m31; do
  for state in cold warm; do
    for n in 1 2 4 8; do
      test=cost_${type}_${state}_${n}
      name=cairo-final-${type}-${state}-${n}
      out=$ROOT/bench/m31-tree/results/$name
      mkdir -p "$out"
      unit=templar-m31-${name}-$(date +%s)
      argv=("$SNFORGE" test --exact m31_tree_bench::tests::$test --max-threads 1 --max-n-steps 80000000 --detailed-resources --gas-report --trace-components gas)
      echo "=== $name start $(date -Is)" >> "$LOG"
      systemd-run --user --wait --pipe --unit="$unit" -p WorkingDirectory="$ROOT/bench/m31-tree/cairo" \
        -p MemoryMax=8G -p MemorySwapMax=0 -p RuntimeMaxSec=300 -p CPUQuota=400% -p CPUAffinity="0 1 2 3" \
        --setenv=PATH="$PATH" "${argv[@]}" > "$out/snforge.log" 2>&1
      rc=$?
      systemctl --user show "$unit" -p MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec,CPUAffinity,CPUUsageNSec,Result > "$out/cgroup.txt" 2>/dev/null
      python3 - "$out" "$test" "$unit" "$rc" "${argv[@]}" <<'EOF'
import json, sys
out, test, unit, rc = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
json.dump({'test': test, 'argv': sys.argv[5:], 'exit_code': rc, 'unit': unit,
           'caps': {'MemoryMax': '8G', 'MemorySwapMax': '0', 'RuntimeMaxSec': 300, 'CPUQuota': '400%', 'CPUAffinity': '0 1 2 3'},
           'note': 'cgroup.txt records systemd unit properties only; post-exit MemoryPeak is not a Cairo RAM measurement'},
          open(out + '/run.json', 'w'), indent=2)
EOF
      if [ "$rc" -ne 0 ]; then
        prog "$name" "FAIL rc=$rc"
        echo "=== STOP $name rc=$rc $(date -Is)" >> "$LOG"
        exit 1
      fi
      prog "$name" "ok"
      echo "=== $name ok $(date -Is)" >> "$LOG"
    done
  done
done
echo "=== ALL CAIRO CELLS OK $(date -Is)" >> "$LOG"
