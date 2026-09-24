#!/usr/bin/env bash
# Spec §11 pre-check test (PI-7): every R0 V4 bench proof, honest and forged, through
# `templar-prover check`, which executes the compiled bridge; honest shapes must be accepted and
# each forged statement rejected with the bridge's own reason (the verdicts of
# bench/m31-private-wrapper/client-port/validate_bridge_r4.py).
# Usage: check_bench_proofs.sh CONFIG PROOFS_DIR   (PROOFS_DIR: prove_payment_r4 outputs by shape)
set -euo pipefail
cfg=$1; proofs=$2
bin=${TEMPLAR_PROVER:-$(dirname "$0")/../prover/target/release/templar-prover}
work=$(mktemp -d "${TMPDIR:-$HOME/.local/share/templar/runs}/check-bench-XXXXXX"); trap 'rm -rf "$work"' EXIT
declare -A expect=([forge-voluntary-reveal]="exit rule" [forge-zero-delivery]="delivery" [forge-recipient-only]="withdrawal"
  [forge-identity-no-intent]="identity intent" [forge-duplicate-nullifier]="duplicate nullifier"
  [forge-asset-range]="address range" [forge-recipient-range]="address range" [forge-zero-chain]="zero context")
fail=0
for d in "$proofs"/*/; do
  name=$(basename "$d")
  python3 -c "import json,sys; json.dump({'relation':'r4','proof':json.load(open('$d/cairo-arguments.json')),'statement':json.load(open('$d/public.json'))}, open('$work/$name.json','w'))"
  out=$("$bin" check "$cfg" "$work/$name.json" --skip-chain-state 2>&1 | tail -1 || true)
  if [[ -n "${expect[$name]:-}" ]]; then
    [[ "$out" == *"Error: bridge"*"${expect[$name]}"* ]] && r=ok || { r=FAIL; fail=1; }
  else
    [[ "$out" == *'"accepted":true'* ]] && r=ok || { r=FAIL; fail=1; }
  fi
  echo "$r $name: ${out:0:140}"
done
exit $fail
