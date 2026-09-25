#!/usr/bin/env bash
# P0b spike (throwaway): prove one virtual-OS PIE with the prover server's templar-prove under a
# systemd CPU cap, one run at a time. Usage: run_prove.sh NAME PIE CPUS  (CPUS = 8 or 16)
# Output: target/wallet-sig-spike/measure/NAME/{os.pie.zip,run.log,proof.bin,prove-result.json,...}
set -euo pipefail
NAME=$1; PIE=$2; CPUS=$3
ROOT=/home/broody/development/templar
PROVE=$ROOT/server/prove/target/release/templar-prove
OUT=$ROOT/target/wallet-sig-spike/measure/$NAME
case $CPUS in 8) AFF="0-7";; 16) AFF="0-15";; *) echo "CPUS must be 8 or 16"; exit 2;; esac
# Refuse to start while a build, test or prover is running.
while pgrep -a -f 'cargo|rustc|scarb|snforge|templar-prove|prove_large|capacity|capture' | grep -v -e pgrep -e run_prove.sh; do
  echo "waiting for the processes above to finish"; sleep 20
done
mkdir -p "$OUT"; cp "$PIE" "$OUT/os.pie.zip"
sha256sum "$OUT/os.pie.zip" > "$OUT/pie.sha256"
uptime > "$OUT/pre-uptime.txt"; free -m > "$OUT/pre-free.txt"
UNIT=wsig-$NAME-$(date +%s)
set +e
systemd-run --user --wait --pipe --unit="$UNIT" -p CPUAffinity="$AFF" -p CPUQuota=$((CPUS*100))% \
  /usr/bin/time -v "$PROVE" prove "$OUT" > "$OUT/run.log" 2>&1
echo "exit=$?" >> "$OUT/run.log"
set -e
[ -f "$OUT/proof.bin" ] && sha256sum "$OUT/proof.bin" > "$OUT/proof.sha256"
tail -n 30 "$OUT/run.log"
