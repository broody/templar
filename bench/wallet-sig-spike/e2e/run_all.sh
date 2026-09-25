#!/usr/bin/env bash
# P0b spike (throwaway): R4 + Stark owner signature over SNIP-12, virtual-OS captures and
# resource analysis. Local only: synthetic state fixture on loopback, no RPC to a real node,
# nothing on chain, no proving. Outputs under target/wallet-sig-spike/e2e (must be fresh).
set -euo pipefail
ROOT=/home/broody/development/templar
HERE=$ROOT/bench/wallet-sig-spike/e2e
E=${E:-$ROOT/target/wallet-sig-spike/e2e}
PROOF_SRC=${PROOF_SRC:-$HOME/.local/share/templar/runs/r4-proofs/full}
export PATH=$HOME/.asdf/installs/scarb/2.18.0/bin:$PATH
cd "$ROOT"
mkdir -p "$E/captures"

# 1. Workspace: copy of target/bridge-r4 + account_sig + snip12; build both account classes.
python3 "$HERE/build_e2e.py" "$E/work" > "$E/build.log" 2>&1

# 2. The R4 client proof (withdrawal shape `full`, circuit hash pinned by target/bridge-r4).
mkdir -p "$E/proof"
cp "$PROOF_SRC"/{cairo-arguments.json,public.json,report.json,trusted-config.json} "$E/proof/"

# 3. SNIP-12 TemplarSpend hash and a fresh Stark key signature (private key never written).
node "$HERE/sign_spend.cjs" "$E/proof/public.json" "$E/sign"

# 4. Virtual-OS captures: baseline, spike, negative (owner signature over valid_until + 1).
C=$E/work/target/contract
python3 "$HERE/capture_os.py" --sierra "$C/templar_membership_account_PaymentVerifierAccount.contract_class.json" \
  --proof-dir "$E/proof" --public "$E/proof/public.json" --output "$E/captures/baseline" > "$E/captures/baseline.log" 2>&1
python3 "$HERE/capture_os.py" --sierra "$C/templar_wallet_sig_account_WalletSigSpikeAccount.contract_class.json" \
  --proof-dir "$E/proof" --public "$E/proof/public.json" --auth "$E/sign/auth-spike.json" \
  --output "$E/captures/spike" > "$E/captures/spike.log" 2>&1
python3 "$HERE/capture_os.py" --sierra "$C/templar_wallet_sig_account_WalletSigSpikeAccount.contract_class.json" \
  --proof-dir "$E/proof" --public "$E/proof/public.json" --auth "$E/sign/auth-negative.json" \
  --output "$E/captures/negative" --expect-reject > "$E/captures/negative.log" 2>&1

# 5. Component trace sizes, Blake attribution, summary.json.
python3 "$HERE/analyze_pies.py" "$E" baseline spike > "$E/analysis.log" 2>&1
tail -1 "$E/analysis.log"
