#!/usr/bin/env bash
# Builds the WASM core for the TypeScript package (docs/sdk-spec.md §13): the release artifact
# (ts/wasm) and the separately named test artifact with seeded exports (ts/wasm-test), then
# checks the release artifact exports no seeded function (SDK-M13, SDK-P12).
set -euo pipefail
SDK="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="${CARGO_TARGET_DIR:-$HOME/.local/share/templar/build/sdk}"
WASM_BINDGEN="${WASM_BINDGEN:-wasm-bindgen}"
"$SDK/scripts/check-pins.sh" || [ -n "${TEMPLAR_DEV:-}" ]
cd "$SDK"
CARGO_TARGET_DIR="$TARGET" cargo build --locked --release -p templar-wasm --target wasm32-unknown-unknown
CARGO_TARGET_DIR="$TARGET/test-rng" cargo build --locked --release -p templar-wasm --features test-rng --target wasm32-unknown-unknown
"$WASM_BINDGEN" --target web --out-dir ts/wasm --out-name templar "$TARGET/wasm32-unknown-unknown/release/templar_wasm.wasm"
"$WASM_BINDGEN" --target web --out-dir ts/wasm-test --out-name templar_test "$TARGET/test-rng/wasm32-unknown-unknown/release/templar_wasm.wasm"
# libbz2-rs-sys (via cairo-air, the proof serializer's dependency) exports C symbols whose names
# contain dots; quote them so the generated declarations parse.
for f in ts/wasm/templar.d.ts ts/wasm-test/templar_test.d.ts; do
  sed -i -E 's/readonly (LIBBZ2_[A-Za-z0-9_.]+):/readonly "\1":/' "$f"
done
if grep -q "export function test_" ts/wasm/templar.js; then
  echo "build-wasm: the release artifact exports seeded functions" >&2
  exit 1
fi
sha256sum ts/wasm/templar_bg.wasm | tee ts/wasm/SHA256SUM
