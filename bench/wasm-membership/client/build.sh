#!/usr/bin/env bash
set -euo pipefail
TASK_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)"
TASK_MANIFEST="$TASK_ROOT/bench/wasm-membership/client/Cargo.toml"
TASK_ARTIFACTS="$TASK_ROOT/target/wasm-membership"
TASK_RUSTUP_ROOT="${TEMPLAR_RUSTUP_ROOT:-/tmp/templar-stwo-privacy-dtgn6e8l/rustup}"
TASK_CARGO_BIN="${TEMPLAR_CARGO_BIN:-/home/broody/.cargo/bin/cargo}"
TASK_RUST_TOOLCHAIN="nightly-2026-01-15"
TASK_JOBS="${TEMPLAR_BUILD_JOBS:-8}"
TASK_MODE="${1:-wasm}"
mkdir -p "$TASK_ARTIFACTS"
cd "$TASK_ROOT"
case "$TASK_MODE" in
  wasm)
    env PATH=/usr/bin:/home/broody/.cargo/bin:/bin RUSTUP_HOME="$TASK_RUSTUP_ROOT" RUSTC_WRAPPER= \
      CARGO_BUILD_JOBS="$TASK_JOBS" CARGO_TARGET_DIR="$TASK_ARTIFACTS/client-target" \
      RUSTFLAGS='-C target-feature=+simd128 -C link-arg=-zstack-size=8388608 -C link-arg=--max-memory=4294967296' \
      "$TASK_CARGO_BIN" +"$TASK_RUST_TOOLCHAIN" build --locked --offline --release --lib \
      --target wasm32-unknown-unknown --manifest-path "$TASK_MANIFEST" \
      2>&1 | tee "$TASK_ARTIFACTS/rebuild-wasm.log"
    "$TASK_ARTIFACTS/tools/bin/wasm-bindgen" --target web --out-dir "$TASK_ARTIFACTS/pkg" \
      --out-name templar_wasm_membership \
      "$TASK_ARTIFACTS/client-target/wasm32-unknown-unknown/release/templar_wasm_membership.wasm" \
      2>&1 | tee "$TASK_ARTIFACTS/rebuild-bindgen.log"
    ;;
  native|test)
    TASK_CARGO_ACTION=build
    TASK_TEST_ARGS=()
    if [[ "$TASK_MODE" == test ]]; then
      TASK_CARGO_ACTION=test
      TASK_TEST_ARGS=(-- --test-threads=1)
    fi
    env PATH=/usr/bin:/home/broody/.cargo/bin:/bin RUSTUP_HOME="$TASK_RUSTUP_ROOT" RUSTC_WRAPPER= \
      CARGO_BUILD_JOBS="$TASK_JOBS" CARGO_TARGET_DIR="$TASK_ARTIFACTS/client-target" \
      RUSTFLAGS='-C target-cpu=native' \
      "$TASK_CARGO_BIN" +"$TASK_RUST_TOOLCHAIN" "$TASK_CARGO_ACTION" --locked --offline --release \
      --manifest-path "$TASK_MANIFEST" "${TASK_TEST_ARGS[@]}" \
      2>&1 | tee "$TASK_ARTIFACTS/rebuild-$TASK_MODE.log"
    ;;
  *)
    echo 'Usage: build.sh [wasm|native|test]' >&2
    exit 2
    ;;
esac
