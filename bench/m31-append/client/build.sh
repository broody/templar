#!/usr/bin/env bash
set -euo pipefail
TASK_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)"
TASK_MODE="${1:-native}"
TASK_ACTION=build
TASK_LOCK=(--locked)
TASK_ARGS=()
case "$TASK_MODE" in
  bootstrap) TASK_LOCK=();;
  native) ;;
  test) TASK_ACTION=test; TASK_ARGS=(-- --test-threads=1);;
  test-build) TASK_ACTION=test; TASK_ARGS=(--no-run);;
  *) echo 'Usage: build.sh [bootstrap|native|test|test-build]' >&2; exit 2;;
esac
cd "$TASK_ROOT"
mkdir -p target/m31-append/client-target
env PATH=/usr/bin:/home/broody/.cargo/bin:/bin \
  RUSTUP_HOME="${TEMPLAR_RUSTUP_ROOT:-/tmp/templar-stwo-privacy-dtgn6e8l/rustup}" \
  RUSTC_WRAPPER= CARGO_BUILD_JOBS="${TEMPLAR_BUILD_JOBS:-8}" \
  CARGO_TARGET_DIR="$TASK_ROOT/target/m31-append/client-target" \
  RUSTFLAGS='-C target-cpu=native' \
  /home/broody/.cargo/bin/cargo +nightly-2026-01-15 "$TASK_ACTION" "${TASK_LOCK[@]}" \
  --offline --release --manifest-path bench/m31-append/client/Cargo.toml "${TASK_ARGS[@]}" \
  2>&1 | tee "target/m31-append/build-$TASK_MODE.log"
