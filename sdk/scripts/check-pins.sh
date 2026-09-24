#!/usr/bin/env bash
# Checks every pinned build input of the SDK (docs/sdk-spec.md §13) before a build.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
FORK="$ROOT/target/proving-arith"
FORK_REV=250cc9c1e50575e9f31a326e7fb9fb8e00ced0c7
WASM_BINDGEN=0.2.128
fail() { echo "check-pins: $*" >&2; exit 1; }

# The arithmetic-profile fork (private: broody/proving-private, branch templar/arithmetic-profile).
[ -d "$FORK/.git" ] || [ -f "$FORK/.git" ] || fail "missing $FORK: git clone -b templar/arithmetic-profile https://github.com/broody/proving-private.git $FORK"
head=$(git -C "$FORK" rev-parse HEAD)
[[ "$FORK_REV" == "$head"* || "$head" == "$FORK_REV"* ]] || fail "fork at $head, expected $FORK_REV"
[ -z "$(git -C "$FORK" status --porcelain --untracked-files=no)" ] || fail "fork has local changes"

# The relation sources the client includes by path (bench/m31-private-blake, client-port) are pinned
# by this repository's commit: they must be unmodified.
[ -z "$(git -C "$ROOT" status --porcelain -- bench/m31-private-blake/client/src bench/m31-private-wrapper/client-port/src)" ] \
  || fail "relation sources have uncommitted changes"

# Toolchain and wasm-bindgen.
grep -q 'channel = "nightly-2026-01-15"' "$ROOT/sdk/rust-toolchain.toml" || fail "toolchain pin"
grep -q "wasm-bindgen = \"=$WASM_BINDGEN\"" "$ROOT/sdk/wasm/Cargo.toml" || fail "wasm-bindgen crate pin"
if command -v wasm-bindgen >/dev/null; then
  [ "$(wasm-bindgen --version)" = "wasm-bindgen $WASM_BINDGEN" ] || fail "wasm-bindgen CLI is not $WASM_BINDGEN"
fi
echo "check-pins: ok (fork $head)"
