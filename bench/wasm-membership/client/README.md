# WASM portability client

This crate exposes the existing **public-transcript**, two-path Poseidon membership experiment through an in-memory Rust API. The statement, AIR closure, lookup boundary, ordinary Blake2s transcript, PCS settings, interaction PoW and binary proof envelope remain unchanged. Bounded coefficient storage with 16-column FRI batches is fixed. This is not a private membership or complete payment circuit.

Native CLI:

```
RAYON_NUM_THREADS=1 templar-wasm-membership FIXTURE_JSON NEW_OUTPUT_DIR
RAYON_NUM_THREADS=1 templar-wasm-membership --verify-tests PROOF_BIN NEW_OUTPUT_DIR
```

Browser module (generated with wasm-bindgen `--target web`):

```
import init, { prove_membership, verify_membership, test_membership_mutations }
  from './pkg/templar_wasm_membership.js';
const exports = await init();
globalThis.onMembershipPhase = name => {
  console.log(name, exports.memory.buffer.byteLength);
};
const result = prove_membership(fixtureJsonText);
const proofBytes = result.proof_bytes;     // Uint8Array; no JS numeric-field conversion.
const summary = JSON.parse(result.summary_json);
const shape = JSON.parse(result.shape_json);
result.free();
verify_membership(proofBytes);             // independently reconstructs trusted preprocessing.
const mutations = JSON.parse(test_membership_mutations(proofBytes));
```

Use a dedicated module worker. Proving is synchronous. The result includes runtime verification, execution target, phase durations and WASM linear memory bytes. Browser verification is not labeled native verification; cross-check the resulting bytes with the archived native executable separately. WASM memory does not shrink, so its post-call byte length is linear-memory capacity high-water, not live allocation or total browser RSS. Reacquire `memory.buffer` after growth.

Build uses the scoped nightly-2026-01-15 toolchain and wasm-bindgen 0.2.128. Required target is `wasm32-unknown-unknown`, with `-C target-feature=+simd128 -C link-arg=-zstack-size=8388608 -C link-arg=--max-memory=4294967296`. The module has an 8MiB stack and a 4GiB maximum linear memory, without shared-memory/atomics or browser worker pools. A compile-time assertion prevents a WASM build lacking simd128.

The only copied upstream source change is `cube_252.rs`: WASM directly invokes the same witness closure instead of constructing a private native Rayon pool. Native execution retains the original 8MiB-stack private pool. Browser startup initializes an explicit single-thread current-thread global Rayon pool once per module, matching rayon-core 1.13.0's documented threadless fallback. No arithmetic, AIR, randomness, FFT, transcript or FRI algorithm changes are made. All other portability code lives in this crate: clock, phase callback, memory metric, panic reporting, and byte/JSON transport adapters.

Original benchmark sources and dependency archives remain unchanged. Build logs and generated artifacts belong under `target/wasm-membership`; runtime evidence is managed by the parent harness.

## Reproduce the build

Start from the preserved `target/direct-air/stwo` and `target/direct-air/stwo-cairo` source snapshots, which already include the reviewed bounded-memory storage implementation. A fresh checkout of only the upstream commit is not equivalent to these snapshots. Copy them into fresh `target/wasm-membership/stwo` and `target/wasm-membership/stwo-cairo` directories, then apply this crate's `patches/cube252-browser-pool.patch` with `patch -p1` from the copied `stwo-cairo` directory. Never patch the preserved source directories. `target/wasm-membership/source-portability-manifest.json` records exact original/copied tree hashes, changed paths and tool versions.

The scoped toolchain must contain nightly-2026-01-15 and its wasm32 standard library. Tool setup used:

```
RUSTUP_HOME=/tmp/templar-stwo-privacy-dtgn6e8l/rustup rustup target add wasm32-unknown-unknown --toolchain nightly-2026-01-15
RUSTUP_HOME=/tmp/templar-stwo-privacy-dtgn6e8l/rustup cargo +nightly-2026-01-15 install wasm-bindgen-cli --version 0.2.128 --locked --root target/wasm-membership/tools
```

Run `bench/wasm-membership/client/build.sh wasm` to reproduce the web package, `build.sh native` for the native CLI, and `build.sh test` for the three fixture/statement tests. The script preserves build output logs and uses the checked-in Cargo.lock with offline/locked resolution. The initial build populated the crate cache online; a new machine must first fetch those locked dependencies. Override `TEMPLAR_RUSTUP_ROOT`, `TEMPLAR_CARGO_BIN` and `TEMPLAR_BUILD_JOBS` when needed. No wasm-opt pass is used.
