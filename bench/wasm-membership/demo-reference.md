# Browser reference: `stwo-wasm-demo`

Source inspection on 2026-09-21. No prover changes, builds, browser executions,
or performance measurements were made for this report. The reference is useful
for loading a Rust prover into a browser; its workload and proof settings do not
establish the resource requirements of our felt252 membership benchmark.
As recorded in the [existing review](/home/broody/development/templar/bench/wasm-membership/review.md),
a supported client privacy route and its complete cost remain a separate
prerequisite for a full private payment. This report performs no new privacy
analysis.

## Exact reference and reproducibility

The inspected [AbdelStark/stwo-wasm-demo checkout](https://github.com/AbdelStark/stwo-wasm-demo/tree/50b7905c07680556a8b87e79c96dadc09e8be52d)
is commit `50b7905c07680556a8b87e79c96dadc09e8be52d`, dated
2024-06-27T18:44:42+02:00, subject `✨ build app`. Local path:
[stwo-wasm-demo](/home/broody/development/templar/target/wasm-membership/stwo-wasm-demo).
It has an MIT license.

Its [Cargo.toml](https://github.com/AbdelStark/stwo-wasm-demo/blob/50b7905c07680556a8b87e79c96dadc09e8be52d/Cargo.toml)
uses an **unpinned Git dependency** on `stwo-prover` and contains no Cargo.lock.
`app/package-lock.json` locks the JavaScript application, not Rust dependencies.
The Rust toolchain is `nightly-2024-01-04`; the manifest requests wasm-bindgen
`0.2.84`, getrandom `0.2` with `js`, and disables wasm-opt. These are not a
reproducible specification of a current rebuild of the committed binary.

The repository does contain a historical binary:

| Item | Inspected value |
| --- | --- |
| Artifact | `app/src/pkg/stwo_wasm_demo_bg.wasm` |
| File size | 357,933 bytes |
| SHA-256 | `efa28421fadf9753a448aadaeab766d8b15099228f47e2ff2794e115e2cb348d` |
| Embedded dependency source path | `.cargo/git/checkouts/stwo-e22b418082f2ccbd/de9892b/crates/prover/...` |
| Resolved historical S-two object | `de9892bbfe4d210b22289b0ca2e134daa7a95769` |
| Memory declaration | One nonshared wasm32 memory, minimum 17 pages = 1,114,112 bytes; no declared maximum |

The dependency object was resolved using the existing local Cargo bare Git
cache. Embedded paths and CPU symbol names identify the historical implementation;
they are not a replacement for a lockfile or a reproducible-build attestation.
The memory declaration was read directly from the binary's memory section. It
is an initial capacity, **not a measured proving peak**. The committed binary
also need not be identical to the currently hosted GitHub Pages artifact.

## Workload and implementation comparison

The old [Fibonacci implementation](https://github.com/starkware-libs/stwo/blob/de9892bbfe4d210b22289b0ca2e134daa7a95769/crates/prover/src/examples/fibonacci/mod.rs)
actually generates the recurrence `a, b = b, a² + b²` over M31, starting from
`1,1`. It proves a single trace column using `CpuBackend`. The pinned old
[prover constants](https://github.com/starkware-libs/stwo/blob/de9892bbfe4d210b22289b0ca2e134daa7a95769/crates/prover/src/core/prover/mod.rs)
and [PCS construction](https://github.com/starkware-libs/stwo/blob/de9892bbfe4d210b22289b0ca2e134daa7a95769/crates/prover/src/core/pcs/prover.rs)
establish the settings below. The comparison target is our archived
[membership client](/home/broody/development/templar/bench/poseidon-membership/client/src/main.rs:42),
not the full payment or recursive Cairo pipeline.

| Property | Historical demo | Our synthetic membership benchmark |
| --- | --- | --- |
| S-two base | `de9892bbfe4d210b22289b0ca2e134daa7a95769` | `489a0f3ee44a59e03944ad9aa4f3e5a91a3d3f08`, with recorded allocation patches |
| Additional AIR source | Fibonacci example in S-two | stwo-cairo `9b6be2710e4d7124bc93fe80a5af36556d42ed29` |
| Backend | CPU | SIMD; WASM SIMD128 port is separate qualification work |
| Work | One M31 recurrence column | Two depth-32 paths, 64 parent hashes, 128 felt252 Hades permutations and required tables |
| Default size | log 5 = 32 trace rows | Variable component traces plus fixed tables reaching log 20 |
| Blowup | log 1 = 2× | log 3 = 8× |
| PCS proof of work | 12 bits | 27 bits |
| FRI queries | 3 | 23 |
| Last-layer degree bound | log 0 | log 0 |
| FRI folding | Historical degree-halving implementation; no configurable step | Step 4 |
| Lifted commitment size | No corresponding current lifted-tree setting | `Some(23)` |
| Interaction work | No interaction trace for this Fibonacci example | Lookup interaction trace and separate 24-bit interaction proof of work |
| Transcript / Merkle hash | Ordinary Blake2s | Ordinary Blake2s |
| Returned object | Success and message; proof consumed by local verification | Serialized proof envelope, verification result, shape and phase data |

The demo's root HTML custom form caps log size at 10; this is only a UI limit,
not a Rust entrypoint bound. The React form does not have that same explicit
cap. The reference README leaves WASM SIMD as a TODO, and the committed artifact
has explicit CPU Fibonacci symbols. No conclusion about current SIMD performance
follows from the demo appearing responsive at its default size.

Our [component inventory](/home/broody/development/templar/bench/poseidon-membership/component-inventory.md)
calculates 1,092.125 MiB of logical expanded fixed-table values at 8× if those
arrays coexist, before other proof storage and scratch space. This is a source
calculation, not browser RSS or a prediction of the new bounded implementation's
peak. The demo has no comparable fixed-table workload.

## Reusable browser plumbing

The [workflow](https://github.com/AbdelStark/stwo-wasm-demo/blob/50b7905c07680556a8b87e79c96dadc09e8be52d/.github/workflows/gh-pages.yml)
builds a Rust `cdylib` with `wasm-pack build --target web`, then publishes the
root `index.html` and generated `pkg/`. It does not deploy the React application.
The useful pattern is a generated ES module, `await init()`, and a small exported
Rust function. The React/Chakra/CRACO layers are unnecessary for our measurement
harness. Pin the new dependency/toolchain set independently rather than copying
the old unpinned manifest.

Both demo pages call the synchronous prover on the main thread. An `async`
JavaScript handler does not make that synchronous work yield. A dedicated Worker
is the suitable place for our proving call, with phase messages to the page and
worker termination for cancellation. Keep proof bytes in a binary buffer; avoid
large JSON conversions in the timed proving interval. Explicitly free generated
wasm-bindgen result wrappers after extracting their outputs: the demo wrapper
has `free()` and a finalizer, but the pages do not explicitly free each result.

The committed [generated loader](https://github.com/AbdelStark/stwo-wasm-demo/blob/50b7905c07680556a8b87e79c96dadc09e8be52d/app/src/pkg/stwo_wasm_demo.js)
returns `instance.exports` from initialization, and the generated declaration
exports `memory`. Thus the useful inspection hook already exists:

```js
const wasm = await init();
const linearMemoryBytes = () => wasm.memory.buffer.byteLength;
```

## Measurement plan and interpretation

Record the exported memory capacity after initialization, at each Rust-to-JS
phase callback, after proof return, after extracting/freeing the result, and
after verification tests. Re-read `memory.buffer` every time: growth detaches
old nonshared buffers, while old shared-buffer views retain their previous
length. Pages are 64 KiB. [WebAssembly memory growth documentation](https://developer.mozilla.org/en-US/docs/WebAssembly/Reference/JavaScript_interface/Memory/grow).

For a successful run in a fresh instance with the same memory throughout,
ordinary linear memory grows but does not shrink, so final capacity also gives
its maximum capacity during that interval. **Capacity is not live allocator
usage or total browser process memory.** Freed Rust allocations may remain in
the linear-memory reservation. JavaScript proof copies, module compilation,
worker/browser overhead and stacks need separate interpretation. If the worker
crashes or is terminated, label the last received sample as incomplete evidence.

Do not rely on a same-worker interval to sample a synchronous proof: it cannot
run until the call yields. Also, replacing JavaScript `Memory.prototype.grow`
does not intercept the WASM `memory.grow` instruction used by an allocator.
Exact allocation-live peaks or individual growth events require separate
instrumentation; phase capacity and final capacity are the simpler first check.

Time the stages using the worker's `performance.now()` and send phase durations
or timestamps explicitly. Worker performance entries belong to the worker's own
context, so the page should also measure end-to-end elapsed time separately.
[Worker performance documentation](https://developer.mozilla.org/en-US/docs/Web/API/WorkerGlobalScope/performance).
Preserve the native phases: transcript regeneration, preprocessing/twiddles and
commitment, base witness, base commitment, interaction PoW/witness, interaction
commitment/STARK proving, and verification. Record asset loading and output
encoding/export separately when practical.

`performance.measureUserAgentSpecificMemory()` is optional supplementary data:
it estimates application memory including workers, has limited browser support,
and requires a secure, cross-origin-isolated context. Its implementation-dependent
numbers should not be compared across browser engines or versions. Do not make
it a prerequisite for the main linear-memory measurement.
[Application memory API documentation](https://developer.mozilla.org/en-US/docs/Web/API/Performance/measureUserAgentSpecificMemory).

Minimum checks for a useful result:

- Save source pins, Cargo.lock, module SHA-256, compiler/wasm-bindgen versions,
  SIMD/thread flags, memory limits, browser/version, fixture hash and proof config.
- Use a new Worker/instance for a cold run; label subsequent proofs in that same
  instance as warm. Record both time and retained memory across repeats.
- Verify the produced proof, compare its bytes/hash with the native fixture,
  and preserve malformed-proof rejection results separately from proof timing.
- Confirm the page heartbeat continues, cancellation terminates the Worker,
  and failures are reported with the last completed phase and capacity.
- Report successful proving capacity separately from any later verification or
  negative-test capacity. Do not silently substitute a smaller fixture or config.

The in-progress local [worker harness](/home/broody/development/templar/bench/wasm-membership/web/worker.js)
already adds phase callbacks, explicit result freeing and native proof hash
comparison; the [page harness](/home/broody/development/templar/bench/wasm-membership/web/app.js)
adds a heartbeat and cancellation. At inspection, its `load_ms` includes WASM
initialization plus fixture/reference loading and hashing, but excludes the
preceding JavaScript dynamic import. The follow-up version names this
`initialization_and_fixture_ms` and includes an explicit timer note. It labels
the first proof in a fresh worker and warm repeats, and separates the proving
linear-memory high-water value from the value after mutation tests.

## Resource-runner review

The [resource runner](/home/broody/development/templar/bench/wasm-membership/measure.py)
and [browser driver](/home/broody/development/templar/bench/wasm-membership/run-browser.mjs)
use three distinct measurement scopes:

| Metric | Scope and limitation |
| --- | --- |
| Cgroup `memory.peak` / systemd `MemoryPeak` | Entire isolated browser plus Node harness/server and cgroup-accounted memory; suitable for the enforced process-group cap |
| CDP process inventory plus `/proc` RSS/PSS | Sampled processes reported by Chrome; inventory/read races and sampling can miss peaks; summed RSS double-counts shared pages |
| Exported WASM memory capacity | One instance's linear-memory size; excludes JS/browser overhead and is not live Rust allocation size |

The original scripts sampled the cgroup every 25 ms and browser processes every
500 ms plus sampling work. Thus CDP samples are not exact instantaneous browser
peaks. The final kernel/systemd cgroup high-water value should be retained
separately from the greatest sampled value. GNU time's largest-process RSS also
must not be described as a summed browser peak. The selected machine is the
current development host, not measured consumer hardware; CPU and memory caps
do not reproduce a different CPU, memory bandwidth, or browser/device ecosystem.

Follow-up source review confirmed the runner owner's fixes:

| Original finding | Follow-up status |
| --- | --- |
| Overescaped `/proc/status` regex omitted RSS/HWM/swap | Resolved: line selection and a digit regex now parse the values directly |
| Missing readings became zero | Resolved: unavailable measurements become null; browser sample completeness/error counts and cgroup sample counts are retained |
| Final systemd peak was absent from the summary | Resolved: final and sampled peaks remain separate, and `effective_peak_cgroup_gib` takes the maximum of available observations |
| Main Python wait timeout bypassed structured artifacts | Resolved for the primary 1,220-second wait: records exit 124 and `harness_timeout`, then continues cleanup and serialization |

The retained [failed-launch summary](/home/broody/development/templar/bench/wasm-membership/results/chrome-three-runs-8g/summary.json)
shows why the maximum is necessary: sampled `memory.peak` reached 188,329,984
bytes, while the post-run systemd property reported only 2,854,912 bytes. The
effective value preserves the larger observation, 0.17539596557617188 GiB.
This report does not infer the cause of that discrepancy or claim the maximum
is a perfect reconstruction of a missed interval. Both raw values remain
available; the smaller final property must not erase an earlier observed peak.
This artifact is a failed launch, not a successful proving measurement.

The residual cleanup-timeout finding is also resolved in the final inspected
source: the 20-second cleanup wait records `cleanup_timeout` before killing the
launcher, and an additional five-second timeout records
`cleanup_exit_unconfirmed`. Both timeout paths continue to JSON serialization.
This is source review of the exceptional paths, not an executed timeout test.

The existing [three-run browser report](/home/broody/development/templar/bench/wasm-membership/results/chrome-three-runs-8g-v2/browser/browser-result.json)
records three successful native-byte comparisons and 235 of 235 complete RSS
and PSS samples, with zero CDP errors. This confirms the corrected reporting
produced data for that run; sampling completeness does not make sampled peaks
continuous measurements.

Follow-up source SHA-256 values:

- `measure.py`: `709520fd8fa42085677ba51fd88d1e9b11cae2722b7cad38a83025d80598c71a`
- `run-browser.mjs`: `f225cd4bfe0e51ac67812b7474235342158edaa68653b08154785ff1e772aa56`
- `web/worker.js`: `ee3e60b256ab2875a74d5a7e7a34cf0efd1d65142af4d532a6e88460c10b596d`

These findings concern measurement reporting only. The reviews read the source
without editing or executing either runner; follow-ups additionally inspected
existing failed-launch and completed-run artifacts. No build or benchmark was
run by this reviewer. The owner retains the final source snapshot and measured
results.
