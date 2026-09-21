# Public membership in a browser

Status: browser portability milestone passed, 2026-09-21.

Port the archived `bench/poseidon-membership` relation to a single browser worker.
Keep the real felt252/Poseidon arithmetic, full lookup closure, public statement,
security settings, serialization and native verification unchanged. The fixture
contains two public depth-32 paths, requiring 128 permutations.

This is public, synthetic arithmetic. It is not a private payment, a new privacy
construction, PROOF1 wrapping, or qualification of a physical consumer machine.
The previous experiment and its dependencies stay unchanged; portability edits
belong to copied dependencies under `target/wasm-membership`.

## Outcome

**Four proofs generated and verified in Chrome 153**, using a single WASM worker
and unchanged proof settings. Three successive proofs in one worker took
**40.93–41.72 seconds** each. A fresh browser passed a **4 GiB process-group cap**
in **41.77 seconds** for proving and verification. All four complete envelopes
are byte-identical to the preserved native artifact, which the preserved native
verifier also accepted after importing browser output.

WASM linear memory grew to **2.150 GiB** on the first proof and stayed there for
the two warm repeats. Browser plus harness memory peaked at **2.21–2.23 GiB**
under Linux cgroup accounting, with no swap or OOM. These are different memory
metrics. The page heartbeat remained active; its greatest observed interval was
121 ms for a 100 ms timer. Both browser launches passed the existing 13 verifier
mutation rejections and three boundary controls.

This demonstrates that exceeding 2 GiB does not itself prevent this workload
from running in a browser. It does not meet the desired sub-2-GiB budget or
establish a complete private payment's footprint. Headless Chrome ran on the
development workstation; consumer hardware, other browsers and mobile remain
unqualified. Three proofs do not establish long-term allocator behavior.

See [measurements](results/measurements.md), [machine-readable results](results/aggregate.json),
[source review](review.md), and the [browser screenshot](results/chrome-three-runs-8g-v2/browser/browser.png).

**Decision:** retain the working browser path. Before committing to a private
client architecture, identify a supported reviewed client privacy construction
and measure its complete cost. Fixed range-check tables and simultaneous trace
expansion remain the main memory leads. No accepted ADR or production prover
has changed, and the native payment pipeline remains the reference.

## Evidence required

- A real wasm32 build and browser proof generation, followed by verification.
- Complete proof comparison with the archived native envelope and native
  verification of the browser output.
- Three successive proofs in one worker, with WASM linear-memory high-water
  size, per-run time, browser-process resource sampling and page responsiveness.
- Record failures and build workarounds. A 4 GiB declared memory ceiling is an
  address-space allowance, not a claim that a user has that much spare RAM.
- A supported client privacy route and its complete cost remain a separate
  prerequisite before implementing a full private payment.

Reference: [AbdelStark/stwo-wasm-demo](https://github.com/AbdelStark/stwo-wasm-demo).
See `demo-reference.md` for its pinned identity and differences from this workload.

## Reproduce

The [client instructions](client/README.md) contain the dependency patch and
pinned Rust build procedure. The emitted web package is archived in `pkg/`;
the measured package identity is in `results/build-wasm-artifacts.json`.
Install the recorded Playwright version into
`target/wasm-membership/browser-tools` using the archived package lock under
`results/`. The harness uses `/usr/bin/google-chrome` and only loopback HTTP.

From the repository root, choose a new run name:

```sh
python3 bench/wasm-membership/measure.py --name browser-reproduction --cap-gib 4 --cpu-cores 4 \
  --scope 'Public synthetic membership in one browser worker; no private-payment qualification' -- \
  "$(command -v node)" bench/wasm-membership/run-browser.mjs \
  bench/wasm-membership/results/browser-reproduction/browser 3 \
  bench/wasm-membership/pkg
```

The CPU allowance covers the browser and harness; the prover uses one worker.
Do not run compilation or other benchmarks alongside a measured run. The
runner saves each proof, full browser result, per-process memory samples,
cgroup records, console messages and a screenshot. Retained source snapshots
identify the scripts used for the original runs.
