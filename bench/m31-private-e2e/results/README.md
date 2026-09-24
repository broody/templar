# Private membership measurements

2026-09-22. **Native and browser membership gates passed.** These measurements
cover the complete depth-32 private membership relation in the
[protocol](../protocol.md), including witness construction, masking,
commitments, quotient/batch/FRI proving and proof serialization. They do not
cover payment semantics or PROOF1 server wrapping.

| Execution | Prove time | Client proving memory | Verify time | Proof size |
|---|---:|---:|---:|---:|
| Native, three fresh processes, one thread | 1.172–1.197 s | 63.48–64.38 MiB peak RSS | 0.163–0.173 s | 3,555,140–3,586,428 bytes |
| Chrome, three runs in one WASM worker | 1.889–2.120 s | 79.94 MiB linear-memory high water | 0.185–0.193 s | 3,593,832–3,629,688 bytes |

Native time is CLI wall time including input parsing and proof-file writing.
Browser proof time surrounds the exported WASM call, including JSON parsing
and output marshaling; initialization, fixture fetching, verification and
local artifact saving are separate. First browser proving takes 2.120 s;
the two warm runs take 1.889 and 1.896 s. Linear memory grows to 83,820,544
bytes on the first proof and does not grow on the next two. Three runs do not
establish long-term allocator behavior.

Browser memory outside WASM is additional. At 250 ms sampling intervals,
the isolated headless Chrome process set peaks at **1,154,539,520 bytes summed
RSS** and **489,152,512 bytes summed PSS** (about 1.08 GiB and 466.5 MiB).
Summed RSS counts shared pages more than once; PSS apportions shared pages.
These are sampled process totals, not exact whole-wallet peak memory or cgroup
accounting. The page's 100 ms heartbeat has a maximum observed interval of
100.155 ms. The WASM module declares a 2 GiB maximum linear-memory allowance;
the observed allocation is much smaller.

## Acceptance evidence

- The frozen source matches all eleven hashes in the independent
  [source review](../source-review.md). Final locked native build succeeds and
  all seven tests pass in 5.72 s. The degree-tail and direct quotient checks,
  fast/scalar batch comparisons and invalid-trace verifier rejection are in
  this final run. See [test log](native/final-test.log).
- Three native proofs of one fresh synthetic witness use fresh `OsRng`
  randomness, have distinct hashes, and each passes a separate verifier
  process. Its directory contains only `public.json` and the three proofs
  before negatives. It receives no witness argument and does not read the
  witness. This is process/input separation, not OS filesystem sandboxing.
  See [native report](native/report.json).
- Seven external native checks reject changed root/pool/chain, midpoint
  bitflip, truncation, appended byte and noncanonical field encoding. The
  unit suite additionally includes a prover deliberately bypassing honest
  trace/OOD gates; the real verifier rejects its invalid-trace artifact.
- The unmodified Rust library builds for `wasm32-unknown-unknown`, using the
  same reviewed sources and lockfile. No vendor or portability patch was
  necessary. See [build commands and artifact hashes](wasm-build/report.json).
- Chrome 153.0.8010.47 verifies a native proof, creates three distinct browser
  proofs, verifies each and rejects four variants per proof (changed root,
  tampering, truncation, trailing byte): **12 browser rejections**.
  See [browser result](browser/result.json).
- A separate native process accepts all three browser artifacts using only
  the public statement and proof files. See the
  [cross-verification record](browser/native-crosscheck.json).

The source review's native execution conditions are discharged by these
records. Protocol/source review is research validation under the documented
classical explicitly programmable ROM and CSPRNG assumptions, with a 96-bit
classical RO-work target. These tests are not a proof of zero knowledge or an
independent production audit. Wider deployment assumptions, side channels,
full payment semantics and server wrapping remain outside the verdict.

## Provenance and reproduction

Hardware: Intel Core i9-10980XE, 36 logical CPUs, 131,591,896 KiB system RAM.
Native proving uses the serial CPU backend (no parallel feature). All
measurements run after compilation and without another timed workload started
by this task. The development machine does not qualify physical 8/16 GiB
consumer desktops. No network traffic goes beyond loopback in the browser
harness.

Rust: `rustc 1.94.0-nightly (86a49fd71 2026-01-14)`, toolchain
`nightly-2026-01-15`. The native binary SHA-256 is
`cb963e1d7330e1d2b427c100e76124ec1d207235071dcfac729234295f2736f8`.
The retained [web package](../pkg/membership.js) uses wasm-bindgen 0.2.128;
its 465,929-byte module SHA-256 is
`4648ff4c4167825b2aefd18812d9239a1aaf5e27283b55ddf104d534077c0d66`.
All 201 S-two source/manifest files checked against the existing append
snapshot match; see the [dependency manifest](dependency-source-manifest.json).
`SHA256SUMS` covers the retained experiment source and evidence.

K3 ran the final tests and native build, then its provider returned a five-hour
quota error. Astra completed the already-defined measurement and WASM/browser
execution directly. No substitute model or protocol change was introduced.

Native reproduction uses [measure-native.py](../measure-native.py), passing
the compiled binary and a new output directory. Browser reproduction uses
[run-browser.mjs](../run-browser.mjs), passing the package, public/private
synthetic fixture, native proof, new output directory and repeat count3.
The exact WASM build environment is preserved in `wasm-build/report.json`;
its temporary Rustup home supplies an already-installed target and is not a
runtime requirement. The same pinned toolchain with that target installed is
sufficient. The private fixture remains under ignored `target/`, mode0600;
it is deliberately excluded from this archive. Fresh fixtures reproduce
behavior, not identical randomized proof bytes.

## Decision

Continue the compact-client architecture. This experiment removes the
multi-gigabyte client-memory concern for this concrete private membership
relation. It does not justify a linear extrapolation to a full payment.
The next decisive experiment is an actual verifier-to-PROOF1 server route
with measured server cost; the current
[adapter incompatibility](../wrapper-compatibility.md) remains unresolved.
