# Public M31 append proof and PROOF1 integration

Status: public native/Cairo verification passes; unchanged PROOF1 generation is
blocked by the preserved outer domain capacity, 2026-09-21.

The [native results](results/native-summary-v2.md) include five valid public
append scenarios, 70 native mutation rejections, six boundary controls, and
16 rejected state-fixture mutations. Single/two-append client runs use about
17–31 MiB RSS, with 192,143/223,098-byte inner proofs. The six repeated resource
runs use frozen native v1; v2 corrects only duplicate-query export handling.
The [complete-proof Cairo tests](results/cairo-negative-v1/report.md) pass two
valid controls and reject all 27 independent mutations, including noncanonical
M31 words and malformed empty-preprocessing data. These complement the
[Cairo differential tests](results/cairo-correctness-v2/report.md).

The [outer attempt](results/outer/summary.md) executes the one-append verifier
through the unchanged virtual OS, then fails during Cairo proof generation.
A 16 GiB server cap OOMs; a 64 GiB attempt reaches about 29.27 GiB RSS and stops
with `Not enough twiddles!`. The preserved prover and recursive verifier fix
the relevant domain parameters. Increasing memory alone does not establish
compatibility. No authentic outer proof or local settlement result exists yet.
The next integration gate is reducing the verifier's largest trace components
to fit that capacity, or explicitly evaluating another supported outer route.
All eight prior benchmark archives were rechecked: 1,741 recorded files remain
unchanged. `SHA256SUMS` freezes this experiment's sources and evidence, excluding
build caches; the saved handoffs and anchor files pin the external binaries.

This isolated experiment tests a public M31 tree update from a direct S-two AIR
through a Cairo verifier and the existing PROOF1 proving path. A local test
contract should accept the verified update and store its new root without
executing the M31 tree hashes itself. It does not implement a private payment,
qualify client zero knowledge, or migrate the live pool or note formats.

The starting point is the frozen [M31 tree experiment](../m31-tree/README.md).
Its exact hash construction, depth, digest encoding and configured proof
parameters are the baseline. Prior archives and production sources stay frozen.

## Statement and trust boundaries

The update binds chain, pool, version, old root and leaf count, the exact ordered
commitments being appended, and new root and count. Verifier identity and proof
configuration come from the approved wrapper program, not an unchecked proof
header. Every append validity check must execute inside the verified proof path;
unproved host preprocessing cannot authorize a state update.

The local contract checks the verified update against its current state and
synthetically authorized commitments, then changes root and count atomically.
The experiment has no tokens, wallet secrets, deposits or private notes. Funding
authorization and linkage to a complete payment proof remain future integration.

PROOF1 verification and contract consumption of verified facts are distinct
steps. A real native proof must pass the preserved verifier. A contract test that
injects facts is not by itself proof that a local node accepted the attached
PROOF1; the final report must distinguish those levels of evidence.

## Acceptance milestones

1. Review the direct-AIR/Cairo compatibility path and fixed public statement.
2. Generate and independently verify a public append proof with the existing
   reviewed M31 permutation construction and complete append bookkeeping.
3. Verify it in Cairo, including statement/claim binding and rejection controls.
4. Run that verifier through the unchanged PROOF1 proving route; independently
   verify the artifact and compare its exact program/message/public binding.
5. Execute local contract acceptance and rejection tests with authentic verified
   outputs, and record whether full node-level proof attachment is supported.
6. Demonstrate a stale update: prepare two updates from A, accept the first,
   reject the second, and regenerate the second against the new root using only
   public data. Rejected updates must leave state unchanged.

The synthetic pool authorizes a fixed ordered queue. Both branches can be valid
tree proofs from A, but only the next queued commitment is initially authorized
for settlement. This tests stale-state rejection and public root refresh; it
does not demonstrate two simultaneously eligible competing settlements.

Initial capacity is deliberately small; the specialists will review single and
two-commitment cases so ordering checks can be exercised. No larger batch or
browser port is implied. Measure inner proving, Cairo verification, outer proving
and contract execution separately. Server resources are distinct from the prior
client memory target.

The source reviewer owns `review.md`; specialist implementations use separate
native and Cairo directories. GPT-5.6 Sol performs routine operational checks and
frozen-build tests, measurements and documentation. Routine benchmarks must not
overlap builds or each other. Tooling uses explicit versions and `sncast` for
local chain interaction, without the controller CLI.
