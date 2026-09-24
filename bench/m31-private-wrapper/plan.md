# Private membership to PROOF1: integration pathfinding

2026-09-22. Aim: a real client-private membership proof verified by an outer
computation, producing genuine PROOF1 accepted by the preserved verifier with
the exact expected facts. Full payment and Sepolia adoption remain ADR-0024 gates.
The immediate objective is to remove the expensive proof-authentication path
without replacing proved inner verification with a host acceptance flag.

The frozen SHAKE client and its six native/browser artifacts remain unchanged.
Independent math and PCS challenge reviews are complete. A separately versioned
Blake research candidate has also passed parameter/source review and native/WASM
execution; see [current results](README.md) and
[the candidate](../m31-private-blake/README.md).
Existing docs/zk-guide changes belong to another task and remain untouched.

## Completed hash pathfinding

The frozen proof uses SHAKE256 output96 bytes for all private Merkle nodes and
transcript state/coins. Cairo2.18's Keccak syscall returns only four64-bit lanes,
32 bytes. The underlying permutation/rate can supply the first32 SHAKE bytes
with correct caller padding, but does not expose the remaining64 bytes. Truncation
or a replacement hash would change the proof protocol and needs separate review.

The isolated exact FIPS202 SHAKE256 cost probe uses:
rate136 bytes, 24 Keccak-f1600 rounds, suffix0x1f and pad10*1, little-endian lanes,
all96 output bytes. Inputs are bounded canonical bytes. No digest hint or host
precheck substitutes for computing the hash in the proved program. Reviewer
approved this standard-function component on2026-09-22. The empty-message
known answer and two actual framed payloads matched; the broader SHAKE boundary
suite was deferred when the user chose Blake2s. Do not label that deferred suite
complete. SHAKE implementation optimization is no longer the active route.

Primary sources: [FIPS202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf)
and [NIST empty-message sample](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHAKE256_Msg0.pdf).

The prior public M31 append verifier executed8,062,701 Cairo steps but the
preserved PROOF1 prover failed its fixed domain capacity at roughly29GiB RSS.
That record is in `bench/m31-append/results/outer/summary.md`. Adding RAM alone
does not fix that compatibility boundary. Measure the new dominant hash work
before constructing an entire verifier that may exceed it. The new Blake
component passes full-output and encoding tests, and a954-compression public
batch now produces genuine PROOF1 accepted by the unchanged original verifier.
That result proves the hash workload, not complete private membership.

## Remaining capacity gate

The Blake32/salt96 candidate preserves all application/AIR/masking/FRI parameters.
Its retained proof needs43,166 compression calls after shared-node reuse.
The pinned implementation requires at least3,453,280 Blake-G rows (at least trace log22),
above the preserved trace log20 limit. This is a source-derived direct-Cairo
bound, not a reason to repeat an unchanged full-prover failure.

The dedicated server hash circuit now passes native and Cairo verification,
but its final PROOF1 attempt fails the preserved twiddle/domain capacity after
7,301,958 OS steps (34.35GiB RSS under a64GiB cap, no OOM). See
[the measured gate](server-circuit/README.md). Next profile/reduce the Cairo
bridge or establish supported larger final-wrapper capacity before porting the
full membership verifier. A narrower AIR remains another route. Preserve all inner validity checks and
the exact statement/program binding. A new proof-format or mathematical change
requires a focused review; unchanged code does not require repeating reviews.

The [follow-up experiments](bridge-capacity/README.md) are complete: checked
M31 inversion reduces standalone steps15.37% and OS steps15.01%, but padded
Blake work still requires log22. An isolated larger configuration regenerates
its trusted roots successfully, then OOMs at96GiB during actual proving.
No new PROOF1 or larger-verifier acceptance was established. Profile-derived
execution savings alone do not remove this gate; measure proof serialization,
OS hash workload and retained prover allocations before another large run.

## Full wrapper obligations

Port every verifier check of the selected, explicitly pinned protocol version,
hardcode the approved circuit fingerprint and derive canonical public encoding.
Authenticate all openings and transcript phases, recompute fixed domains,
selectors, four OOD identities, batch values and every FRI fold. Publicly proved
auxiliary calculations may reduce server work; unproved host calculations may
not become trusted inputs. Differential controls must include altered public
inputs, authentication data, OOD/FRI values, configuration and trailing data.

Then execute the verifier account through the approved virtual OS, produce
actual PROOF1, independently verify it and compare program/chain/pool/message
facts. Preserve exact binaries and record full server resources. Local virtual
state and node/real Sepolia acceptance are distinct levels of evidence.
