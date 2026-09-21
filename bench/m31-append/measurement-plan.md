# Public append integration measurement plan

This plan separates mathematical validity, PROOF1 compatibility, local contract
execution and resource costs. All inputs are synthetic and public. Existing
archives are immutable. The review fixes the exact format and configuration.

## Correctness before measurements

- Independent M31 reference roots for empty, single-append and two-append
  states must agree with the native implementation and Cairo validation.
- Native and Cairo accept the same complete proof and bind the full statement.
  Reject changed chain/pool/version, old/new roots and counts, omitted/extra or
  reordered commitments, invalid leaf position/path, noncanonical encodings,
  incorrect sponge wiring, changed proof/config/claims, truncated/trailing
  data, and malformed empty-preprocessing openings. Keep boundary tests
  separate from unchanged-proof mutation tests.
- Exported Cairo arguments, public fact preimage, digest, statement-account
  class identity and emitted public message must agree byte-for-byte or
  element-for-element with an independent reference.
- The original PROOF1 verifier must accept the resulting artifact and reject
  altered proof or public output. The exact virtual-OS/bootloader/program
  authority must remain unchanged; log any new statement-account identity.
- Local state tests cover accepted insert, replay, stale old root/count,
  unauthorized/changed commitment, wrong context/program, and atomic rejection.
  A concurrent update is regenerated from the latest public state with the
  same requested commitments. No private client input is involved.

Record whether contract tests consume genuine native-verified facts in an
isolated harness or whether a complete local node validates an attached proof.
Never call a fact-injection-only test end-to-end PROOF1 verification.

## Resource runs

Freeze reviewed sources, binaries, fixtures, tool versions and configuration
before collecting performance data. No timed stages overlap builds, tests or
other benchmarks. Use fresh processes, explicit CPU budgets, memory caps and
zero swap. Preserve failing runs and label any cap adjustment.

1. Native one- and two-insertion proofs: one pinned CPU, initially 1 GiB cap,
   three successful fresh runs per shape. Report proof generation and separate
   verification, process RSS, cgroup charge, total elapsed time and proof sizes.
2. Cairo verifier execution: one run per shape after correctness, explicit
   step budget and 8 GiB cap. Report Cairo steps/builtins and host RSS/time.
3. Full unchanged PROOF1 wrapper: one insertion first, four CPU workers and
   a 16 GiB server cap. Include virtual execution, trace generation, proving,
   recursion and serialization. Measure verification in a separate process.
   Establish a valid round trip before adding repeats or the second shape.
4. Local contract: report actual call-level resources excluding setup and any
   separately measured native verifier. If full proof attachment is supported,
   include its costs explicitly; otherwise record the missing node-level cost.

On resource exhaustion, identify the stage before selecting a bounded larger
server cap. No reductions to security settings or weakened checks are allowed
to make a run pass. Cap failures do not imply a minimum memory requirement.

## Interpretation

Server memory is not client memory. This experiment makes no browser or private
payment claim and does not resolve the supported client hiding construction.
Deterministic repetitions describe fixture stability, including the same
grinding search, rather than a payment latency distribution. Local contract
resource estimates are not network fee quotes.

The decisive outcome is a verifiable and correctly bound settlement path for
public M31 updates, with separate visibility into server cost and contract
cost. A Cairo-execution-only result or a proof accepted for the wrong program
does not satisfy the PROOF1 milestone.
