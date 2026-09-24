# ADR-0018: Adopt client-side S-two ZK proving with native Starknet proof facts

- Status: Accepted (PROOF1 pool lifecycle demonstrated on Sepolia; production integration and desktop qualification pending); preserved note semantics amended by [ADR-0021](0021-push-only-payments.md); client/server proving split, private hash format and device assumptions amended by [ADR-0024](0024-compact-client-proofs-and-server-wrapping.md)
- Date: 2026-09-20
- Deciders: broody
- Supersedes: [ADR-0008](0008-inner-proof-system.md),
  [ADR-0015](0015-gnark-multicommit-garaga.md),
  [ADR-0016](0016-noir-honk-feasibility.md), and
  [ADR-0017](0017-desktop-native-hash-pathfinding.md) for production proof-system
  selection and the proposed BN254 hash migration.
- Amends: [ADR-0010](0010-single-phase-architecture.md) for proof transport,
  verification and milestones; [ADR-0014](0014-m2-statement-shape.md) for
  proof-system-specific implementation and device assumptions.
- Evidence: [preserved experiment records](evidence/0018/README.md).

## Context

The Groth16 path requires custom felt252 limb arithmetic to resolve the
gnark/Garaga commitment-extension incompatibility. Noir/Honk demonstrated
verifier compatibility, but the tested felt252 emulation exceeded the bounded
compiler-memory budget. Native BN254 hashing proved economical for desktop
clients, at the cost of a new note/tree format and substantially more Cairo
hashing work. Those benchmarks remain useful evidence.

The upstream S-two recursive privacy pipeline now provides a ZK route that can
execute Templar's felt252/Poseidon statement directly. The earlier ADRs' lack
of an available S-two ZK path is no longer the basis for selecting a SNARK.
This decision selects that privacy pipeline, not an arbitrary S-two proof:
using the core prover alone does not establish witness privacy.

Three experiments inform the decision. They are different configurations, and
their memory figures must not be combined into a claim about deployed performance.

| Experiment | Workload and result | Limitations |
|---|---|---|
| Standalone Cairo statement with experimental staged allocations | Ordinary 2/2/1, controlled 1/1/1 and maximum ordinary 4/4/2 cases verified in about 11.7–12.0 s, with 8.44–8.68 GiB peak RSS under a 10 GiB cap and no swap | Earlier prover revision; no virtual OS; prototype memory patch |
| Current V2 privacy service against Sepolia 0.14.4 state | Ordinary 2/2/1: 15.006 s request time, including 11.199 s proving; 14.22 GiB peak RSS under a 16 GiB cap; no swap; 231,955-byte compressed proof | Stock allocations; one synthetic case; gateway rejected live submission |
| Pinned V1 privacy service against Sepolia 0.14.4 state | Ordinary, controlled and maximum cases locally verified under a 16 GiB cap without swap; ordinary proof accepted on L2 with the expected state change | Stock allocations; synthetic acceptance contract; production pool and physical desktop qualification remain |

All used four physical cores on an i9-10980XE. These establish feasibility on
a constrained development host, not a consumer-desktop or browser guarantee.
The [V1 measurements](evidence/0018/v1/README.md) used an unmodified source build
of `PRIVACY-0.14.3-RC.2`, with its genuine V1 recursive ZK prover and verifier:

| Case (inputs/outputs/withdrawals) | Request time | Proving within request | Peak RSS | Compressed proof |
|---|---:|---:|---:|---:|
| Ordinary 2/2/1 | 18.592 s | 12.631 s | 13.50 GiB | 237,232 bytes |
| Controlled 1/1/1 | 18.844 s | 12.326 s | 13.98 GiB | 239,116 bytes |
| Maximum ordinary 4/4/2 | 19.588 s | 13.083 s | 14.34 GiB | 236,518 bytes |

Each used a fresh service process; startup took another 1.42–1.46 s. Request
time includes virtual OS execution and RPC state reads, but excludes compilation,
fixture preparation, service startup and the separate local verification check.
All three matched the eight reference public values and passed the pinned V1
cryptographic verifier in 155–172 ms. Changed message digests, program hashes
and proof bytes were rejected. These are single measurements, not latency
distributions or a controlled V1-versus-V2 performance comparison.

The ordinary V1 proof was submitted directly to the official Sepolia gateway.
[Transaction 0x27eaa862…90c5f85](https://sepolia.voyager.online/tx/0x27eaa86230d34e8a2874ec93d0c91027d782cd2d896f7f6bde9added90c5f85)
was `ACCEPTED_ON_L2 / SUCCEEDED` in block 15,357,460. The acceptance counter
became one and its event contained the expected binding. The actual fee was
1.489247120327854848 test-STRK, with 77,423,200 L2 gas and 384 L1 data gas.
This measures the asset-free acceptance transaction, not a complete pool spend.
The controlled and maximum proofs were checked locally, not submitted on-chain.

A subsequent [actual-pool lifecycle test](../../bench/stwo-e2e/README.md) used
an isolated, byte-identical copy of the pool core with a native adapter behind
its existing `IVerifier` interface. Funded deposit, payment, recipient respend
and final withdrawal succeeded on Sepolia with pool fees enabled. Three
successful spend proofs took 18.94–20.54 s per request, at 13.92–14.02 GiB RSS;
actual full-spend network fees were 1.529–1.780 test-STRK. Action tampering,
forged public binding, replay and a zero-recipient withdrawal reverted on-chain
with pool state and test-token balances unchanged. This qualifies the ordinary
integration path; real controller signatures, wallet delivery/discovery and
production deployment remain separate work. The primary pool package was not
modified, and the test used a synthetic ERC20 with an explicitly configured fee
token. Its built-in default fee-token address was found absent on Sepolia.

On 2026-09-20, Sepolia's official gateway returned
`StarknetErrorCode.PROOF_VERSION_NOT_ALLOWED` for `PROOF2`, but accepted the V1
transaction above. The Zan RPC could supply state and read the successful
receipt, yet its fee estimator rejected V1 as disallowed by its protocol
configuration. Cartridge's tested estimator returned `PROOF_FACTS_LENGTH`
despite supplied facts. Those simulations did not reach the intended replay
or changed-binding checks. RPC behavior is therefore an integration constraint,
not a reliable substitute for testing the actual submission route. Upstream
[PR #15120](https://github.com/starkware-libs/sequencer/pull/15120) added
protocol support for V1 alongside V2, and
[PR #15122](https://github.com/starkware-libs/sequencer/pull/15122) added
independent gateway acceptance switches. Protocol support and gateway rollout
remain separate concerns. The live receipt establishes V1 acceptance for the
tested Sepolia route and date only.

## Decision

1. **Select S-two's recursive ZK privacy pipeline as Templar's production
   proving direction.** Implement the spend statement in Cairo and generate
   its privacy proof locally on the user's device. Stop treating Groth16,
   custom felt252 limb arithmetic, or Noir/Honk as the M2 production path.
   Retain their reference implementations and benchmarks for differential
   testing and comparison.

2. **Use an approved virtual OS and native Starknet proof verification.**
   Execute the Cairo statement inside the approved virtual-OS wrapper, then
   attach the recursive privacy proof and proof facts to one on-chain spend
   transaction. The pool's acceptance path must bind the verified virtual
   message to the expected statement contract/class, chain, pool, protocol
   version and eight public statement values. This requires an explicit
   proof-facts adapter and review of the current `IVerifier`/`apply_spend`
   interface. The subsequent isolated ordinary-flow test demonstrated that an
   adapter can use that interface without changing the pool core; promoting it
   to the production package still requires review and broader qualification.

3. **Preserve felt252/Poseidon and the existing spend semantics.** Keep the
   note-secret, invoice-inner, commitment, nullifier, tree and binding domains;
   recipient-authored outputs; depth 32; single-token bundles; 4/4/2 maxima;
   padded bindings with counts; and the eight public scalars from ADR-0014.
   Do not adopt ADR-0017's proposed BN254/Poseidon2 format migration. A Cairo
   implementation may evaluate active slots while preserving canonical zero
   padding in the bound public statement.

4. **Keep one on-chain spend transaction and no proving operator.** The
   virtual execution and privacy proof are prepared locally. ADR-0010's
   removal of general private invokes and its controller integration model
   remain in force. Its bans on virtual-OS execution, proof facts and proof
   recency checks are superseded for this verification path; no blind-operator
   milestone or arbitrary pool-authorized dispatch is restored.

5. **Target desktops with 16 GiB RAM initially.** Accept the larger prover
   footprint as a tradeoff for preserving the format and using a transparent
   hash-based proof construction. ADR-0017's preferred 4 GiB / maximum 6 GiB
   client budget and earlier phone-proving assumptions no longer determine
   proof-system selection. Optimize for enough remaining memory to run the
   OS and normal applications. A 16 GiB cgroup success at 14.34 GiB RSS does
   not qualify a physical 16 GiB desktop for release.

6. **Use the demonstrated PROOF1 route as the initial integration baseline.**
   Pin the V1 prover and verifier together with the approved virtual OS and
   statement class. Both V1 and V2 privacy pipelines include ZK blinding;
   none of the tested Templar statement shapes required V2. Do not make
   eventual PROOF2 gateway acceptance a prerequisite for this architecture.
   Treat V2 as a separately qualified upgrade when needed for maintained
   upstream support, capacity or other requirements. A V2 upgrade must use
   its matching prover, verifier and serialization, then pass differential,
   privacy, memory and live acceptance checks. Changing a version marker is
   not a conversion. The pinned V1 baseline is not a commitment to retain an
   obsolete release; review upstream security and compatibility changes.

7. **Qualify the complete submission route on each target network.** The
   successful Sepolia path used local proving plus direct official-gateway
   submission. State reads, estimation and submission may have different
   proof-version support even on the same chain. Implement proof-preserving
   signing/transport, bounded fees and receipt/state verification; qualify
   estimation independently. Mainnet acceptance remains untested and is a
   deployment gate. A successful test-contract transaction does not mark
   production pool integration complete.

## Alternatives considered

- **Native BN254 Noir/Honk:** excellent measured client RAM and proof size,
  but requires a format migration, additional Cairo hashing work and a
  universal KZG SRS assumption. Preserve the experiment; do not adopt it as
  the current production direction.
- **Custom felt252 Groth16 limb layer:** preserves the format, but adds
  specialized arithmetic implementation, audit work and a per-circuit setup
  ceremony that this proof layer no longer needs.
- **Felt252-emulated Noir/Honk:** compatibility is demonstrated for the
  microbenchmark; the measured compiler scaling makes it a poor next
  investment for the full statement.
- **Direct Cairo STARK verifier:** a possible deployment alternative, but
  compatibility and transaction costs for the exact privacy proof remain
  unmeasured. Native verification is the selected route.
- **Require V2 from the start:** no demonstrated need in the tested Templar
  workloads. V1 already produced valid ZK proofs and a successful Sepolia
  transaction. Retain V2 as an upgrade option without making its activation
  a launch dependency.

## Consequences and implementation order

**M2 becomes the Cairo statement, desktop privacy prover and native proof-facts
integration.** The current experimental wrapper is an asset-free acceptance
sink, not the production pool. Promote reviewed code and extend differential
tests against the existing reference, covering ordinary, controlled and maximum
bundles, malformed witnesses, canonical encodings and adversarial transitions.
The pool must still independently enforce known roots, spent nullifiers,
action binding and zip checks, controller signatures/deadlines, and atomic
token movement. Pin expected statement identity and validate proof recency
and context; the prototype's 4,096-block age bound is not a production policy.

Port the staged allocation experiment to the pinned V1 baseline with an
explicit low-memory API. Preserve blinding and all security parameters, and
verify outputs after each change. Repeat the complete virtual-OS measurements
for ordinary, controlled and maximum bundles, then qualify actual 16 GiB
consumer desktops without swap and with normal applications running.
Compilation, witness preparation, cold startup, proving and verification must
be reported separately. The V1 prebuilt image exited with signal 4 on this
host; a native source build succeeded. Shipping requires a compatible CPU
baseline or dispatch strategy. Browser/mobile support remains future work.

Pin the prover, recursive verifier root, virtual OS, statement class and
serialization as a compatible version set. A network upgrade may require new
artifacts or a prover upgrade. Preserve the successful V1 regression fixture
and repeat its on-chain receipt and state checks after compatibility changes.
For V2, generate a genuine fresh V2 proof and repeat the same acceptance test.
Measure full production spend costs separately from the V1 acceptance sink's
actual fee, the earlier V2 simulation estimate and the subsequent synthetic-token
pool lifecycle. Retain the live replay, binding and rollback regressions from
that lifecycle test; the earlier public RPC simulations did not exercise those
V1 branches. Qualify the intended token configuration and RPC failure recovery.

**M3 retains governance, real controller-signature verification and audit, and
adds production network/version and desktop qualification.** The Groth16
ceremony is removed from this proof layer's launch requirements. The selected
construction does not require a per-circuit ceremony or universal KZG SRS;
its ZK configuration, proof binding and implementation still require review.
Local proving keeps witness material on the device; public statement values,
message facts, network metadata and controller disclosures retain their
existing visibility. RPC state-read privacy also needs review.

A hash-based proof layer does not make the complete system quantum-safe:
account/controller signatures, note encryption and Starknet's other security
assumptions remain separate. Acceptance of this ADR records the direction;
it does not mark the production port, privacy audit or mainnet rollout complete.

## Decision history

- 2026-09-20: Selected S-two ZK following standalone and V2 experiments.
- 2026-09-20: Revised after genuine V1 proofs passed all three local workload
  checks and the ordinary proof succeeded on Sepolia. Replaced the assumption
  that Templar must wait for PROOF2 with a demonstrated PROOF1 baseline.
- 2026-09-20: Ordinary pool lifecycle and four adversarial transaction checks
  passed on Sepolia using the existing pool core and a native verifier adapter.
