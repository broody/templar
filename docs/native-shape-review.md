# Re-evaluating 4/4/2 under native proving

Date: 2026-09-21. This is pathfinding evidence and a recommendation, not an
adopted replacement for the tested pool format or a production desktop claim.

**4/4/2 is an application limit, not the native prover's note-count ceiling.**
Larger controlled statements verified with the same pinned native PROOF1 prover
and local verifier. The practical limit is shaped by memory, execution budget,
settlement cost and wallet policy. It should not be inferred from a large machine
success or from a Cairo constant alone.

## Why the original decision needs revision

[ADR-0014](adr/0014-m2-statement-shape.md) selected 4/4/2 based on fixed Groth16
circuits, emulated Poseidon constraints, proving-key size, a phone target, and
one circuit/ceremony. Those arguments do not set the corresponding limit for a
Cairo program proved by the native recursive pipeline. One bounded Cairo program
can execute varying counts while emitting the same eight public scalars. Counts
and all operation details remain authenticated by the statement binding.

The private program still has real budgets. The
[pinned native prover](https://github.com/starkware-libs/sequencer/blob/e6b6fd2e9932909107833579e5b6efd6c75fa0af/crates/starknet_transaction_prover/src/proving/virtual_snos_prover.rs)
enforces virtual execution gas; the
[pinned V1 proof configuration](https://github.com/starkware-libs/proving-utils/blob/3035dd00421daa541894297bd754db6e2787807b/crates/privacy_circuit_verify/src/consts.rs)
fixes trace and recursion parameters. These are resource constraints, not a
four-note interface. We have not located the cryptographic maximum note count.

## Measured comparison

Both variants allow at most 64 inputs, 64 outputs and 32 withdrawals in one
program, but the wallet supplies only active witnesses. The padded variant hashes
zero-filled arrays to those maxima. The counted variant hashes explicit counts
followed by active fixed-width legs, using Cairo's Poseidon span implementation.
Both retain controller/policy commitments, actual withdrawal destinations, exact
delivery digests, expiry/nonce binding and the ordinary/controlled distinction.

| Inputs / outputs / withdrawals | Padded to 64/64/32 | Counted active entries |
| --- | ---: | ---: |
| 1 / 2 / 0 | 20.11 s / 15.27 GiB | 20.53 s / 13.62 GiB |
| 4 / 4 / 2 | 21.17 s / 15.42 GiB | 20.03 s / 14.47 GiB |
| 8 / 8 / 4 | 20.72 s / 15.35 GiB | 19.12 s / 14.27 GiB |
| 16 / 16 / 8 | OOM at 16 GiB cap | 19.85 s / 15.38 GiB |
| 32 / 32 / 16 | OOM at 16 GiB cap | OOM at 16 GiB cap |
| 64 / 64 / 32 | OOM at 16 GiB cap | OOM at 16 GiB cap |
| 32 / 2 / 0 | OOM at 16 GiB cap | OOM at 16 GiB cap |
| 1 / 32 / 0 | 19.84 s / 15.33 GiB | 20.21 s / 14.45 GiB |

Every successful row includes local cryptographic verification and exact public
message checks. Each measurement is one fresh prover run on four pinned cores,
under a 16 GiB cgroup cap with no swap. Request time includes virtual execution
and RPC reads; verifier-process memory is separate. Failures marked OOM are
confirmed by `Result=oom-kill` and a 16 GiB cgroup peak, rather than inferred from
a dropped HTTP connection. Two additional native executions per variant reject
an over-cap count and the previous protocol version.

These use **synthetic notes and synthetic tree roots**, through new statement
accounts declared on Sepolia. They are not funded pool spends. The pool verifier
and existing controller lifecycle remain unchanged. Signature verification and
settlement gas for larger spends have not been qualified. A 16 GiB process cap
on the large host is not a physical 16 GiB desktop test.

## Implications

1. **Remove mandatory padding in the next reviewed format.** Raising a fixed
   padded ceiling charges ordinary small payments for unused entries. Counted
   fixed-width legs keep the encoding unambiguous without that work. Production
   adoption must update the statement, public pool binding and controller signer
   together, with version separation and differential tests.
2. **Treat the three limits independently.** Inputs need depth-32 membership
   work and nullifier checks. Outputs need commitment validation and, at
   settlement, encrypted publication and tree insertion. Withdrawals need public
   token transfers. The 32-output success does not demonstrate 32-input capacity.
3. **Use device-appropriate wallet batches below protocol limits.** Do not make
   a wallet attempt the largest permitted statement whenever many notes exist.
   Select a supported memory profile, leave OS/browser headroom, and split large
   consolidations when necessary. The current duplicate-input check is quadratic;
   review a canonical ordering approach before much larger input sets.
4. **Qualify a larger cap through actual settlement before enabling it.** A
   counted 8/8/4 bundle is a reasonable next integration candidate, while the
   16/16/8 result shows additional proving capacity on a machine with enough RAM.
   The 32-output case warrants a separate output-cap/gas test. Test worst-case
   combined shapes, fees, token callbacks, delivery, viewing, recovery, controller
   approval and intended wallet transport; do not extrapolate from one axis.
5. **Keep desktop memory reduction a priority.** Even the successful small
   counted payment uses roughly 14 GiB. A successful 16/16/8 proof at roughly
   15 GiB leaves too little room on a desktop with 16 GiB total RAM. Larger
   batching improves consolidation and can amortize proof verification, but does
   not itself solve the prover's baseline footprint.

The tested live pool stays at 4/4/2. This review supports changing the encoding
and qualifying larger resource-informed caps; it does not silently upgrade its
ABI, policy signer or pinned statement class.

## Evidence

- [Padded experiment](../bench/native-shapes/README.md), [measurements](../bench/native-shapes/results/measurements.md), [source/prover hashes](../bench/native-shapes/results/evidence.json).
- [Counted experiment](../bench/native-counted-shapes/README.md), [measurements](../bench/native-counted-shapes/results/measurements.md), [source/prover hashes](../bench/native-counted-shapes/results/evidence.json).
- [Funded controlled lifecycle](../bench/controlled-push-e2e/README.md): real controller signatures, recovery and four native spends; five on-chain rejections; 55 Python and 68 Cairo tests.
