# Compact client proof and PROOF1 wrapping experiment

Status: synthetic Cairo interoperability passes, 2026-09-21. Client privacy
qualification and a complete PROOF1 round trip remain open. Further disclosure
diagnostics are deferred at the user's request. This is isolated pathfinding,
not an accepted architecture replacement or production privacy qualification.

The candidate moves Templar's private validity checks into a compact client
proof. A wrapping service receives only a zero-knowledge proof and its public
statement, verifies them inside an approved proving path, and produces native
PROOF1. The existing native prover remains the reference and fallback.

## Measured outcome

- Two saved synthetic Rust proofs pass the Cairo verifier and return the exact
  independently computed public commitment. Nine altered or malformed proofs
  are rejected; four focused serialization/transcript tests pass.
- Cairo verification takes 2.03–2.12 seconds and 0.77–0.78 GiB peak RSS, using
  4.85–4.91 million VM steps. These are two native execution measurements, not
  server proving latency or client payment measurements.
- The synthetic client baseline failed a 2 GiB cap. The same binary completed
  under an 8 GiB cap, at 2.61 GiB peak RSS and about 5.7–6.0 seconds per proof.
  Its upstream fixed lookup tables remain large even for this tiny relation.
  It uses ordinary upstream allocation behavior, not the earlier bounded-memory
  proving entry point. This is not a lower bound for a purpose-built AIR.
- The compiled virtual statement account is ready for integration. No native
  PROOF1 wrapping result, Sepolia deployment, 2-in/2-out payment AIR, or WASM
  qualification is claimed. The privacy prerequisite has not passed.
- A `sncast` Sepolia declaration dry-run succeeds, estimating 93.28 test STRK
  for declaration alone at the recorded prices. It submits no transaction and
  does not validate the statement's runtime invocation on-chain.

See [measurements](results/measurements.md), [bridge findings](bridge-findings.md),
and the [payment-statement preservation checklist](payment-statement.md).

The next engineering step is to declare and deploy the isolated synthetic
statement account in a supported test environment, then prove its invocation
through the unchanged native service and verify the resulting PROOF1 and message
binding. The pinned service has no state-override argument and its virtual OS
forbids declarations/deployments inside the transaction being proved. A local
executable verification does not complete this step. A reviewed client privacy
construction remains necessary before using wallet secrets or interpreting a
memory benchmark as a private-wallet result.

## Decision gates

1. Identify a supported zero-knowledge construction for the artifact leaving the
   client. Review the blinding, topology, public outputs, randomness and security
   parameters. A raw validity proof is not assumed to hide the witness.
2. Verify a tiny synthetic proof inside a Cairo wrapper and demonstrate the
   unchanged PROOF1 verification route. Pin the custom verifier identity and
   exact public statement; reject changed claims and corrupted proofs.
3. If those gates are feasible, build an ordinary 2-input/2-output candidate with
   the existing felt252/Poseidon format, two depth-32 membership paths, ownership,
   nullifiers, bounded amounts, conservation and ordered delivery bindings.
4. Measure the complete client privacy pipeline, including preprocessing and
   witness generation, single-thread execution, proof size, and browser/WASM
   memory. Measure server wrapping cost separately.

Do not promote a hash-only, non-ZK, shallow-tree or reduced-security benchmark
to evidence for the complete payment path. All initial inputs are synthetic;
no real wallet secrets or old private fixture witnesses enter this experiment.

## Responsibilities

- The client proof enforces private ownership, membership, nullifier derivation,
  amount bounds/conservation, output commitments, private policy preservation,
  and binding to exact context and actions.
- The wrapper's verification is itself proved. No operator assertion substitutes
  for cryptographic verification. The verifier configuration is fixed by the
  accepted statement identity, not supplied unchecked by the prover.
- The pool checks current nullifier freshness, accepted roots, public controller
  authorization/deadlines, actual token transfers and atomic return settlement.
- Delivery initially retains the existing ciphertext-digest binding. Proving
  encryption correctness is a separate change. Existing pool fees are paid by
  the public caller, outside private conservation.

The new service introduces availability, pricing and request-metadata concerns.
Its interface should allow alternate providers and self-hosting. The current
ADR-0018 commitment to fully local proving remains in force unless a subsequent
decision explicitly changes it.

`setup.py` copies the pinned dependencies into `target/direct-air` and records
the accepted outer prover/verifier hashes. Earlier archives and working copies
are preserved. Native builds and benchmarks run separately; hard memory caps
and zero swap remain required for reported measurements.
