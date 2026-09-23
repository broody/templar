# ADR-0024: Compact private client proofs with server-side PROOF2 wrapping

- Status: Proposed — both client routes verified end to end locally; Sepolia, hiding and
  review gates open
- Date: 2026-09-22
- Evidence updated: 2026-09-23 (PROOF2 wrapping, both client routes, R0 payment, lane packing)
- Deciders: broody
- If accepted, would amend: [ADR-0018](0018-stwo-private-proving.md) for the
  client/server proving split, private hash format and device assumptions;
  [ADR-0010](0010-single-phase-architecture.md) for the wrapping service role;
  [ADR-0014](0014-m2-statement-shape.md) for any revised public encoding.
- Current baseline: ADR-0018 remains Accepted. This proposal supersedes no
  accepted decision and authorizes no production format migration.

## Context

Templar targets ordinary desktops and, strategically, phones and browsers
through WebAssembly. Under the accepted architecture the client proves the whole
payment: the Cairo statement account in the virtual OS, then the recursive
PROOF1. With [bounded-memory proving](../../bench/bounded-memory/README.md), an
ordinary payment still takes **6.12 GiB / 22.7–23.1 s** on four cores of the
development host (9.00 GiB / 16.7 s without it). That is above the browser
budget and most phones.

A compact client proof keeps the private witness on the device and hands the
expensive Starknet-compatible wrapping to a service. The service sees the
client proof and public data, never the witness.

### What changed since the first version of this record

- **The wrapping capacity gate is gone.** The first version targeted PROOF1,
  whose log20 limit could not fit a wrapped client verifier. Starknet v0.14.4
  adds PROOF2, whose [large path](../../bench/m31-private-wrapper/proof2-large/README.md)
  (`privacy_recursive_prove_large`) accepts Cairo traces up to log25–29.
  StarkWare's sample transaction costs 87 s / 42.1 GiB on that path. Sepolia
  runs 0.14.4, but its gateway rejected PROOF2 on 2026-09-20. Mainnet's 0.14.4
  upgrade is scheduled for 2026-10-05, pending governance.
- **Two client routes now reach a verified PROOF2**, and a complete ordinary
  payment (R0) has been measured through one of them. See Evidence.

## Proposed decision

Continue toward a compact private client proof, verified by a Cairo account
executing in the virtual OS and wrapped by the server as PROOF2. Keep one
atomic on-chain spend and the accepted push-payment semantics.

**Preferred client route: a blinded stwo-circuits proof on an arithmetic-only
component set** (`eq` and `qm31_ops`, no lookup tables). The hardest
cryptography stays on StarkWare's maintained prover and verifier, the server
needs no intermediate verifier circuit, and one code line serves client,
bridge and PROOF2. The custom TMPZK002 protocol stays in parallel as a
fallback until the hiding question below is settled. Write the payment
relation once, so that both routes can use it.

### Private client statement

All privacy-sensitive validity rules belong in the client proof. These are
ownership, input commitment derivation and membership, nullifier derivation,
bounded integer conservation, output commitments and delivery bindings, and
the private conditions of supported controlled-note and ReturnNote operations.
Bind the statement to the chain, pool, token, protocol, hash and relation
versions and the exact public operation. The pool still checks that nullifiers
are unspent.

[R0](../../bench/m31-statement/privacy-contract.md) is the first bounded target:
two inputs, two outputs, one public token, depth-32 membership, no withdrawals,
controllers or external execution. Its restricted scope does not remove product
features. Unsupported variants must be rejected explicitly. Range checks use bit
decomposition, not lookup tables, because lookup multiplicities depend on the
witness.

### Server and pool boundary

The service receives the client proof, the public statement and the public
operation data. Spending and viewing keys, note openings, amounts, leaf
positions, Merkle paths and proof randomness stay on the client. The privacy
argument must cover the whole upload, repeated proofs and retries, and any
metadata the service API adds.

The wrapped computation verifies the client proof inside the account, against
a pinned circuit hash and parameter set. It binds the public statement to the
operation and emits the facts PROOF2 attests. A check in ordinary server code
is not sufficient. The server has no authority over ownership, conservation,
nullifiers or output validity. It can delay or censor, not forge.

The pool authenticates the expected account class and facts, checks known roots
and unused nullifiers, applies controller and settlement checks, and updates
state and balances atomically, as the accepted pool does today. With an M31
note tree, output appends must be authenticated from the current root and count
to the next, tied to the ordered output commitments. The historical input root
is not the current append root, and a server-chosen root must never be accepted
without verified append semantics.

### Hash format and compatibility

An M31-native private hash suite (Poseidon2-M31, 9-word digests) avoids
emulating felt252 hashing in the client proof. The R0 formats measured here are
**representative-cost experimental formats**, not a reviewed suite. Adoption
requires pinning:
- the domains and security target;
- the canonical multiword-to-felt encodings;
- versioned wallet, recovery and contract formats;
- a migration or fresh-pool plan that accounts for existing funds and notes.

## Evidence

All runs used the development host, four pinned workers for server stages, zero
swap, and a synthetic local chain-state fixture. **Nothing was submitted to any
network.**

### Wrapping

| Workload | Account (bridge) | Virtual OS | PROOF2 large path |
| --- | ---: | ---: | ---: |
| StarkWare sample transaction | — | — | 87 s / 42.1 GiB |
| Custom route: circuit A verifying a TMPZK002 membership proof | 5.80M steps | 8.13M steps | 142 s / 66.0 GiB |
| stwo-circuits, stock components, membership | 5.06M steps | 7.22M steps | 140 s / 63.1 GiB |
| stwo-circuits, arithmetic-only, membership | 3.38M steps | 4.93M steps | 116 s / 52.2 GiB |
| stwo-circuits, arithmetic-only, R0 payment | 3.77M steps | 5.42M steps | 139 s / 64.2 GiB |
| **Same, lane-packed hashing (log19)** | 3.53M steps | 5.13M steps | **117.5 s / 55.0 GiB** |

- Every PROOF2 is accepted by the V2 verifier. Each run rejects a changed output, a
  flipped proof byte and a truncated proof.
- Every OS capture emits exactly the independently computed message.
- The custom route additionally needs circuit A (67 s / 39.9 GiB) to verify the
  client proof before the account runs.
- Evidence: [client port](../../bench/m31-private-wrapper/client-port/README.md) and its
  results for [proving-stack](../../bench/m31-private-wrapper/client-port/results/proving-stack/README.md),
  [stock](../../bench/m31-private-wrapper/client-port/results/stwo-client-stock/README.md),
  [arithmetic](../../bench/m31-private-wrapper/client-port/results/stwo-client-arith/README.md)
  [R0](../../bench/m31-private-wrapper/client-port/results/stwo-client-r0/README.md)
  and [R0 lane-packed](../../bench/m31-private-wrapper/client-port/results/stwo-client-r0-lanes/README.md).

### Client

| Client workload | Threads | Peak memory | Proving |
| --- | ---: | ---: | ---: |
| Original pipeline, ordinary payment (bounded) | 4 | 6.12 GiB | 22.7–23.1 s |
| Original pipeline, ordinary payment (default) | 4 | 9.00 GiB | 16.7 s |
| TMPZK002 membership, native / Chrome WASM | 1 | 53 MiB / 63 MiB linear | ~1.0 s / ~2 s |
| stwo-circuits membership, stock components | 1 | 2.75 GiB | 15.5 s |
| stwo-circuits membership, arithmetic-only (default / bounded) | 1 | 0.56 / 0.28 GiB | 2.5–10 s |
| R0 payment, arithmetic-only (default / bounded) | 4 | 2.2 / 1.1 GiB | 2.5–3.8 / 4.4–5.2 s |
| **R0 payment, lane-packed hashing (default / bounded)** | 4 | **1.1 / 0.54 GiB** | 2.0–3.6 / 2.4–2.6 s |

The R0 client proves:
- ownership keys;
- input commitments;
- two independent depth-32 paths to one root;
- nullifiers;
- output commitments;
- u128 amounts, range-checked by bits and nonzero;
- integer conservation.

The 92-limb public statement is emitted directly, and the account binds it for
the pool with a felt252 Poseidon binding.

Checks:
- The circuit matches a native reference, and broken witnesses fail.
- The bridge rejects 14 altered inputs, including a claimed sum moved onto an
  absent component.

Lane packing runs four Poseidon2 permutations per QM31 row, which takes R0 from 631k to 295k
rows (log19) with the same statement. log18 would need single-permutation tree nodes, a
format change.

### Implementation state

- **Fork.** The arithmetic-only profile and the bounded-memory proving mode live on our
  fork (`broody/proving`, branch `templar/arithmetic-profile`, on upstream `5a7c5ed`).
  - An absent component has log size 0, which the circuit hash commits.
  - Verifiers must reject a nonzero claimed sum for an absent component.
  - Bounded-memory proofs are identical to default ones.
  - Upstream suites pass, plus new profile and equality tests.
  - The fork is unreviewed. Its changes are proposed upstream in broody/templar#2 (draft).
- **Custom route.** The TMPZK002 membership construction has
  [scoped math](../../bench/m31-private-e2e/independent-math-review.md) and
  [PCS](../../bench/m31-private-e2e/independent-pcs-review.md) reviews, which found no
  acceptance bypass or single-proof disclosure under their assumptions. Circuit A
  has no independent review yet.

## Hiding

The two routes differ most here.

- **stwo-circuits** hides the witness with upstream row padding, 45 random rows
  per component. That is an entropy-budget argument, not a proof. The
  arithmetic-only profile removes the lookup tables whose multiplicities would
  leak, so the question narrows to whether padding hides `eq` and `qm31_ops`,
  including their LogUp interaction columns. It is open (broody/templar#2).
- **TMPZK002** uses polynomial masking and salted commitments with the research
  reviews above. Its unrestricted adaptive multi-proof argument is open.

Until one route has an accepted hiding argument, the uploaded proof's privacy is
**not established**. A server-generated outer proof cannot restore privacy lost
in the upload.

## Consequences and alternatives

- **Client.** Client cost drops roughly 8–11× in memory and 5–9× in time for an
  ordinary payment, which makes browser and phone proving plausible. WASM and
  whole-wallet budgets still need measurement.
- **Server cost.** Wrapping costs ~125 s and ~55 GiB per payment on the server,
  close to the PROOF2 path's fixed floor.
- **Service dependency.** Wrapping adds a dependency for availability, latency and
  pricing. A service can delay or censor and see network metadata, but cannot learn
  the witness or forge a transition. Specify retry behavior and support independent
  or self-operated wrappers, so that no single service holds pool authority.
- **PROOF2 dependency.** The route depends on PROOF2 availability: gateway
  acceptance on Sepolia, and mainnet 0.14.4.
- **Maintenance.** The stwo-circuits route needs our fork until upstream offers an
  arithmetic-only profile. The custom route needs its own protocol, prover, verifier
  and circuit A maintained and reviewed indefinitely.
- **Alternative: keep the accepted local pipeline.** It preserves tested semantics and
  needs no service, but still needs memory work. It remains the integration baseline
  while this proposal is open.
- **Alternatives rejected.** Sending witnesses to a remote prover violates the privacy
  boundary. A tree-only M31 migration retains substantial felt252 cost
  ([measurements](../../bench/m31-tree/README.md)).

## Acceptance criteria

Promote to Accepted only after each gate has recorded evidence and the resulting
architecture is approved. Current status in brackets.

1. **Complete ordinary client proof.** [Done for measurement: R0 implemented,
   verified without the witness, adversarial witnesses rejected, native repeats
   measured. Open: WASM repeats, upload sizes against an explicit budget,
   production formats (gate 6).]
2. **Actual server verification.** [Done locally: the client proof is verified in the
   account, the OS emits exact facts, PROOF2 is verified. Checks cover wrong circuit
   hash, context, statement fields, absent-component sums and malformed proofs.
   Open: operational cost against a stated budget.]
3. **Sepolia payment acceptance.** [Open.] Complete an ordinary payment lifecycle
   through the actual wrapper and pool: funded inputs, output recovery and respend,
   correct state transitions, and rejection of replays and wrong bindings. This
   includes authenticated M31-tree appends and their on-chain cost, which is not yet
   measured. It needs a synced node and gateway acceptance of PROOF2.
4. **Hiding.** [Open.] An accepted argument that the uploaded client proof hides the
   witness, for the selected route and the complete transcript, including repeated
   proofs and retries (broody/templar#2 for stwo-circuits).
5. **Review.** [Open.] Independent review of the selected route's changed components:
   the fork's arithmetic-only profile and bounded-memory mode, the bridge and account,
   the R0 relation. For the custom route, circuit A too.
6. **Format and operational decision.** [Open.] Pin the hash and note versions,
   migration or fresh-pool plan, service availability and retry behavior, and extend
   to controlled notes and ReturnNote before claiming feature parity.

Until then, this record documents a proposed direction with strong local evidence.
ADR-0018 and the accepted note, recovery, controller and ReturnNote semantics
remain in force. Production integration, an independent security audit and
device qualification remain separately tracked requirements.
