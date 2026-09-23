# ADR-0024: Compact private client proofs with server-side PROOF2 wrapping

- Status: Accepted architecture (2026-09-23); hiding argument, review, formats and production
  qualification tracked separately (see Qualification gates)
- Date: 2026-09-22; accepted 2026-09-23
- Evidence updated: 2026-09-23 (PROOF2 wrapping, both client routes, R0 V2 payment with
  withdrawals, lane packing, live Sepolia run)
- Deciders: broody
- Amends: [ADR-0018](0018-stwo-private-proving.md) for the client/server proving split,
  private hash format and device assumptions; [ADR-0010](0010-single-phase-architecture.md) for
  the wrapping service role; [ADR-0014](0014-m2-statement-shape.md) for the R0 public encoding.
- Baseline: ADR-0018's local pipeline remains the tested integration baseline until the
  gates below close. This record authorizes no production format migration.

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
  payment (R0 V2: transfers, partial and full withdrawals) has been measured through
  one of them. See Evidence.
- **The route ran live on Sepolia up to the gateway** (2026-09-23): real deposits, a
  wallet proof built from on-chain events, the account executed in the virtual OS on
  live state, and PROOF2. The signed relayer transaction succeeds in simulation, and
  the gateway rejects it only for its proof version (`PROOF_VERSION_NOT_ALLOWED`).

## Decision

Adopt a compact private client proof, verified by a Cairo account executing in
the virtual OS and wrapped by the server into a Starknet proof. Keep one atomic
on-chain spend and the accepted push-payment semantics. The client proves every
private rule; the server only wraps.

The outer proof is PROOF2's large path today. The small log20 path (PROOF1's
geometry, accepted by both gateways now) is under evaluation for the same
account; see Consequences.

**Preferred client route: a blinded stwo-circuits proof on an arithmetic-only
component set** (`eq` and `qm31_ops`, no lookup tables). The hardest
cryptography stays on StarkWare's maintained prover and verifier, the server
needs no intermediate verifier circuit, and one code line serves client,
bridge and PROOF2. The custom TMPZK002 protocol stays in parallel as a
fallback until the hiding question below is settled. The payment relation is
written once, so that both routes can use it.

### Private client statement

All privacy-sensitive validity rules belong in the client proof. These are
ownership, input commitment derivation and membership, nullifier derivation,
bounded integer conservation, output commitments and delivery bindings, and
the private conditions of supported controlled-note and ReturnNote operations.
Bind the statement to the chain, pool, token, protocol, hash and relation
versions and the exact public operation. The pool still checks that nullifiers
are unspent.

[R0](../../bench/m31-statement/privacy-contract.md) is the first bounded target.
R0 V2 has two inputs, two output slots (each active or not), at most one public
withdrawal, one public token and depth-32 membership. It has no controllers or
external execution. One circuit covers transfers, partial and full withdrawals.
Its restricted scope does not remove product features; unsupported variants must
be rejected explicitly. Range checks use bit
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

Local runs used the development host, four pinned workers for server stages,
zero swap and a synthetic chain-state fixture. The live Sepolia run is listed
separately below.

### Sepolia (2026-09-23)

[bench/m31-sepolia](../../bench/m31-sepolia/README.md): an option-A pool with
frontier storage and single-permutation nodes, the R0 V2 statement account, a
PROOF2 fact adapter and a synthetic token, all deployed on Sepolia.

| Stage | Result |
| --- | --- |
| 4 deposits; on-chain commitments equal the wallet's | done |
| Wallet proof from the pool's events, 4 threads, bounded | log18, 4.7 s, 0.30 GiB |
| Account in the virtual OS on live state | 3.36M steps, 11.8 s, exact message |
| PROOF2 | 118.8 s, 52.5 GiB, 250,814 bytes, verified; 9 facts checked |
| Signed relayer `apply_spend`, simulated with validation | succeeds: adapter fact check, root, nullifiers, append |
| Gateway | `PROOF_VERSION_NOT_ALLOWED` (PROOF2 not enabled) |

The transfer's fee from a Sierra 1.7 relayer is 134.9M L2 gas, **3.12 STRK** at
Sepolia prices. About 75M of that is the fixed per-proof charge
(`gas_per_proof`), and `apply_spend` is 52.2M. Deposits are 70.4M, 1.48 STRK.

### Wrapping

| Workload | Account (bridge) | Virtual OS | PROOF2 large path |
| --- | ---: | ---: | ---: |
| StarkWare sample transaction | — | — | 87 s / 42.1 GiB |
| Custom route: circuit A verifying a TMPZK002 membership proof | 5.80M steps | 8.13M steps | 142 s / 66.0 GiB |
| stwo-circuits, stock components, membership | 5.06M steps | 7.22M steps | 140 s / 63.1 GiB |
| stwo-circuits, arithmetic-only, membership | 3.38M steps | 4.93M steps | 116 s / 52.2 GiB |
| stwo-circuits, arithmetic-only, R0 payment | 3.77M steps | 5.42M steps | 139 s / 64.2 GiB |
| **Same, lane-packed hashing (log19)** | 3.53M steps | 5.13M steps | **117.5 s / 55.0 GiB** |
| Same, single-permutation tree nodes (experimental format, log18) | 3.39M steps | 4.96M steps | 120.3 s / 54.4 GiB |
| Same, after the review fixes (optimized, pruned verifier) | 1.99M steps | 3.32M steps | 113.1 s / 52.4 GiB |
| R0 V2 with withdrawals, full withdrawal | 2.05M steps | 3.41M steps | 117.1 s / 50.9 GiB |
| R0 V2 transfer, live Sepolia state | — | 3.36M steps | 118.8 s / 52.5 GiB |

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
  [R0 lane-packed](../../bench/m31-private-wrapper/client-port/results/stwo-client-r0-lanes/README.md)
  and [R0 single-permutation nodes](../../bench/m31-private-wrapper/client-port/results/stwo-client-r0-compress/README.md).

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
| R0, single-permutation tree nodes (experimental format) | 4 | 0.58 / 0.30 GiB | 1.4–4.1 / 1.7–2.0 s |
| R0 V2 (withdrawals), transfer | 4 | 0.59 / 0.31 GiB | ~1.5–2 s (4.7 s in the live run) |

The R0 client proves:
- ownership keys;
- input commitments;
- two independent depth-32 paths to one root;
- nullifiers;
- output commitments;
- u128 amounts, range-checked by bits and nonzero;
- integer conservation, including the public withdrawal;
- inactive output slots: zero amount, zero commitment, no delivery digest.

The 112-limb public statement (V2) is emitted directly, and the account binds it
for the pool with a felt252 Poseidon binding (`TMR0_BIND_V2`).

Checks:
- The circuit matches a native reference for every shape, one topology serves all
  shapes, and broken witnesses fail.
- The bridge rejects 16–17 altered inputs per shape, including a claimed sum moved
  onto an absent component and a changed withdrawal.

Lane packing runs four Poseidon2 permutations per QM31 row, which takes R0 from 631k to 295k
rows (log19) with the same statement. An experimental single-permutation tree-node format
(truncated Poseidon2, depth still 32) reaches 175k rows (log18); it needs review before
adoption.

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

- **stwo-circuits** hides the witness with row padding. Upstream's 45 rows per
  component (queries + 10) leave FRI out, as the
  [math review](../../bench/m31-private-wrapper/client-port/reviews/math-review.md)
  found (H1). Each FRI layer opens the query's whole coset, about 1,700 extra
  values per R0 proof. Our provers now size padding for every opened value,
  2,390 iterations at a 2¹⁸ trace, and assert that each proof fits. This costs
  nothing measurable
  ([results](../../bench/m31-private-wrapper/client-port/results/stwo-client-r0-blinding/README.md)).
  The count is necessary, not sufficient: **H2**, found by test, was that the add-only
  blinding rows left `dst − op0 − op1` unblinded, so every proof revealed about 156
  witness-only values. It is fixed in the fork with a mul blinding row, and a per-component
  rank audit now finds no unblinded column combination
  ([results](../../bench/m31-private-wrapper/client-port/results/hiding-leak/README.md)). All
  earlier R0 proofs, including the Sepolia run's, predate the fix. The arithmetic-only profile removes
  the lookup tables whose multiplicities would leak. What remains is a
  simulation argument over the full transcript: interaction and composition
  openings, unsalted Merkle leaves, and correlations (broody/templar#2).
- **TMPZK002** uses polynomial masking and salted commitments with the research
  reviews above. Its unrestricted adaptive multi-proof argument is open.

Until one route has an accepted hiding argument, the uploaded proof's privacy is
**not established**. A server-generated outer proof cannot restore privacy lost
in the upload.

## Consequences and alternatives

- **Client.** Client cost drops roughly 8–11× in memory and 5–9× in time for an
  ordinary payment, which makes browser and phone proving plausible. WASM and
  whole-wallet budgets still need measurement.
- **Server cost.** Wrapping costs ~119 s and ~52 GiB per payment on PROOF2's
  large path, close to its fixed floor (87 s / 42 GiB for StarkWare's sample).
  The small log20 path is under evaluation. A trace of the live transfer's PIE has
  only three components one power of two over log20. They are driven by the client
  proof's shape: its Blake Merkle openings, and the OS hashing its 29,866 calldata
  felts with Poseidon. PROOF1-geometry proving took ~12 s / 14 GiB in the PROOF1
  Sepolia run.
- **Service dependency.** Wrapping adds a dependency for availability, latency and
  pricing. A service can delay or censor and see network metadata, but cannot learn
  the witness or forge a transition. Specify retry behavior and support independent
  or self-operated wrappers, so that no single service holds pool authority.
- **PROOF2 dependency.** The large path depends on PROOF2 availability: gateway
  acceptance (rejected on Sepolia on 2026-09-20 and 2026-09-23) and mainnet 0.14.4.
  Fitting the small log20 path would remove it.
- **Account class size.** The sequencer rejects classes whose compiled CASM exceeds 81,920
  felts; a local OS run never checks this. The R0 V2 account is 60,608 CASM felts, and the
  bridge build enforces the limit.
- **Declaration cost.** Declaring a class costs 40,960 L2 gas per Sierra + CASM felt. On
  Sepolia that was 77.5 STRK for the statement account (once per circuit version) and 73.0 STRK
  for the pool. A compact permutation (`compact_perm`) halves the pool's cost for +4.5% gas
  per call.
- **On-chain tree cost.** Measured ([bench/m31-pool](../../bench/m31-pool/README.md)) and
  confirmed on Sepolia (`apply_spend` 52.2M simulated against 51.8M locally).
  - A pool appending to an on-chain M31 tree, with single-permutation nodes and both outputs
    appended in one pass, costs 53.3M L2 gas per 2-in/2-out transfer on average. That is 4.6×
    the felt252 reference pool's 11.5M: 1.11 against 0.24 STRK at mainnet median prices.
  - A deposit costs 57.7M against 6.3M (1.20 against 0.13 STRK).
  - A full withdrawal costs about the same as today (0.039 against 0.029 STRK).
  - Hashing is over 90% of it.
  - These figures hold only for callers on an account class of Sierra 1.7 or later. An older
    account makes the whole call tree bill in Cairo steps, about 2.7× more.
  - Where appends run remains a format decision (gate 6): on chain (measured, used on
    Sepolia), batched off chain and proven, or unchanged felt252.
- **Maintenance.** The stwo-circuits route needs our fork until upstream offers an
  arithmetic-only profile. The custom route needs its own protocol, prover, verifier
  and circuit A maintained and reviewed indefinitely.
- **Alternative: keep the local pipeline.** It preserves tested semantics and needs no
  service, but needs 6–9 GiB on the client. It remains the integration baseline until the
  gates below close.
- **Alternatives rejected.** Sending witnesses to a remote prover violates the privacy
  boundary. A tree-only M31 migration retains substantial felt252 cost
  ([measurements](../../bench/m31-tree/README.md)).

## Qualification gates

The architecture is accepted on the evidence above. Production use requires each
gate below to have recorded evidence. Current status in brackets.

1. **Complete ordinary client proof.** [Done for measurement: R0 implemented,
   verified without the witness, adversarial witnesses rejected, native repeats
   measured. Open: WASM repeats, upload sizes against an explicit budget,
   production formats (gate 6).]
2. **Actual server verification.** [Done locally: the client proof is verified in the
   account, the OS emits exact facts, PROOF2 is verified. Checks cover wrong circuit
   hash, context, statement fields, absent-component sums and malformed proofs.
   Open: operational cost against a stated budget.]
3. **Sepolia payment acceptance.** [Done up to the gateway. The deployment, deposits,
   wallet proof from chain events, virtual OS on live state, PROOF2 and the relayer
   transaction are all verified. On-chain M31 appends are measured. Open: an included
   proof-carrying spend, then the withdrawals, replay and wrong-binding rejections and
   respend. These need PROOF2 gateway acceptance, or the log20 small path.]
4. **Hiding.** [Open.] An accepted argument that the uploaded client proof hides the
   witness, for the selected route and the complete transcript, including repeated
   proofs and retries (broody/templar#2 for stwo-circuits).
5. **Review.** [Open.] Independent review of the selected route's changed components:
   the fork's arithmetic-only profile and bounded-memory mode, the bridge and account,
   the R0 relation. For the custom route, circuit A too.
6. **Format and operational decision.** [Open.] Pin the hash and note versions,
   migration or fresh-pool plan, service availability and retry behavior, and extend
   to controlled notes and ReturnNote before claiming feature parity.

Until then, ADR-0018's pipeline remains the integration baseline, and the
accepted note, recovery, controller and ReturnNote semantics remain in force.
**The uploaded proof's privacy is not established until gate 4 closes; no
production deployment may send client proofs to a service before then.** Production integration, an independent security audit and
device qualification remain separately tracked requirements.
