# ADR-0024: Compact private client proofs with server-side PROOF1 wrapping

- Status: Proposed — pathfinding; production adoption criteria remain open
- Date: 2026-09-22
- Evidence updated: 2026-09-23
- Deciders: broody
- If accepted, would amend: [ADR-0018](0018-stwo-private-proving.md) for the
  client/server proving split, private hash format and device assumptions;
  [ADR-0010](0010-single-phase-architecture.md) for the wrapping service role;
  [ADR-0014](0014-m2-statement-shape.md) for any revised public encoding.
- Current baseline: ADR-0018 remains Accepted. This proposal supersedes no
  accepted decision and authorizes no production format migration.
- Evidence: [private membership results](../../bench/m31-private-e2e/results/README.md),
  [protocol review](../../bench/m31-statement/end-to-end-protocol-review.md),
  [source review](../../bench/m31-private-e2e/source-review.md),
  [wrapper compatibility assessment](../../bench/m31-private-e2e/wrapper-compatibility.md),
  [independent math challenge](../../bench/m31-private-e2e/independent-math-review.md),
  [bounded PCS review](../../bench/m31-private-e2e/independent-pcs-review.md),
  [wrapper capacity measurements](../../bench/m31-private-wrapper/bridge-capacity/README.md).

## Context

Templar targets ordinary desktops, with browser proving through WebAssembly as
a strategic capability. Proving the full payment through Cairo and the virtual
OS on the client still exceeds the desired browser memory budget. A compact
client proof could keep private data on the device while moving expensive
Starknet-compatible wrapping to a service.

The isolated M31 experiment now proves knowledge of a private leaf preimage
and its depth-32 membership path. Its verifier receives only the public chain,
pool and root plus proof bytes. One path requires 65 active Poseidon2
permutations in this relation. Three fresh native proofs and three browser
proofs pass a separate native verifier; the browser also accepts a native
proof. Unit and external checks reject invalid traces and altered artifacts.

| Membership client | Proving time | Proving memory | Proof size |
| --- | ---: | ---: | ---: |
| Native, serial CPU backend | 1.17–1.20 s | 63–64 MiB peak RSS | 3.39–3.42 MiB |
| Chrome, one WASM worker | 1.89–2.12 s | 79.94 MiB linear-memory high water | 3.43–3.46 MiB |

These runs use the development workstation, not qualified consumer hardware.
WASM linear memory excludes browser overhead: the sampled Chrome process set
peaks at about 1.08 GiB summed RSS and 466.5 MiB summed PSS. The experiment
omits payment ownership derivation, amounts, nullifiers, conservation, outputs,
delivery binding, controllers and ReturnNotes. Its footprint is not a complete
2-in/2-out payment estimate.

The construction is a custom protocol using S-two fields, circle FFTs and FRI
folds, with polynomial masking and private salted commitments. It is not the
stock S-two proof format. The existing protocol and source reviews support an
isolated research milestone under the stated classical explicitly programmable
random-oracle and CSPRNG assumptions, with a 96-bit classical RO-work target.
The independent challenge review qualifies the numerical claim as a
single-proof knowledge-error bound in the classical programmable random-oracle
model, not an unconditional practical-forgery work estimate. Unrestricted
adaptive multi-proof service composition remains open. This is not a 128-bit
security claim or a production cryptographic audit.

## Proposed decision

Continue pathfinding toward a compact private client proof followed by
server-side wrapping into the existing native PROOF1 acceptance route. Keep
one atomic on-chain spend transaction and the accepted push-payment semantics.
Record the following boundaries before choosing a production format.

### Private client statement

All privacy-sensitive validity rules belong in the client proof: ownership,
input commitment derivation and membership, correct nullifier derivation,
bounded integer conservation, output commitments and delivery bindings, and
the private conditions of supported controlled-note and ReturnNote operations.
Bind the statement to the chain, pool, token, protocol/hash/relation versions
and exact public operation, including withdrawals, fees and execution intent
when supported. The pool still checks whether nullifiers are unspent.

Use the [ordinary R0 requirements](../../bench/m31-statement/privacy-contract.md)
as the next bounded client target: two inputs, two outputs, one public token,
depth-32 membership and no external execution or controller. R0's restricted
scope does not remove existing product features. Unsupported operation
variants must be rejected explicitly. Any new range or lookup machinery needs
privacy analysis covering its entire contribution to the proof transcript.

### Server and pool boundary

The service receives the inner proof, public statement and public operation
data. Spending/viewing keys, note openings, private amounts, consumed leaf
positions, Merkle paths and proof randomness remain on the client. The privacy
argument must cover the full upload, repeated proofs and retries, including
metadata or diagnostic exports introduced by the service API.

The outer proved computation must verify the complete inner proof against a
trusted verifier identity and parameter set, bind its public statement to the
operation, and produce the expected PROOF1 facts. A successful check in ordinary
server code is insufficient. The server has no discretionary authority over
ownership, conservation, nullifiers or private output validity.

The pool authenticates the approved outer program/OS/statement identities and
facts, checks accepted roots and unused nullifiers, applies existing controller
and settlement checks, and updates state and token balances atomically. Any
server-computed M31 append must also be proved and tied to the current root,
count and exact ordered funded commitments. The historical input membership
root is distinct from the current append root; simply accepting a returned
root would make the server a trusted state operator.

### Hash format and compatibility

Evaluate an M31-native private hash suite to avoid costly felt252 emulation.
The measured membership leaf is experimental; it does not select production
note, ownership, commitment or nullifier formats. Pin the complete suite,
domains, security target and canonical multiword-to-felt encodings before
adoption. Changing tree hashes changes roots; changing note derivations also
requires versioned wallet, recovery and contract formats. Define a migration
or fresh-pool plan that accounts for existing funds and notes.

The present recursive adapter cannot accept the new proof unchanged. Its
hash/transcript, sample layout and composition representation differ. Pathfind
either a verifier circuit behind the existing Cairo bridge or a direct Cairo
verifier proved by the server. Both require reviewed implementation and actual
PROOF1 measurements. The frozen SHAKE construction uses 768-bit commitment
outputs and roughly 3.4 MiB proofs. A separately reviewed
[Blake candidate](../../bench/m31-private-blake/README.md) preserves its relation
and M31 application tree while using full Blake2s-256 authentication and
96-byte salts. It measures 52.7–54.5 MiB native RSS and 63.25 MiB WASM linear
memory, with approximately 2 MB proofs. Neither format is adopted by this ADR.

A representative public Blake hash workload has produced PROOF1 accepted by
the original verifier. That proves hash computations, not the complete private
proof verifier. A specialized server hash circuit also verifies natively and
in Cairo; checked M31 inversion reduces its Cairo steps by 15.37%. Its actual
OS workload still needs log22 components, beyond the preserved log20 wrapper.
An isolated enlarged configuration regenerates trusted roots but exhausts a
96 GiB server cap before producing a proof. Larger geometry requires different
trusted verifier parameters; no larger-proof acceptance has been established.
This ADR selects neither adapter route. Full private-proof wrapping remains
an implementation and capacity gate.

## Consequences and alternatives

- A compact private statement makes desktop and browser proving more plausible;
  the full payment and whole-wallet budgets still require measurement.
- Wrapping adds a dependency for availability, latency and pricing. A service
  can censor or delay requests and observe public-operation/network metadata,
  even when it cannot learn the private witness or forge a valid transition.
  Specify retry behavior and support independent wrapping providers or a
  self-operated wrapper without giving one service exclusive pool authority.
- M31 migration and a custom proof format add cryptographic review, wallet
  compatibility and verifier maintenance obligations. Production security
  parameters must be explicitly justified; benchmark success is not permission
  to reduce them. Controlled notes, ReturnNotes and recovery remain required
  qualification work for their supported release scope.
- Continuing the accepted local Cairo/PROOF1 architecture preserves its tested
  semantics and avoids a wrapping dependency, but still needs memory work.
  It remains the integration baseline while this proposal is unresolved.
- Sending private witnesses to a remote prover would violate the intended
  privacy boundary. A tree-only M31 migration also has insufficient evidence:
  the [mixed-workload and insertion measurements](../../bench/m31-tree/README.md)
  retain substantial felt252 cost and show expensive direct Cairo insertion.

## Acceptance criteria

Promote this ADR to Accepted only after the following evidence is recorded and
the resulting architecture decision is approved:

1. **Independent challenge review:** the fresh math and bounded-PCS reviews
   of the frozen membership construction are complete. They found no concrete
   native acceptance bypass or single-proof witness disclosure, subject to
   their explicit assumptions and scope. Resolve the remaining adaptive
   multi-proof service argument and review changed relation or wrapper
   components as they are introduced. These research reviews do not replace
   production security qualification.
2. **Complete ordinary client proof:** implement R0's ownership, independent
   membership paths, nullifiers, outputs, amount ranges/conservation and
   delivery/context binding. Verify without the witness, reject adversarial
   transitions, and measure repeated native and WASM proofs. Record total
   client memory, timings and upload sizes against an explicit desktop budget.
3. **Actual server verification:** feed the client artifact and public data
   through the selected wrapper, generate genuine PROOF1, and verify the exact
   bound facts. Negative cases must reject wrong verifier/program/context,
   altered operations and malformed proofs. Measure full server memory,
   execution/proving time, proof size and operational cost against a stated
   budget; acceptance by the Rust verifier alone does not satisfy this gate.
4. **Sepolia payment acceptance:** complete an ordinary payment lifecycle
   through the actual wrapper and pool acceptance path, with funded inputs,
   output recovery/respend, correct state transitions and replay/binding
   rejection. If adopting M31 state, include authenticated append integration.
   Confirm settlement costs and preserve receipts and artifact identities.
5. **Format and operational decision:** specify hash/note versions, migration,
   service availability/retry behavior and the remaining launch qualifications.
   Adopt only the scope supported by the evidence; production integration,
   independent security audit and broader device/feature qualification remain
   separately tracked requirements.

Until then, this record documents a promising proposed direction. ADR-0018 and
the accepted note, recovery, controller and ReturnNote semantics remain in
force. No statement capacity increase is made by this proposal.
