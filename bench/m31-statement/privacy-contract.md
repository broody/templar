# Private client statement and server boundary

Status: **requirements and implementation gates; no hiding construction approved
or implemented by this document.** Recorded 2026-09-22 against
`0f5448bafe2885199482b8d5a512dc98745c5692`. The independent review of the latest
[hiding proposal](hiding-spec.md) is complete: **NO-GO for implementing gamma
as client privacy** ([hiding-review.md](hiding-review.md)) — a qualification
failure, with no practical attack claimed. The next specification path is the
[polynomial masking plan](polynomial-masking-plan.md). This document does not
supersede that review or promote this experiment into a production format.

The objective is a client artifact that an untrusted wrapping server can verify
without receiving private payment data. A server-generated outer proof cannot
restore privacy already lost when the client uploads its inner artifact.

The source observations below describe that recorded baseline. The subsequent
[version-2 context encoding repair](results/context-binding/README.md) passed
its scoped review and regression checks; it does not implement
the private relation or qualify hiding.

## 1. What the measured code establishes

The current artifact is a public arithmetic benchmark. Its
[`Envelope`](client/src/lib.rs) (lines 40–46) serializes the entire
[`PaymentStatement`](client/src/statement.rs) (lines 51–78): secrets, input
commitments, positions, sibling paths, amounts, and the deterministic pad seed.
`verify` calls `statement.validate()` (lib.rs:90–92). That host function derives
all sponge requests and checks the note hashes and both paths against the root
(statement.rs:106–139).

The AIR enforces permutation arithmetic and exports each input/output tuple to
LogUp (m31.rs:230–285). The verifier balances its claimed sum against **all
host-reconstructed request rows**, including padding (lib.rs:122–124;
m31.rs:203–214). It does not privately constrain the complete payment relation.
Removing private fields from serialization therefore requires new semantic
constraints and lookup accounting, not just a serializer change or extra pads.

The benchmark has two synthetic input notes and **no output-note relation or
conservation equation**. Its paths merge immediately at sibling leaves
(statement.rs:185–244). The 132-request measurements are not a complete 2-in/2-out
payment measurement and do not cover arbitrary independent paths or a hiding
construction. Existing artifacts remain evidence of their recorded workload.

## 2. First private-payment target: ordinary 2-in/2-out

Use one fixed experimental relation, called **R0** here: two ordinary inputs,
two ordinary outputs, depth-32 membership, one public token, no withdrawals, no
controller, and no external execution. These restrictions bound the experiment;
they do not remove controlled notes or ReturnNote from Templar's product scope.

The logical public input `x`, in order, is:

1. Experimental protocol/note-format identifier, hash-suite identifier, and
   fixed relation identifier (R0, depth 32, two inputs, two outputs).
2. Chain ID, pool address, and token address.
3. Accepted input membership root.
4. Ordered pair of input nullifiers.
5. Ordered pair of `(output commitment, delivery digest)` values.

The verifier selects the expected relation, parameters, and preprocessing from
its trusted configuration. A prover-supplied identifier does not authorize a
different circuit. Fixed shape implies no variable counts or unused slots in R0.
Unsupported operation variants must be rejected, not silently ignored. Exact
numeric identifiers and wire encodings are a subsequent reviewed specification.

Use the current 9-M31-word digest representation for the experimental M31 roots,
commitments, and nullifiers, with every word canonical (`0 <= word < 2^31-1`).
Felt-valued context and delivery digests require an injective encoding, such as
nine **consecutive** little-endian 28-bit limbs, with canonical felt/address
checks. Digest words must not be squeezed into one felt by modular reduction.
The **baseline** `felt_words` encoder dropped four bits per 32-bit chunk; the
version-2 repair replaced it with the consecutive-limb encoding and passed its
scoped review and regression checks
([results/context-binding/README.md](results/context-binding/README.md)).

The local witness `w` includes each input's spending secret, note randomness,
amount, leaf position and 32 siblings, and each output's receiving identity,
randomness and amount. Input commitments, authorization/nullifier keys and hash
requests are witness-derived. Proof blinding randomness is prover-local, fresh
per proof, and distinct from note randomness.

Keep input commitments and their positions out of `x`. The ledger publishes
commitments at creation; publishing which commitments are consumed would reveal
the spend linkage. Output commitments are public because they are newly created
ledger entries. Receiving addresses and private amounts are not public inputs.

Public ciphertexts accompany the operation. For this first relation, their
digests may retain the existing felt-valued delivery hash and enter `x` through
canonical limbs: hashing **public bytes** at the public wrapper/contract boundary
does not require felt arithmetic in the private AIR. The exact delivery hash,
canonical byte encoding, lengths and ordered commitment/digest association must
be pinned and checked. This is a proposed boundary, not demonstrated PROOF1
compatibility or a measured gas saving.

## 3. What R0 must prove privately

The intended semantics come from the accepted
[push specification](../../docs/push-payment-spec.md) and its executable
[controlled/ordinary statement](../controlled-push-e2e/cairo/src/statement.cairo)
(lines 35–68). An M31 migration needs reviewed domains and encodings; copying
felt domain tags or replacing the hash function alone is not a format review.

| Obligation | Required relation |
| --- | --- |
| Ownership | Derive spending authorization and nullifier authority from the input spending secret; derive the receiving identity and match the committed note. Preserve the distinction between a payer who knows an opening and an owner who can spend. |
| Input commitment | Bind context, token, amount, receiving identity and fresh note randomness, with ordinary controller/policy fields zero. The current `H(secret, amount)` cost fixture is not the push-ownership relation. |
| Membership | Boolean position bits select each left/right ordering, hash outputs connect across all 32 levels, and the result equals the public root. No adjacency/shared-spine assumption. |
| Nullifiers | Derive each public nullifier from the owner's nullifier authority, the same input commitment and the same position used by membership. Reject duplicate inputs/nullifiers. |
| Outputs | Recompute both public commitments from their private openings with the same context/token and ordinary conditions. Bind each to its ordered public delivery digest. |
| Amounts | Preserve nonzero u128 note amounts from the reference. Enforce integer ranges and `a_in[0] + a_in[1] = a_out[0] + a_out[1]` with explicit bounded limbs/carries. |
| Hash wiring | Constrain domain separation, framing, sponge absorption/padding, multi-block chaining, digest extraction and lookup connections. Valid independent permutation rows do not establish these relationships. |
| Public binding | Bind every element of `x`, with a canonical unambiguous transcript and exact equality to the public values later verified by the wrapper and pool. |

For u128 amounts, eight 16-bit limbs with constrained carries are one possible
representation to review; summing two amounts needs 129 bits. QM31 has
characteristic `2^31-1`, not a 124-bit prime modulus: extension-field addition
does not implement wide integer addition. The tiny host-checked amount bound in
the current cost fixture is not a token-format decision.

Delivery binding preserves the existing guarantee: the operation commits to
the exact ciphertext published for each output. It does **not** prove correct
encryption or recipient receipt. The receiver decrypts and checks the funded
commitment. Do not silently add encryption-correctness constraints to a memory
estimate for this milestone.

Pool fees in the current reference are charged separately to the public caller
([pool.cairo](../controlled-push-e2e/cairo/src/pool.cairo):112–115); network gas is
also separate. R0 has no hidden fee subtraction. Any future fee paid from private
value needs an explicit public recipient/amount binding and conservation term.

## 4. Server observation and authority

The server receives the complete serialized proof, `x`, and the public operation
data. The privacy argument must cover all of the following jointly:

- Base, interaction and composition commitments and all their transmitted OOD
  samples, queried values and Merkle decommitments.
- FRI commitments, fold-complement values, last-layer polynomial and nonces.
- Claimed lookup sums, public/configuration metadata, proof shape and every
  transcript-derived challenge and query position.
- Any extra upload, debug export, error response or retry artifact exposed by
  the service protocol. A private `statement.json` must not become an upload.

The server must not receive openings, leaf positions, paths, spending/viewing
keys, private amounts, private request lists, pad seeds or pad rows. This means
the current verifier's public request-boundary reconstruction must be replaced
by reviewed private relation wiring and balanced lookups. Publishing request
digests or partial sums requires analysis too; renaming them public inputs
does not establish privacy.

Hiding must be argued for the **actual R0 relation and complete transcript**,
including newly added semantic/range components. The permutation-only pad
analysis cannot automatically qualify those components. The source inventory
is [recorded separately](server-observation-inventory.md).

The formal review target is simulation from the real, fixed public statement
and permitted public/auxiliary data without the witness, under explicitly
stated cryptographic assumptions and transcript model. Comparing two executions
with different public statements, showing a rank bound, counting pad entropy,
or failing to recover a witness does not establish that property. Repeated
proofs, fresh randomness and the server's ability to choose requests must be
addressed. This document supplies requirements, not a proof or an audit verdict.

Public token, shape, ciphertext sizes, creation/spend timing, sender/relayer
metadata and any deliberate viewing/controller disclosure remain part of the
privacy model. Neither the proof nor this server boundary solves RPC access
privacy or network anonymity.

## 5. Public wrapper and pool responsibilities

The wrapper may verify the inner proof, authenticate the expected relation and
parameters, recompute public delivery/binding hashes, and package public facts.
All these checks must themselves be enforced by the verified outer computation
and its on-chain acceptance path; ordinary server code is not trusted authority.
No private validity rule in §3 may be deferred to the wrapping operator.

The pool must authenticate the resulting proof facts and expected verifier,
statement/class/OS identity and context; check accepted roots and unused
nullifiers against canonical state; bind actual operation data; and apply
nullifiers, funded outputs, public fees and token movement atomically.
The existing pool's responsibilities are visible at
[pool.cairo](../controlled-push-e2e/cairo/src/pool.cairo):95–130.

For a fully M31 tree, output appends need their own authenticated transition
from the **current** root/count to the next root/count, tied to the ordered
output commitments. This can be public server work proved by the wrapper.
Do not confuse the historical input membership root with the current append
root, and do not accept a server-chosen root without verified append semantics.
R0 first tests private spending against a fixed known tree; it does not claim
to have implemented deposit funding or stateful append integration.

The existing generic squared-Fibonacci recursion demonstration is separate
from an authentic M31-to-PROOF1 round trip. Its verifier also needs trusted
preprocessing-root authentication before reuse
([main.rs](../compact-recursion/client/src/main.rs):64–115). A locally accepted
generic recursive proof is not proof of acceptance by the fixed PROOF1 verifier.

## 6. Work order and pass criteria

1. **Source boundary and math review — complete.** The K3 source inventories
   are recorded ([server-observation-inventory.md](server-observation-inventory.md),
   [masking-api-inventory.md](masking-api-inventory.md)) and the independent
   math review is complete with verdict **NO-GO** for gamma as client privacy
   ([hiding-review.md](hiding-review.md), scope/conditions in
   [hiding-review-status.md](hiding-review-status.md)). The next step is the
   [polynomial masking plan](polynomial-masking-plan.md) as a specification
   path; no alternative hiding construction is approved.
2. **Repair public statement binding before reuse.** The context encoder/parser
   and version separation are [complete](results/context-binding/README.md).
   Encoding round trips and canonicality tests pass. High-bit changes missed
   by the old `+1` mutation tests, including the known chain/pool collisions,
   now reject. Authenticating expected relation/preprocessing identity in the
   generic recursive wrapper remains a separate open item.
3. **Review and implement private semantic wiring.** The standalone verifier
   must take only `(x, proof)`, plus pinned public parameters, and never load
   the private fixture. Exercise arbitrary paths, wrong ownership, cross-note
   substitutions, duplicate inputs, malformed amount limbs/carries, and
   malformed sponge connections. Include tests that bypass honest host witness
   validation so rejection actually exercises the proof constraints.
4. **Qualify hiding for that relation.** The reviewed construction must cover
   every observation in §4 and all added components, with fixed public shape,
   fresh private randomness and explicit assumptions. Empirical probes support
   implementation checks; they do not replace the argument.
5. **Demonstrate the actual wrapper route.** Verify the same M31 statement
   natively, inside the wrapper, and through the unchanged pinned PROOF1
   verifier with identical public facts. Reject altered facts, relation identity,
   preprocessing and proof bytes. A public-only compatibility experiment may
   precede hiding, but must remain labelled public-only.
6. **Measure the complete qualified workload.** Record client/wrapper costs
   separately, then native single-thread and WASM/browser costs. Reuse measured
   baselines unless a relevant change invalidates them. No new large rank sweep
   or Cairo memory benchmark is needed for this document.

Controlled-note transition binding and ReturnNote intent/settlement obligations
remain extension gates. Neither a passing R0 nor a compatible wrapper would
qualify those variants, wallet recovery, production migration or deployment.
