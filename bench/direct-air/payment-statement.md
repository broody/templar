# Payment statement requirements for a later representative benchmark

This is a preservation checklist, not a new accepted encoding. The first
experiment gates must pass before a payment prover is described as private.

Use the ordinary branch of the controlled-push reference as the initial
semantic baseline: `bench/controlled-push-e2e/cairo/src/statement.cairo` and
`docs/push-payment-spec.md`. Keep the reference felt252 Poseidon domains and
depth 32. An eventual ReturnNote extension has its own versioned reference and
must not silently reinterpret this format.

## Public binding

The complete ordered action bundle must bind protocol version, chain, pool,
root, public token, input/output/withdrawal counts, nullifiers, output
commitment/delivery-digest pairs, withdrawal recipients/amounts, and applicable
controller/deadline/nonce/transition/intent fields. A compact digest is acceptable
only if its preimage encoding and recomputation are identical on every layer.

The fixed inner-verifier identity and security configuration must be pinned by
the wrapper statement. A witness-supplied verification key, preprocessing root,
security parameter set or unchecked public-output layout cannot define what
constitutes a valid Templar transition.

## First representative shape

- Exactly two active inputs and two active outputs, no withdrawals, ordinary
  controller/policy fields. Account for the reference's inactive canonical slots
  when comparing public bindings.
- Derive spending authority, nullifier authority and receiving identity from
  the private spending secret with the reference domains. Do not accept viewing
  authority as a spending secret.
- Recompute each input commitment; authenticate the same 32-bit leaf position
  through 32 sibling hashes and include that position in the nullifier.
- Reject duplicate input nullifiers. Pool settlement separately checks current
  unspent status and root acceptance.
- Enforce nonzero, canonical note fields and nonzero u128 amounts. Implement
  bounded integer conservation without unintended finite-field wraparound.
- Recompute output commitments. Bind the ordered delivery digests; encryption
  correctness remains a receiver-side check under the current reference.
- Preserve public-caller pool fees outside private conservation. A later
  private-fee design would need an explicit protocol decision.

## Adversarial and measurement requirements

Reject wrong keys, paths, positions, roots, nullifiers, duplicate inputs, altered
amounts, out-of-range encodings, missing/extra elements, output substitutions,
delivery substitutions and changes to any context/binding field. Compare valid
synthetic vectors against the existing Cairo/Python reference.

Measure witness generation, preprocessing, trace construction, the direct proof,
and any local privacy wrapper together as well as separately. Include raw and
serialized/compressed proof sizes, one- and four-thread native runs, peak RSS,
cgroup charges, zero swap, and repeated runs. Browser measurements must include
linear-memory high-water usage and data copies; native RSS is not a substitute.
