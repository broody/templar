# Controlled push experiment review

This is an implementation self-review and test plan for a fresh Sepolia pool,
not an independent audit or permission to use production funds. The protocol
identifier is `TEMPLAR_CONTROL_POC1`; existing pools and earlier evidence are
unchanged. Transactions use sncast and an unrestricted synthetic test token.

## Ownership and policy

The note commitment binds chain, pool, token, amount, controller, policy, and an
inner receiving-identity/randomness commitment. The receiving identity binds
separately tagged authority and nullifier-key hashes derived from the spending
secret. Membership and position-derived nullification require that secret.
Viewing keys, controller signing keys and signatures do not substitute for it.
All input and output notes in one operation must have the same controller. A
controlled owner cannot convert those notes to ordinary notes. Ordinary notes
require zero policy and no approval fields. Different policies under one controller
can be represented, but the fixture authorizer permits only its configured policy.

A withdrawal releases the value to its approved public destination; restrictions
do not follow tokens outside the pool. A recipient must inspect controller and
policy before accepting value as freely spendable. Recovery reports unspent value
and note conditions, not guaranteed availability of controller approval.

## Exact approval

The private statement recomputes the canonical transition from its actual input
nullifiers, amounts and policies, output commitments, amounts, policies and delivery
digests, and withdrawal destination/amount pairs. The hash also includes domain,
version, chain, pool, root, token, controller, deadline, nonce, counts and padding.
The public operation binding covers this transition and the exact public operation.
A new proof for another withdrawal destination cannot reuse the original approval.

The controller receives only this scoped transition request. It learns its amounts,
policies, output commitments, nullifiers and public withdrawal destinations. It is
not given spending keys, receiving identities, note openings or Merkle paths.
The fixture policy checks context, deadline, policy, withdrawal destination and
limit, and conservation before signing. This is a deliberately narrow test policy,
not a complete application policy language or a hardened authorization service.

`SignatureController` stores an immutable Stark-curve public key and uses core
ECDSA verification with explicit scalar bounds. Both signer and contract use the
low 251 bits of the Poseidon transition as the ECDSA message. The full transition
remains proof-bound. This many-to-one message encoding still requires a hash
collision/second preimage to repurpose an approval; its exact encoding and
cryptographic assumptions need independent review. The pool enforces a block-number
deadline and consumes nullifiers atomically. A nonce scopes approvals; it is not
an independent on-chain revocation or nonce registry.

Controller unavailability can freeze value. There is no unilateral escape, key
rotation, approval revocation or controller upgrade in this fixture. Designing
those features must not silently let owners remove the promised restriction.

## Preserved boundaries

The native adapter requires real transaction-level PROOF1 facts, the pinned V1
virtual OS, exact statement address/class, one expected message and bounded proof
age. Pool verifier and fee administration remain owner-controlled experimental
configuration, and are not a production governance design. All state/token/fee
changes revert atomically on failed approval. Encryption correctness is not
proved; decryption, commitment matching and complete delivery history remain
required before crediting a recipient. Ciphertexts are canonically encoded and
bound through their digests.

The existing recovery model checks an accepted checkpoint with two trusted RPCs,
rebuilds the public tree and verifies every payload digest before decryption.
It is not a light client; colluding providers and wallet-specific nullifier query
patterns remain limitations. No viewing or spending secrets go to RPC providers.
Controlled-note discovery and seed recovery preserve controller and policy fields.

Tests cover real signatures, ordinary regression, maximum statement shape,
controller/owner separation, stripped conditions, wrong policies, substituted
withdrawal destinations, missing/wrong/expired approval and replay. Mock-verifier
unit tests exercise pool guards only; live native proofs separately qualify the
integration. The prover is bounded to four cores and 16 GiB without swap. This
limit is not evidence of suitability for desktops with 16 GiB total system RAM.

Secrets, witnesses and signed transaction requests stay in a mode-0700 runtime.
Only allowlisted public proof, transaction and aggregate recovery evidence is
archived. These synthetic aggregate reports are intentionally public test data;
production wallets must not publish their private balances or note associations.
