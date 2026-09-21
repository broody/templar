# ADR-0021: Push-only payments with reusable receiving addresses

- Status: Accepted — product and architecture decision; production integration and cryptographic format review pending; external-return scope extended by [ADR-0023](0023-return-notes-and-adapter-compatibility.md)
- Date: 2026-09-20
- Deciders: broody
- Supersedes: [ADR-0012](0012-recipient-authored-notes.md); consolidates the architectural recommendations of [ADR-0019](0019-offline-push-receiving.md) and [ADR-0020](0020-full-viewing-and-recovery.md)
- Amends: ADR-0009 ownership/nullifier derivations, ADR-0007 creation metadata, ADR-0014 output/action binding, and ADR-0018's preservation of existing note semantics
- Evidence: [ordinary push payments, full viewing, and cold recovery on Sepolia](../../bench/push-e2e/README.md)
- Current design: [push-payment specification](../push-payment-spec.md)

Controlled-note scope is extended by [ADR-0022](0022-controlled-push-payments.md); the receiving model remains push-only.

## Decision

The initial product has one payment flow: a recipient shares a reusable shielded
receiving address; a payer creates and encrypts a fresh recipient-owned note;
the recipient discovers it from public encrypted history, including while
restoring a wallet after being offline. Change uses the same flow to the payer's
own address. No per-payment recipient response is required.

Do not include recipient-authored invoices, receive boards, invoice inventory,
invoice reservation, or persistent delivery channels in the initial protocol or
wallet. These are not alternate receiving modes to maintain. A future merchant
payment request could carry an address and an expected amount at the application
layer, but it is outside this release and would not require recipient-generated
note secrets or a different spending rule. A future delivery optimization needs
measured benefit and a separate decision; no channel state or dormant channel API
is required now.

Separate receiving, viewing, and spending authority. A sender can construct an
output using public receiving material without obtaining the recipient's spending
secret or nullifier key. Incoming viewing decrypts receipts. Optional full viewing
also determines which received notes are spent, without authorizing a spend.
No viewing capability is disclosed to a service by default.

Publish encrypted note data atomically with each funded commitment. Bind exact
ciphertext digests and withdrawal destinations into the proven public operation.
Use seed-derived keys plus complete public encrypted history for recovery; a seed
alone cannot regenerate sender-chosen note randomness. Missing history must remain
visible as an incomplete result. No separate secret note file is handed to a payee.

The first integration supports ordinary notes. Controlled-note authorization is
a separate extension requiring its own push-format statement, delivery binding,
signature implementation, and tests. Reserved controller fields are zero in the
demonstrated path; they do not establish controlled-payment support.

## Why

The Sepolia experiment demonstrates the required user capabilities without
persistent shared delivery state: two independent payers pay an offline address,
a full viewer computes the balance, and a restored wallet spends it after loss
of its local cache. Maintaining an additional invoice flow would add secret
inventory and synchronization responsibilities without enabling a required
first-release capability. Channels likewise need a demonstrated discovery or
throughput benefit before their state and recovery complexity is justified.

Merkle membership, ownership, and delivery are separate mechanisms. The tree
supports a hidden input's membership proof. Public receiving keys permit
sender-authored outputs; encryption delivers their openings. Neither a Merkle
tree nor S-two uniquely implies this user experience, and map storage does not
fundamentally require channels.

The address identifies who receives funds, not what they are owed. Wallets credit
only successfully decrypted, commitment-matching funded notes and report the
actual token and amount received. The spending proof does not prove correct
encryption or authenticate the payer's identity.

## Adoption boundary

This accepts the architecture and first-release scope, not an audited production
cryptographic construction or a frozen wallet encoding. The POC2 authority and
nullifier derivations, seed scheme, address/export encodings, and delivery storage
representation require independent review before production format freeze.

`bench/push-e2e/` is the executable reference and contains real native PROOF1
Sepolia evidence. `packages/pool/` and prior deployments still implement their
recorded format. They are not silently upgraded by this decision. Keep earlier
evidence intact. Do not reinterpret an existing leaf with a new nullifier rule or
swap an existing pool's verifier to the push statement. Production integration
requires either a fresh pool or a separately reviewed versioned migration that
preserves each old input's original nullifier semantics.

The current implementation trusts its RPC providers for canonical state and leaks
candidate-nullifier query patterns to them. History synchronization, private query
design, historical availability, secure key storage/exports, address authentication,
rotation, and an independently reviewed recovery format remain work. The roughly
14 GiB proving footprint also remains a desktop qualification issue.

## Documentation contract

The Vocs architecture guide describes push payments directly as the supported
design. It contains no invoice migration story or payment-design chronology.
Implementation qualifications and experimental measurements belong on its status
page. ADRs and preserved specifications retain the engineering decision record;
their existence must not introduce alternate user flows into the guide.

The optional controlled-note integration is specified by [ADR-0022](0022-controlled-push-payments.md). Its fresh-pool reference extends this receiving model without changing the push-only decision.
