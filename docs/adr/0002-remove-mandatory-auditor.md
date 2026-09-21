# ADR-0002: No mandatory auditor; voluntary viewing keys only

- Status: Accepted
- Date: 2026-09-19
- Deciders: broody

## Context

Upstream bakes an `auditor_public_key` into the pool. At registration the user's
private viewing-key scalar is ECDH-encrypted to the auditor and stored permanently
(`packages/privacy/src/privacy.cairo:319-356`); withdrawal and open-note-recipient
addresses are likewise auditor-encrypted (`privacy.cairo:518-529`, `701-712`). One
scalar lets the auditor reconstruct a user's entire graph retroactively: channel
keys, note amounts, counterparties, and nullifier↔note linkage (nullifiers include
`owner_private_key`, `hashes.cairo:229-236`). This is a deliberate global backdoor.

Upstream already has the *legitimate* version of this feature: viewing keys
(`SetViewingKey` + ECDH channel encryption) let any user disclose their activity to
a specific party by handing over the private scalar out-of-band.

## Decision

Delete the auditor entirely from TemplarPool:

- Remove `auditor_public_key` storage, constructor arg, `set_auditor_public_key`,
  `AuditorPublicKeySet` event, `get_enc_private_key`.
- Remove `EncPrivateKey`, `EncUserAddr`, `EncOutgoingChannelInfo` and their
  encrypt helpers (`utils.cairo:202-258`) and every call site.
- Keep `SetViewingKey` reduced to `(user_addr, public_key)`. Selective disclosure
  is a *user-side* act (share your viewing scalar with an auditor/counterparty),
  never a protocol-side mandatory ciphertext.

## Alternatives considered

- **Rotating/multi-auditor, threshold decryption**: still a global backdoor; adds
  complexity to a feature that voluntary viewing keys already provide.
- **Keep auditor ciphertexts but allow opt-out**: opt-out pools have no credible
  compliance story and inherit all the attack surface; worse than both options.

## Consequences

- Compliance-sensitive users lose "the protocol proves I'm audited" — addressed by
  the opt-in ZK association sets of ADR-0003 instead.
- Withdraw/recipient ciphertext machinery disappears, which also removes the
  withdraw-`random`-reuse linkability bug (upstream `actions.cairo:191-201`).
- The viewing-key registry (`public_key: Map<addr, pk>`) still publicly links
  identity ↔ key; stealth-style key publication is an open item (PLAN.md §8).
