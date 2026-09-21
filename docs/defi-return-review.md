# Open notes and DeFi returns: reassessment

Date: 2026-09-21. Status: **Ordinary-swap pathfinding passed; production integration pending.**

The [isolated prototype](../bench/defi-return-e2e/README.md) focuses on ordinary
notes. Controller approval and controlled-note integration are outside this
pathfinding experiment.

The architectural decision is now captured in [ADR-0023](adr/0023-return-notes-and-adapter-compatibility.md):
`ReturnNote` is the transaction-local funding destination, while `OpenNoteDeposit`
is the upstream adapter response. See the [specification](return-note-spec.md) and
[new compatibility reference](../bench/return-note-e2e/README.md). The earlier
experiment below remains preserved evidence.

## Experimental outcome and confidence

The [Sepolia experiment](../bench/defi-return-e2e/README.md) passed with four
successful native spends, ten rejected adversarial transactions, one rejected
native statement execution, and fresh seed recovery followed by spending.
The real Ekubo swap used its existing Sepolia Core/Router with a dedicated
synthetic-token pair: 1,000 input units produced 999 output units. A separate
mock fill changed from 950 to 977 after proving and settled correctly with the
original proof. No controller was deployed or required.

| Question | Confidence after this experiment |
| --- | --- |
| Can ordinary notes provide atomic swap-and-return? | High for the tested single-hop flow, including deployed Ekubo interoperability. |
| Can returns with unknown amounts be recovered and spent? | High for the experimental receipt format: fresh seed restoration and subsequent native spends passed. |
| Is the operation bound to the owner's authorization? | Tested across both proof and settlement: stripped intent, redirection, changed terms, replay, and rollback cases rejected. Independent security review is still required. |
| Is it ready for normal desktops or production? | Not qualified. Single prover requests used 13.79–13.99 GiB and 20.0–21.7 seconds on the larger host; production tokens, wallet transport, formats, and security remain to be qualified. |
| Does this establish arbitrary private DeFi? | No. Persistent positions, lending/borrowing, partial fills, and general routing were not tested. |

**Decision: proceed to a reviewed design for ordinary-note swaps.** The core
feasibility questions have passed. Preserve one funded-note ownership model and
add an explicit return-receipt format and bound swap intent. Integration remains
separate work; memory reduction and practical synchronization keep their existing
priority. This does not change the current production specification or adopt the
experiment's encoding as a frozen standard.

The [measurements](../bench/defi-return-e2e/results/measurements.md) and
[qualification boundaries](../bench/defi-return-e2e/REVIEW.md) record the scope.
The real swap cost 1.835414 test STRK at this run's prices; it is not a mainnet fee
estimate. Public swap amounts/activity and return-deposit linkage remain visible.

## Conclusion

Reopen the DeFi return-path decision. Controlled notes supply an additional
spending condition; they do not by themselves execute a swap, receive an unknown
output amount, or guarantee atomic redeposit. A useful first experiment is an
atomic swap adapter that returns proceeds to a recipient-owned tree note, with
controller policy as an optional additional constraint.

This can preserve the unified funded-note format. An append-only Merkle tree does
not prevent externally funded returns: append the final commitment after the
amount is known and funding is secured. Whether the new receiving mechanism is
called an open note is less important than its funding and recovery guarantees.

## What upstream actually supplies

Reviewed upstream revision: `b40bf109c8e5b97d9d6e8ec6db48b16b9d10a106`.

- An open note starts as an amount-zero placeholder. External execution supplies
  the actual amount, and the pool pulls the tokens and fills it once. The action
  loop requires all newly created open notes to be funded before completion.
  “Open” does not grant arbitrary people spending authority.
  [Pool implementation](https://github.com/starkware-libs/starknet-privacy/blob/b40bf109c8e5b97d9d6e8ec6db48b16b9d10a106/packages/privacy/src/privacy.cairo).
- The Ekubo adapter executes a swap, enforces minimum output, measures the output
  balance increase, and returns funding instructions for the open note.
  [Ekubo implementation](https://github.com/starkware-libs/starknet-privacy/blob/b40bf109c8e5b97d9d6e8ec6db48b16b9d10a106/packages/ekubo_swap_anonymizer/src/ekubo_swap_anonymizer.cairo).
- The Vesu adapter deposits underlying tokens for vault shares or redeems shares
  for underlying, then returns funding instructions. This evidence covers those
  operations, not arbitrary private borrowing or liquidation logic.
  [Vesu implementation](https://github.com/starkware-libs/starknet-privacy/blob/b40bf109c8e5b97d9d6e8ec6db48b16b9d10a106/packages/vesu_lending_anonymizer/src/vesu_lending_anonymizer.cairo).

The useful capability comes from external execution, actual token funding, and
the return-note mechanism working together. Existing DeFi contracts interact with
an adapter; they do not need to understand shielded notes.

## What our controlled notes supply today

The [current specification](push-payment-spec.md) and
[ADR-0022](adr/0022-controlled-push-payments.md) require an owner proof plus a
controller approval of exact transition legs. Public withdrawals bind destination
and amount. They release value from the note condition. There is no proof-bound
swap route, minimum received, return destination, or obligation to redeposit.

The executable [pool](../bench/controlled-push-e2e/cairo/src/pool.cairo) verifies
approval and transfers withdrawals. Its controller interface verifies a signature;
it does not execute a DeFi application. An app can receive an approved withdrawal,
but returning the proceeds requires additional contracts and protocol rules.
An asynchronous app also introduces custody/liveness assumptions between steps.

| Capability | Current controlled notes | Proposed atomic adapter |
| --- | --- | --- |
| Owner proof plus policy approval | Implemented and exercised | Optional policy layer |
| Execute a swap or vault operation | Requires additional integration | Adapter calls the existing protocol |
| Credit the actual, previously unknown output | No complete recovery-compatible path | Finalize a funded return note |
| Enforce swap terms and return ownership | Not in the current transition | Bind the complete intent |
| Roll back the spend if the DeFi operation fails | No integrated operation exists | Required acceptance criterion |

Ordinary notes should be eligible for a self-directed swap without introducing
a mandatory controller service. If a controlled flow must preserve restrictions
across the swap, its approval and settlement checks must bind the return controller
and policy. Current withdrawal approval alone does not enforce that preservation.

## Which earlier arguments changed

[ADR-0009](adr/0009-note-type-unification.md) deferred open-note funding to
app-specific controllers or withdraw-and-redeposit. That is a possible integration
direction, not an implemented replacement. [ADR-0010](adr/0010-single-phase-architecture.md)
already acknowledged atomicity and metadata tradeoffs, but its suggestion that
controllers cover the same user-visible use case depends on additional execution
and return-funding machinery.

The older cost argument assumed an operator-side outer proof around another
proof system. Native local S-two has changed that premise. It does not remove
external-call security risks or prove that a DeFi extension will fit desktops.

The candidate below keeps DeFi execution public and checks its results on-chain.
The local proof authorizes the private spend and its execution conditions; it
need not simulate the AMM inside the private statement. This is a design proposal,
not a measured integration.

## Candidate flow to investigate

```text
private token-A notes
        |
        | owner proof + bound execution intent (+ approval if controlled)
        v
adapter receives exactly the authorized token-A amount
        |
        v
existing DeFi contract executes publicly
        |
        | actual token-B proceeds; check minimum received
        v
pool receives token B and appends a final recipient-owned note
```

All steps must settle in one transaction or revert together. Two separate
transactions do not provide this guarantee. A plain account multicall is also
insufficient authorization if someone can reuse the spend proof with different
swap terms or submit only its withdrawal leg.

Bind chain/pool/version, an authorized executor, the route and input budget,
output token, minimum received, deadline, return ownership commitment, recovery
payload, and any output controller/policy to the owner's authorization. Enforce
those bindings at settlement, including rejection of an isolated withdrawal leg.
Choose and test one execution model: an adapter that orchestrates pool calls, or
a narrowly scoped pool entry point. Do not rely on the existing signature verifier
as an execution hook. Review reentrancy and intermediate balances for that model.

The existing single-token spend equation can account for token A leaving the
pool, while a separately funded deposit accounts for token B entering it. No
cross-token equality is implied. A multi-token private-spend statement may be
useful later, but is not inherently necessary for this architecture.

## The key format gap: unknown amounts and recovery

Our current deposit already constructs a commitment from a supplied `inner`
value and an actual token/amount. However, the existing sealed delivery plaintext
also contains an exact amount. A receipt encrypted before a swap cannot contain
its unknown output, and a ciphertext with a guessed amount will fail wallet
commitment validation when the actual amount differs.

Investigate a versioned deposit receipt that seals recipient ownership/randomness
and relevant context in advance, while attaching the actual public output amount
at settlement. The wallet must authenticate the amount, token, conditions, payload,
and final funded commitment together before crediting anything. Future spends
could then use the existing owner-keyed commitment/nullifier construction; this
requires review and cannot reinterpret the current delivery format silently.

Never append an unfunded placeholder to the spendable tree or mutate an existing
leaf to fill it. Publish recovery material atomically with the final funded leaf.
Use fresh per-operation randomness and do not expose the reusable receiving
identity or a viewing/spending key to the adapter.

## Privacy and scope

The public protocol still exposes its calls, assets, amounts, timing, and the
connection between that operation and its return deposit. The goal is to avoid
identifying the owner's earlier private note and personal public account, with
later note spends retaining membership privacy. Transaction sender/gas funding,
small anonymity sets, and amount/timing correlation still need assessment.

Returning liquid ERC20 vault shares is a useful next case after swaps. Persistent
positions, borrowing, liquidation, NFTs, and delayed withdrawals need their own
ownership and liveness designs. Open notes alone do not solve those problems.

## Bounded pathfinding task

1. Specify one token-A to token-B swap with dynamic output, exact intent binding,
   an executor restriction, and an authenticated return-receipt format.
2. Exercise local settlement using a mock adapter, including slippage failure,
   return redirection, wrong token, replay, isolated withdrawal, unfunded output,
   malicious callback, and rollback of nullifiers and token transfers. Account
   for actual received balances and define supported token behavior.
3. Restore the ordinary return note from seed plus indexed public history, check
   incoming and full viewing behavior, then spend it. Controller policy is not
   required for this experiment.
4. Qualify native proof attachment through the chosen call structure and test a
   real supported DeFi deployment on Sepolia using `sncast`. Measure fees,
   proving resources, latency, and privacy-visible data. Mock success alone does
   not establish compatibility with an existing protocol.
5. Write a go/no-go ADR before production integration. Keep the current payment
   protocol unchanged until the return mechanism and security model are reviewed.

This research should happen before freezing long-lived delivery formats. It does
not displace desktop memory reduction or practical wallet synchronization.
