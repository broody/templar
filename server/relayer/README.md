# templar-relayer

The service's relayer (`docs/account-bound-note-spec.md` §7.3 and §7.4, phase P4b). It runs beside
a prover server that serves pool V3 and has a `[relay]` section.

**The rule it keeps.** It must never cause a second transaction beside a wallet's fallback
(AB-P31). So it answers a job with a refusal only when nothing was sent. A send whose outcome is
unknown, or a second job for notes it already sent, is answered with the transaction hash, and
the wallet watches that hash.

**One pass:**

1. Answers the server has not acknowledged yet are sent again.
2. On a lagging node (latest block older than `staleSecs`, default 30 s), nothing is sent.
3. Its own transactions are tracked:
   - a revert denies those notes for good (an asset or receiver that reverts once included cannot
     be relayed again);
   - a rejection, or a transaction the node lost, resets the nonce;
   - one pending past `stuckBlocks` (default 20) makes new jobs wait.
4. It lists the prover's handoff (`GET /relay/v1/jobs`), earliest deadline first. Each result
   waits until its submit block (`base_block + 11`), then must pass:
   - the pool call is `apply_spend` (invokes need tight minimums first, F06);
   - an exit's asset is in `assets`;
   - `send_deadline ≥ latest + marginBlocks`;
   - the pool's verifier is still the pinned adapter;
   - the root is known and still accepted for the margin;
   - both nullifiers are unspent.
5. It prepares the exact transaction with its own nonce sequence, never below the chain's at
   `pre_confirmed`. It simulates with validation, refuses a maximum fee above `maxFee`, and
   checks the margin again.
6. It claims the job (`POST /relay/v1/jobs/{id}/claim`), and sends only on a 200. The server
   refuses an unclaimed job once its deadline is within `relay_margin_blocks`, so the client can
   fall back early when the relayer is down.
7. It records the notes with the signed transaction hash, sends, and answers
   (`POST /relay/v1/jobs/{id}`) with `{transaction_hash}` or `{refused: reason}`.

The client reads the answer in its job status. It falls back at once on a refusal. Otherwise it
falls back only from `send_deadline − FALLBACK_MARGIN` (40 blocks), and never while the relayer's
transaction is pending or after it landed. The relayer's margin, at least 60 blocks, is always
more than 20 above that.

**What it keeps** (`stateFile`, replaced atomically): the nullifiers of what it submitted, with
the transaction hash, until each deadline; the denied notes; its own transactions not yet final;
the next nonce. It logs job ids and outcome kinds, never nullifiers, amounts or transaction
contents.

## Running

The logic is `@templar/sdk/relayer` (`sdk/ts/src/relayer.ts`). Build the SDK first, then:

```bash
node server/relayer/relayer.mjs /etc/templar/relayer.json
```

- **The account.** One account submits every spend, whatever the product, so the
  submitter tells nothing apart. It needs STRK for fees; tickets pay the service off chain. Its
  private key is read from `account.keyFile` (mode 0400) and never logged. The transaction hash
  is taken from what its signer signed, so it is known before sending.
- **The handoff** needs the token on both sides: the prover's `[relay] token_file` and
  `handoff.tokenFile` here. Keep the listener on loopback, or a private network or TLS proxy.
- **The node.** Use the operator's own node, as for the prover.
- **P4b limits:**
  - one relayer per prover;
  - a prover restart loses its queue, and clients then fall back at their deadline;
  - no quotes or per-asset fees (`docs/relayer-spec.md`, P7).
