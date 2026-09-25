# R0 V5 bridge and statement account (P3)

2026-09-26. The Cairo side of [`docs/account-bound-note-spec.md`](../../../../../docs/account-bound-note-spec.md)
§5: the bridge that verifies an R0 V5 client proof and decodes its statement, and the statement
account that authorizes it. Account-bound spends are authorized by the bound account's
`is_valid_signature`. Code: [`cairo-r5/`](../../cairo-r5). Nothing is deployed; the virtual-OS
captures and PROOF2 are P5.

## Result

| | R0 V4 | **R0 V5** |
| --- | ---: | ---: |
| Bridge, standalone, honest proofs | 1.99–2.07M steps | **1.97–2.06M steps** (16 proofs, 8 shapes × 2 modes) |
| Bridge validation | 60/60 | **118/118** |
| Statement account tests (snforge) | — | **20/20** with mock accounts, **4/4** against real wallets |
| Account CASM (limit 81,920) | 61,395 felts | **63,483 felts** (Sierra 30,702) |
| Circuit hash pinned | R4's | R5's, the same as [`../stwo-client-r5/trusted-config.json`](../stwo-client-r5/trusted-config.json) |

## Bridge ([`validation.json`](validation.json))

`validate_bridge_r5.py` runs the built bridge standalone on real proofs:
- **Accepted:** all 16 honest proofs, 8 shapes in both modes. Each returns the binding that
  [`bench/adr8/ref_poseidon.py`](../../../../adr8/ref_poseidon.py) recomputes independently (AB-IM4).
- **Rejected, altered statements and encodings (88):** on an ordinary transfer, a bound transfer
  and a bound withdrawal. These cases require a failure, not a particular check (AB-IM7), except
  the tag, padding and a transfer's asset, which must fail `statement tag`, `statement padding` and
  `exit rule` before proof verification:
  - a changed output limb in the tag, asset, nullifier, commitment, account, `valid_until` and
    padding;
  - an absent-component claimed sum, a flipped proof byte, trailing or truncated data;
  - a wrong chain, pool, root, nullifier, delivery, withdrawal, intent, identity, account or
    `valid_until`, and an added or dropped account;
  - a claimed asset the proof does not publish (every shape).
- **Rejected, real proofs of forged statements (14):** each statement is one the circuit admits and
  only the bridge's own check rejects, and each is rejected by that check:

  | Forgery | Reason |
  | --- | --- |
  | voluntary asset reveal | `exit rule` |
  | zero delivery digest | `delivery` |
  | recipient without an amount | `withdrawal` |
  | identity without an intent | `identity intent` |
  | duplicate nullifier | `duplicate nullifier` |
  | asset at 2^251, recipient at 2^251 | `address range` |
  | zero chain | `zero context` |
  | **account at 2^251** | `account range` |
  | **account at p** (no tamper hook needed) | `non-canonical felt` |
  | **`valid_until = 0`** | `valid_until` |
  | **account limb at 2^28**, **either `valid_until` limb at 2^28** | `limb range` |

The decoding and checks mirror `src/payment5.rs` (`decode_statement`, `bridge_checks`), the
reference the Math Reviewer checked in P2.

## Known-answer vectors ([`cairo-r5/kat/`](../../cairo-r5/kat))

- `gen_kat.cjs` computes, with starknet.js 10.8 as the reference:
  - the SNIP-12 type hashes;
  - three spend messages (domain, binding commitment, struct and message hash; Sepolia and
    mainnet, u128 and address extremes);
  - four `TMR0_BIND_V5` bindings.

  It writes `kat.json` and the Cairo tests `bridge/src/snip12_kat.cairo`. The bridge build runs
  those tests, and all pass. The binding tests also show that a bound statement with the same
  fields binds identically, because the binding omits the account (AB-IM4).
- **SDK note for P4:** `public.json` holds `withdrawal_amount` (u128) and `valid_until` (up to
  2^56) as JSON numbers. `JSON.parse` rounds them, which silently changes the binding and the
  signed hash. `kat/v5.cjs` reads them from the text.

## Statement account ([`account-tests.json`](account-tests.json))

`cairo-r5/account_tests` runs the account on real proofs (`kat/gen_fixtures.cjs` writes the
fixtures), with a mock account deployed at the address the bound proof names:

- **Accepted:**
  - the account's `VALID` over the exact starknet.js spend hash, with one message
    `[class_hash, 'TMPZR0_PAYMENT_V5', chain, pool, binding]`;
  - an ordinary spend with no salt and no signature, also with one message.
- **Rejected:**
  - another salt, or a tampered signature (`SIG_NOT_VALID`);
  - a zero salt in bound mode (`SALT`);
  - an account that returns 0, or two felts (`SIG_NOT_VALID`);
  - an account that panics, re-enters, or has no `is_valid_signature` (`SIG_CALL_FAILED`). The
    re-entry case carries an empty proof, so the bridge also rejects it; `nonzero_caller` tests the
    caller-0 guard itself (AB-IP3);
  - no contract at the address (`ACCOUNT_NOT_DEPLOYED`);
  - a statement naming the statement account itself (`SELF_ACCOUNT`);
  - a nonzero caller (`OS_ONLY`), another chain (`chain`);
  - an ordinary spend with a salt or a signature (`ORDINARY_AUTH`);
  - `__validate__` with a tip or a price (`PROVE_ONLY`).
- **A callee that emits a message** leaves two messages. The adapter's `MESSAGE_COUNT = 1` rejects
  that proof (spec §5.4); the test records the count.

**Deployment check (added in P3, spec §5.4 amended).** Calling an undeployed address does not
return an `Err`: it aborts the whole execution ("Requested contract address … is not deployed").
The account now checks `get_class_hash_at(account) ≠ 0` first, so the rejection is an explicit
`ACCOUNT_NOT_DEPLOYED`. The check costs one syscall and 89 CASM felts. It is diagnostic (AB-IP1):
other callee failures can still abort rather than err, such as the callee calling an undeployed
address or running out of steps. An aborted run emits no message and yields no proof, and the
server charges it to the client (spec §9).

## Real wallets ([`real-wallets.json`](real-wallets.json))

Ready X 5.33.11 (Argent 0.5.0) and Braavos 4.19.6 (Braavos 1.2.0) each signed, through
[`cairo-r5/sign`](../../cairo-r5/sign), the V5 `TemplarSpend` for a real bound proof naming its
own Sepolia account. Signature layouts: `[r, s]` and `[1, r, s]`.

- The page's hash equals the prepared one.
- A read-only `is_valid_signature` on Sepolia returns `VALID` for both.
- `test_real_wallets.cairo` runs the statement account on a local fork of Sepolia at block
  15,637,581 (pinned, AB-IP6), with nothing sent:
  - with the wallet's proof, salt and signature, the live account classes accept, and the account
    emits the expected message with the expected binding;
  - under another salt, both real accounts reject, and the spend fails (`SIG_CALL_FAILED`).

This is spec §15 P3's real-wallet signing of §5.3. It ran in snforge with a cheated caller and
chain. The same accounts inside the pinned virtual OS, and V5 signatures of an in-pool transfer and
an invoke, are P5 (AB-IP2, AB-IP6).

The signing server binds to 127.0.0.1, forwards only read-only RPC methods, and refuses a foreign
`Host` or `Origin` and non-JSON posts (AB-IP5). The committed `real-wallets.json` holds truncated
addresses and no signatures.

## Also in P3

- **F38.** `tests/payment_r5.rs::pinned_circuit_hashes_match_the_code` recomputes the R5 hash the
  bridge pins, and the deployed R4 bridge's hash, from the current code.
- **Out of P3's scope:**
  - F13 (the fork's Rust `verify_circuit_proof` takes its pins from the proof);
  - F34 (proof re-encodings of the same statement are accepted).

  Both are fork changes that each need their own review. Today's callers pin everything, and F34
  re-encodes only the same statement.

## Reproduce

Tools: `cargo +nightly-2026-01-15`, scarb 2.18.0, snforge 0.63.0, and for the real-wallet tests
the local Sepolia node at `127.0.0.1:9545`. Runs belong under `~/.local/share/templar/runs`.

```text
cargo +nightly-2026-01-15 build --release --features tamper --examples
prove_payment_r5 PROOFS/{ordinary,bound}-SHAPE --compress-nodes [--bound] --shape SHAPE      # 16
prove_payment_r5 PROOFS/forge-KIND --compress-nodes --bound --forge KIND [--shape partial]   # 14
prove_payment_r5 PROOFS/fixture-bound --compress-nodes --bound --account 0x0123456789abcdef0123456789abcdef --shape partial
prove_payment_r5 PROOFS/fixture-ordinary --compress-nodes --shape partial
node cairo-r5/kat/gen_kat.cjs
python3 build_bridge_arith.py results/stwo-client-r5/trusted-config.json RUN/bridge
python3 validate_bridge_r5.py RUN/bridge PROOFS RUN/validation
node cairo-r5/kat/gen_fixtures.cjs RUN/bridge PROOFS
(cd RUN/bridge/account_tests && snforge test --profile contract)
# Real wallets: prove PROOFS/wallet-{ready,braavos} with --account <address>, then
node cairo-r5/kat/gen_sign_requests.cjs PROOFS RUN/sign-requests.json
python3 cairo-r5/sign/serve.py RUN/sign-requests.json RUN/sign-results   # sign in each wallet
node cairo-r5/kat/gen_fixtures.cjs RUN/bridge PROOFS
(cd RUN/bridge/account_tests && snforge test --profile contract --include-ignored real_)
```

## Review

- Math, bridge: [`docs/reviews/account-bound-p3-math-review.md`](../../../../../docs/reviews/account-bound-p3-math-review.md), GO.
- Protocol, statement account: [`docs/reviews/account-bound-p3-protocol-review.md`](../../../../../docs/reviews/account-bound-p3-protocol-review.md), GO.

| Finding | Resolution |
| --- | --- |
| AB-IM6 | A Cairo unit test for the `valid_until` high limb; forgeries `valid-until-hi-limb-range` and `account-noncanonical` |
| AB-IM7 | The tag, padding and transfer-asset tampers assert their check; the README says the other altered cases require only a failure |
| AB-IM8 | Recorded above: limbs below p by type; tag and padding are defence in depth; the Python binding on real proofs is the independent cross-check |
| AB-IP1 | §5.4 calls the deployment check diagnostic; §9 charges an OS revert or abort to the client; a test for a contract without `is_valid_signature` |
| AB-IP2 | §9: the admission pre-check is advisory, the virtual OS authoritative, and the L2 gas bound comes from the measured cost; P5 runs the real wallets in the virtual OS |
| AB-IP3 | The re-entry test is renamed and documented; `nonzero_caller` covers the guard |
| AB-IP4 | §5.4: a future padding contract's address must be rejected by the account |
| AB-IP5 | The signing server checks `Host`, `Origin` and the content type. The P0b spike's server has the same gap; it is throwaway and not reused |
| AB-IP6 | The fork block is pinned. P5 signs an in-pool transfer and an invoke. The SDK draws salts uniformly from `[1, 2^251)` (spec §5.3); only the test salts are forced odd |
