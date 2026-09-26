# ADR-0027: One wallet model: remove account-bound notes, R0 V6, and key custody

- Status: Proposed. Revision 3, with the owner's decisions of 2026-09-26: a Templar-specific
  derivation, the vault at `vault.templar.money` embedded as an iframe, a routing adapter, and
  relaying invokes before launch. Two review rounds are recorded in
  [docs/reviews/adr-0027-review.md](../reviews/adr-0027-review.md):
  - a four-lens review (protocol, custody, completeness, consistency) with adversarial
    verification, which confirmed 47 findings and rejected 7;
  - a coverage check of revision 2 plus a fresh-eyes review.

  Every confirmed item is applied in this revision.
- Date: 2026-09-26
- Deciders: broody
- **Supersedes, from ADR-0026:**
  - decisions 1, 2, 4 and 5: two products, the account-bound receiver, the product-1 seed, the
    spend message;
  - from decision 6: the published `account`, the 35-output statement, and the identity rule's
    anti-leak rationale, which rested on `ak_w`.
- **Withdraws ADR-0026 decision 3** (no escape path) as moot. Its premise is reversed: a leaked
  seed is now theft, not "privacy only" (spec S4).
- **Amends ADR-0026:**
  - decision 7: pool V3 stands unchanged, and its R0 verifier becomes a V6 routing adapter;
  - decision 8: the relayer submits plain R0 spends only, and the fallback submitter follows
    decision 3 below.
- **Amends ADR-0023:** the identity handle becomes `H(IDENTITY, ak₀ ‖ scope)` with
  `ak₀ = H(AUTH, sk₀)`.
- **Stands from ADR-0026:** decision 9 (process). It governs this ADR's design phase.
- **On acceptance,** ADR-0026's status becomes "Superseded in part by ADR-0027", and the ADR
  index rows for 0023, 0026 and 0027 are aligned.

## Context

ADR-0026 gave existing wallets (Ready, Braavos) their own product: **account-bound notes**. A
bound note needs the wallet's Templar key *and* a signature from its Starknet account, which the
prover server's statement account checks with `is_valid_signature` inside the proven execution.
It is built and measured:
- P5: real Ready and Braavos accounts in the pinned virtual OS, on live Sepolia state;
- P6: pool V3 on Sepolia, and an end to end with a Braavos account up to the gateway.

Two facts came out after that work.

**External wallets never needed bound notes to use the pool.**
- Deposits come from any account, and withdrawals go to any address.
- Spends are authorized by the Templar key inside the browser-made client proof.

What bound notes added is narrower: the external wallet as a required **co-signer** of every
spend. They do not spare users a backup. A bound wallet has its own random 21-word seed, which the
user must back up (ADR-0026 decision 4), because the account's signature cannot replace the
Templar key.

**So what bound notes buy is theft protection when the Templar seed leaks at rest** (spec S4). It
does not hold against a compromised signing interface. An independent review of the codebase
(2026-09-26) found no capability that only bound notes have. It found four related losses:
1. A leaked seed can also act through the wallet's shadow accounts.
2. The account's key can be rotated without moving notes.
3. Every bound spend shows a wallet prompt, so it cannot happen silently.
4. The server keeps a per-account daily cap on free withdrawals.

It found capabilities that only the ordinary path has:
- policy notes;
- any account type: guardians, multisig, passkeys and Cartridge Controller;
- pool V2.

**What bound notes cost:**
- **Privacy.** The server learns which account made which spend, and sees the account's signature
  while proving. A retained signature would be third-party-verifiable evidence. This is the only
  place where Templar's server is trusted with the spender's identity.
- **Reach.** Only Stark-key Argent 0.5.0 without a guardian, and Braavos 1.2.0, are accepted.
  2FA Ready accounts and passkey wallets such as Controller are refused.
- **Complexity:**
  - the account-class matrix, setup checks, per-vendor resource caps, and bound freezes (a
    guardian cosignature, a new signer type, a class upgrade);
  - the bound seed, per-spend signing, an operator-controlled node and memory-only retention on
    the server;
  - a Cairo trace that differs by mode inside PROOF2, hence the paused padding work;
  - in the bridge, a SNIP-12 message and a call into arbitrary account code: the most
    security-sensitive code in the relation.

Crypto users already treat a leaked seed as theft. Nothing is on mainnet and nothing is audited,
so removing bound notes now is as cheap as it will ever be.

## Decision

1. **One wallet model.** Every user holds ordinary Templar notes, spent with the Templar key
   inside the client proof. External wallets connect to the site for login, deposits,
   withdrawals and paying for the service, and never authorize spends. Any account type works for
   deposits and withdrawals.

2. **Remove account-bound notes entirely: the off-chain code and the protocol.**
   - **R0 V6 is R0 V5 with `m = 0` and `account = 0` fixed.** Its statement is V5's ordinary
     statement without the account limbs. It keeps:
     - `valid_until`, V4's two outputs and conservation;
     - V5's binding. `TMR0_BIND_V5` is forced, since pool V3 hardcodes it. It is sound, because
       the adapter pins the statement account, its class and the account tag inside the message,
       so each relation version is identified by where its message comes from;
     - V5's ordinary receiver, commitment, nullifier and identity handle,
       `H(IDENTITY, ak₀ ‖ scope)` with `ak₀ = H(AUTH, sk₀)`. Ordinary receivers, addresses and
       notes, whether from deposits or V5 ordinary spends, carry over unchanged and stay spendable
       under V6. No V5 shadow account exists on Sepolia: pool V3's allowlist is empty.
   - **What the deployed class and pool fix:**
     - the message shape `[class, tag, chain, pool, binding]`, sent to `to_address` 0;
     - `MESSAGE_COUNT = 1`;
     - `facts[0] == 'PROOF2'`;
     - `TMR0_BIND_V5`, byte-identical to `spend5.cairo`'s `compute_binding`.

     The V6 statement account emits
     `[runtime class hash, 'TMPZR0_PAYMENT_V6', chain, pool, binding]`.
   - **Design requirements carried from V5:**
     - the zero-tip, zero-price rule (`PROVE_ONLY`) stays in `__validate__`;
     - the caller-0 guard (`OS_ONLY`), which blocks re-entry, stays in `__execute__`.

     A V6 choice, which the server's virtual-transaction builder must follow: `__validate__` and
     `__execute__` take the proof data only.
   - **The public layout shrinks.** V5's 138 limbs pad to 140 (35 outputs). V6 drops the nine
     account limbs, leaving 129, which pad to 132 (33 outputs). The design phase fixes:
     - the bridge's offsets, with a zero check on every padding limb;
     - the tags: `R0V6`, and `R0C6` for pool V3's compress-only tree (F30);
     - the new pinned circuit hash;
     - the r6 job body, which carries no salt or signature.
   - **A cross-version known-answer test.** One witness, with its real inputs and its stored
     companion, gives identical nullifiers, commitments, identity handle and binding under V5
     ordinary and V6. It is mirrored in the SDK core's vectors.
   - **The hash kind `WAUTH = 16` is reserved permanently.** Stranded bound receivers in pool
     V3's tree contain it.
   - **A new V6 bridge and statement account** with no signature path, and **a new R0 adapter**.
     Its constructor values:
     - the V6 statement account and its class;
     - the pinned OS program;
     - `max_proof_age = 1,024`. The server checks one age against every adapter, the P1 adapter
       uses 1,024, and it stays well above PROOF2 latency. V5's other rationale, the bound
       key-rotation window, is gone.

     **The adapter is a new routing class** (decided 2026-09-26). Pool V3 has one R0 verifier
     slot, so a later route, such as a device statement with its own proof version (decision 6),
     is added in the adapter without another R0 swap.
     - Each route pins a statement account, its class, its account tag, the OS program, the proof
       version and `max_proof_age`.
     - Adding or removing a route follows the pool's own rules: `propose` and `apply` within
       `[eta, eta + T]` with the same `T`, events, and the SDK reading pending changes.
     - Phase A specifies the class. It is a new owner lever, so it goes into the governance review.
       Declaring it is a small cost.
   - **Stranding.** After the swap, every bound receiver in pool V3's tree is unspendable forever
     (spec S1). Today that is P6's one bound deposit (1,000 test token A); P6's ordinary deposit
     stays spendable. Wallets never create bound receivers again, and any bound address anyone
     still holds becomes a burn address. The R0 V5 statement account and the V5 adapter are
     retired on Sepolia.
   - **Off-chain removals:**
     - **SDK:**
       - bound wallets, `BoundSigner`, `authorize`, `BOUND_ACCOUNT_CLASSES`, the bound keys and
         `snip12`, and the `prover_account_class` error code;
       - the pool's ABI generation is separated from the relation version (network, chain and
         prover modules; core `pool.rs`), and the `spend_message` check on servers is dropped;
       - `sdk/vectors/keys.json` is regenerated without `bound_seeds` (`check_keys.py`,
         `vectors_keys.rs`), and the SNIP-12 known-answer tests are retired (`cairo-r5/kat`,
         `bench/wallet-sig-spike/snip12`).
     - **Prover server:**
       - bound mode goes, with `operator_node` (used only for bound spends),
         `bound_account_classes`, `bound_data_dir` and `bound_retention_secs`;
       - so do the bound fields in `/v1/info`, the per-account free cap, and the 403 reasons
         `account_class` and `signature`. `prover.example.toml` is updated;
       - `/v1/info` gains an `r6` section: pool parameters, no spend message.
     - **Relayer:** its logic stays. Its pins (adapter, statement account and class, tag, circuit
       hash, version), its `v5` check and the prover's r5-only relay gate move to V6.
     - The bound code stays in git history.
   - **Specs and guide.** The account-bound spec is revised into a pool V3 spec (R0 V6, pool V3,
     submission and payment) without §3, §6, §10, the bound parts of §5, and the bound rows of
     §12–§14. The sdk, prover-server and hidden-asset specs and the guide follow. Also updated to
     V6:
     - `open-note-spec.md`'s handle (its `sk₀` text), and its owner lever: `set_shadow_class` is
       now the timelocked `propose` and `apply`;
     - ADR-0023's handle text.

3. **Submission and connected accounts.** The protections that exist only in bound mode today
   become rules for any external account connected to a session.
   - **Who submits.** The relayer submits plain R0 spends. Spend results go from the vault straight
     to the prover server and the relayer; they never pass through the application.
   - **Invokes and P1 settlements are not relayed** until tight minimums exist (F06). Until then
     the vault's submitter account submits them; the connected account cannot, since its override
     is unavailable (below).
     - Each such submission publicly links the submitter account, and any account that funded it,
       to the spend. The SDK marks them linkable and asks first.
     - Relaying invokes (F06 tight minimums) is a launch requirement for the web application
       (decided 2026-09-26).
   - **Fallback.** For plain spends, the preferred fallback is a second, independently operated
     relayer, added to ADR-0026 P7's relayer operations. After that comes the vault's submitter
     account.
     - The connected account submits only through an explicit, linkable override.
     - That override needs a wallet API that signs and sends a proof-carrying transaction. No
       extension wallet is known to support that today. Until one does, and until it is tested on
       Ready, Braavos and Controller, the override is unavailable.
     - Any account the user funds from the connected account is publicly linked to it by that
       funding.
   - **RPC separation.**
     - The vault owns the spend provider, and refuses one that shares a node with the
       application's provider.
     - Spend-specific reads cover fee estimates, simulation, nullifier, root and recipient checks,
       and status polling. They go through the relayer, or through a provider that has not seen the
       connected account, over OHTTP where available.
     - OHTTP is no longer mandatory, because no V6 read names an account.
   - **Identity separation.** The connected account must not be linked to the spends:
     - no login session, cookie or wallet credential reaches the prover server, the relayer or the
       ticket redeemer;
     - job requests carry no session;
     - OHTTP is recommended for job submission.
   - **The pass.** Buying the pass on chain with the connected wallet publicly links the pass to
     it, and in this model the connected account is the depositing one. So the pass is bought from
     an account unlinked to the depositing one, or paid off chain so the mint does not name the
     payer. P7 decides which (AB-P32).
   - **Bound statements before the swap.** After the off-chain removal and before the swap, r5
     admission refuses statements with `account ≠ 0` as a client fault that consumes tickets, and
     the SDK refuses to plan them.
   - **Backup check.** The seed backup is confirmed with a word check before the first address is
     shown.

4. **Key custody at launch: a website with a vault on its own origin.**
   - **The vault** runs on the exact host `vault.templar.money`, separately hosted and deployed.
     The seed, the SDK core, sync and proving live there; the application's origin never holds the
     seed.
     - No other origin is served at or under the vault host.
     - **It is embedded in the application as an iframe** (decided 2026-09-26). The iframe is the
       vault's everyday surface: storage, sync, proving and balances.
     - Being same-site with `templar.money`, its storage is not partitioned when framed. It shares
       the DNS zone and, in Chrome, may share the application's renderer process. Both are recorded
       in the threat model.
   - **Security-critical steps open a top-level vault window:** passkey enrolment, unlock, word
     display and entry, restore, export, and every spend confirmation. The application could
     overlay or spoof an embedded frame, and Safari cannot create passkeys in a cross-origin iframe.
     Everything else stays in the embedded iframe. The split is revisited if UX testing shows too
     much friction (owner, 2026-09-26).
     - Only same-site application origins may frame the vault (`frame-ancestors`).
     - The vault composes each spend. The asset, amount and recipient are entered or confirmed in
       the vault window. In-pool recipients are shown with the SDK's address fingerprint.
   - **The channel.** The application opens the vault window with `window.open`, and the two talk
     by `postMessage`, checking `event.origin` and an explicit `targetOrigin` against an origin
     allow-list.
     - A strict `Cross-Origin-Opener-Policy` would sever that opener. So the interactive window
       sends `unsafe-none`, and the application at most `same-origin-allow-popups`.
     - The alternative is a strict COOP, relaying through a same-site headless vault iframe over
       `BroadcastChannel`, which needs a shared storage partition.
     - The vault's acceptance tests:
       - a popup round trip on Chrome, Firefox and Safari;
       - a matrix confirming that a headless vault iframe and the vault window share IndexedDB,
         Web Locks and `BroadcastChannel`. If they do not, the iframe is dropped, and sync and
         proving run in the vault window's worker.
   - **What the message API discloses.**
     - For a deposit or the pass purchase, it returns a receiving address or a prepared,
       proof-free transaction for the connected wallet to sign in the application.
     - For a spend, it returns only a status: pending, landed or failed. It never returns spend
       calldata, proof facts, nullifiers or amounts to the application.
   - **The seed** is 32 random bytes, exportable as the 24-word mnemonic. It is never derived from,
     or unlocked by, a wallet signature.
   - **Unlocking:**
     - **The passkey is the default.** A password is the fallback:
       - it can be phished by a lookalike domain, whereas the browser's WebAuthn UI enforces the
         RP ID;
       - anyone who copies the vault's storage can guess it offline, without rate limits.
     - **PRF rules:**
       - the RP ID is the exact vault host, with no related origins and no `/.well-known/webauthn`;
       - a random salt per wrap, stored with the ciphertext;
       - `userVerification: required`, and HKDF with a context label;
       - one wrap per credential.
     - **Enrolling a passkey:**
       - a passkey is enrolled only after the backup word check;
       - its PRF output is verified by a `get()` that unwraps a test ciphertext before it becomes an
         unlock method, never from a create-time output alone;
       - each wrap records its credential id, salt and provider.
     - Browsers and providers support PRF unevenly. Some return nothing, so a provider and browser
       matrix is part of the vault's acceptance.
   - **Extensions are outside what a web vault can defend.** An extension with host access to the
     vault (Chrome 122+, Firefox 150+ for WebAuthn) can do more than use its passkeys:
     - its content scripts run in the vault page;
     - they can read the words while displayed, the password as it is typed, the wrapped seed and
       the plaintext seed in memory;
     - they can rewrite the confirmation.

     The threat model records this and recommends a dedicated browser profile for the vault. It is
     also an argument for decision 5: other extensions cannot inject scripts into a
     `chrome-extension://` page.
   - **The words are the only backup.** A passkey unlocks the seed only on a device that holds the
     wrapped seed. Browser storage does not sync, and the only standard way to carry data with a
     passkey (`largeBlob`) is not portable. So a new device restores from the 24 words and enrolls
     its own passkey. The UI never calls the passkey a backup.
   - **Local storage is a cache.**
     - Safari deletes script-writable storage after 7 days of Safari use without interaction with
       the site.
     - So the vault calls `navigator.storage.persist()`, shows the result, and on Safari explains
       the rule.
     - A "seed missing" flow restores from the words and enrolls a passkey again. It warns that
       local history, live records and companions are lost, and says what that reveals to the
       server. It waits out any in-flight record's deadline before planning again.
     - An encrypted record backup is considered before mainnet.
   - **Several devices.** A seed may be used on more than one device, with sdk-spec §9.1's caveats
     shown in the UI:
     - records do not sync;
     - a note in flight on one device is not spent again from another until its record dies.
   - **What unlocking protects.** At rest the ciphertext is protected by the passkey or password.
     While unlocked, the seed is protected only by origin isolation: it is plaintext in the vault's
     JavaScript and WebAssembly memory. Auto-lock terminates the workers that hold the seed or
     prove, after zero-filling buffers.
   - **Locking and in-flight spends.** Records are encrypted under a key derived from the seed.
     - Auto-lock is deferred while any record is between `sent_to_server` and settled.
     - Otherwise a locked vault keeps only a small state apart from the seed: job id, prover URL,
       the relayer's transaction hash and the deadline. It alerts the user before
       `send_deadline − FALLBACK_MARGIN`; a fallback send needs an unlock.
     - Long-running work lives in the headless iframe, not the popup. Closing the application tab
       gives up the fallback. That affects liveness only, since the record dies at `valid_until`.
   - **The vault is trusted afresh on every load.** Hardening:
     - separate hosting, deploy credentials and CI approvers, and a hardened DNS and registrar;
     - `Origin-Agent-Cluster`, and COOP as above;
     - a strict CSP: `script-src 'self' 'wasm-unsafe-eval'` and `worker-src 'self'`, with no
       `unsafe-inline` or `unsafe-eval`;
     - a narrow `connect-src` (RPC, prover, relayer, OHTTP relay), `frame-ancestors` limited to the
       application's origins, and Trusted Types.

     Subresource Integrity and reproducible builds support audits; they do not stop a malicious
     deploy. A signed extension (decision 5) is the answer to code delivery.
   - **The password fallback's parameters** go in the vault specification: Argon2id in a pinned,
     reviewed WebAssembly build, versioned parameters, and a strength rule.
   - **SDK shape.** The SDK splits into a vault-side package (seed, core, store, proving,
     submission to the prover server and relayer) and an application-side client.
     - The application's client handles only deposits and the pass purchase. The vault prepares
       the transaction (note, calldata, fee bounds), and the connected wallet signs and sends it.
     - There is a versioned keyring format with several wraps, and a lock API.
     - Addresses are gated on the backup check.
   - **The vault's message API is designed as the future extension's provider API,** with the same
     disclosure rules.

5. **Later: the Templar wallet as a Chrome extension.**
   - A fork of the Argent account contract provides the public account.
   - **One 24-word seed, two derived key families:**
     - the Templar keys (Templar's own derivation, frozen as `TEMPLAR_*_V1` over the BIP-39
       entropy);
     - the account key, by a **Templar-specific** labelled derivation from the same entropy
       (decided 2026-09-26).

     The words therefore restore only in Templar, which keeps sdk-spec §3.1's rule: never type them
     into another wallet. Both families get known-answer vectors, and a Math Reviewer checks them
     before release. The alternative, an Argent-compatible path, would need §3.1 amended and the
     risk of importing the words elsewhere accepted.
   - **One seed controls both** the public account and the private notes. They cannot be linked on
     chain except by the user's own deposits from the account, withdrawals to it, fallback
     submissions from it, or a pass it holds.
   - **Moving from the vault** is a separate vault-window flow, never part of the message API.
     - By default the user imports the 24 words. Another wallet's 12-word mnemonic is never
       imported (sdk-spec §3.1).
     - A handoff, if built:
       - pins the Chrome Web Store extension ID and uses `externally_connectable`;
       - requires re-entering the words or confirming a fingerprint;
       - retires the vault's copy afterwards.
     - In-flight spends are finished or left to expire first. Notes do not move.
   - **The provider.** The extension exposes the get-starknet provider for its account, plus a
     separate, namespaced `templar:*` feature behind its own per-origin permission. That feature is
     neither exposed nor announced to a page before the permission is granted, and it follows
     decision 4's disclosure rules. The extension's account never co-signs private spends.

6. **Device-side proving** (no prover server; submission still through a relayer) is decided in its
   own ADR, after the benchmark spike in `bench/m31-device-proof1/PLAN.md`.
   - It is expected to rest on native M31 arithmetic in Cairo, unless felt252 emulation passes a
     tier. Native M31 needs:
     - the qm31 libfuncs in Starknet's audited allowlist;
     - the qm31 component in the small path's recursion circuit, with a root Starknet accepts.
   - It also needs an adapter class that accepts its proof version and statement account; see
     decision 2's adapter choice.
   - The current estimate: out of reach for phones and browsers, and at best a 32 GiB desktop tier
     with native M31.

7. **Phases.** Letters, to avoid clashing with relation names.
   - **A. Design, before any code.**
     - Revise the pool V3 spec for V6: the relation, the statement layout, the bridge checks, the
       statement account, the adapter's class and values, and the cutover.
     - Restate the soundness arguments without bound mode:
       - the identity rule, with `ak₀ = H(AUTH, sk₀)` computed in-circuit from input 0's `sk`,
         never a witness, keeping its mutation kill;
       - Invariant B becomes "every published limb except the tag and padding enters the binding";
       - S1 stays as the stranding argument, and S2–S4 go.
     - Amend sdk-spec and prover-server-spec for r6. Specify the routing adapter.
     - Math and protocol design sign-off (ADR-0026 decision 9, `AGENTS.md`).
   - **B. Off-chain removal of bound mode only.** The V5 ordinary path stays until the swap.
     - First, move the shared-path tests to ordinary fixtures: the server's admission and
       ticket-state test, pool V3 pins and proposals, the free full withdrawal, and an
       ordinary-only pool V3 end to end.
     - Add the rules that need no vault: RPC and identity separation, linkable marking, and the
       refusal of `account ≠ 0`.
   - **C. Implement V6.**
     - The relation, bridge and statement account; SDK core and WebAssembly proving (`v6`), server
       `r6`, and relayer support.
     - Tests: §4.4 without the mode cases, the cross-version known-answer test, the hiding
       regression (F27), and a pool end to end.
     - Measure caps, L2 gas and Blake from a V6 virtual-OS run on live Sepolia state, plus
       WebAssembly timing. State whether a Blake and component-size check stays in the prover
       binary, now that the class allowlist and the padding that carried it are gone.
     - An implementation review by the Math Reviewer.
   - **D. Sepolia deploy, then a dual-version release.** Every on-chain action is user-approved.
     1. Declare and deploy the V6 statement account and adapter. Read back the adapter's six
        storage slots (pool, statement, statement class, OS program, `max_proof_age`, account tag)
        as server startup and `verifyPins` do.
     2. Release the SDK, server and relayer with those pins, before `propose`:
        - the server starts with both R0 relations, treats the inactive one as dormant rather than
          fatal, and switches on `get_verifier('R0')` at apply without a restart;
        - the SDK shows a pending R0 proposal equal to its pinned V6 adapter as the planned cutover.
          It still refuses deposits, but without the "withdraw instead" alarm.
     3. Announce the cutover.
   - **E. Sepolia cutover.**
     1. `propose('R0', adapter)`.
     2. Deposits are refused from `propose`, and r5 jobs from `eta − pending_margin`. The default
        margin is `max_proof_age × 6` = 6,144 s, so with `T` = 7,200 s refusals start about
        18 minutes after `propose`.
     3. `apply` within `[eta, eta + T]`; otherwise the proposal lapses and is proposed again.
     4. V5 records die at `valid_until` plus the record depth and are planned again. The relayer's
        state from denied V5 spends is cleared.
     5. A Sepolia end to end up to the gateway: P6's ordinary deposit is spent under V6 through the
        SDK, the r6 server and the relayer's simulation. The gateway still refuses PROOF2.

     The outage is acceptable on Sepolia, where the gateway refuses large proofs anyway.
   - **F. The vault.**
     1. Its specification, with a crypto and protocol review.
     2. Its implementation and the SDK split.
     3. An implementation review.

     The web application's launch is gated on F.
   - **G. Specs and guide.**
   - **The extension** follows, with the derivation review of decision 5.

## Alternatives considered

- **Keep both products** (ADR-0026). Rejected: the costs above buy only co-signature, and crypto
  users already treat a leaked seed as theft.
- **Keep bound mode in the protocol, dormant.** No new relation and no verifier swap. Rejected:
  - the dormant path stays in the relation and the bridge to be audited and maintained;
  - removing it before mainnet costs one relation version and a Sepolia swap.
- **Remove only the bridge's signature path:** a V6 statement account that refuses `account ≠ 0`,
  on the unchanged V5 circuit (which already enforces `m = 1 ⇔ account ≠ 0`). No circuit review,
  but the mode bit and `WAUTH` stay in the circuit and the SDK core. It is the fallback if phase
  A's review finds the circuit change riskier than expected.
- **Bound notes as an opt-in "vault mode"** for large holders. Rejected: a second note kind and all
  of the complexity above for a niche.
- **A seed derived from a wallet signature.** Rejected: any site can request the signature, and
  with ordinary notes that is theft. Key rotation would also change the seed.
- **The seed in the application's own origin** (no vault). Rejected: any compromise of the
  feature-rich application would steal every unlocked seed.
- **Custodial or MPC key services** (for example Privy, Web3Auth, Turnkey). Rejected: the prover
  needs the raw key, so the provider would become a trusted party again.
- **A passkey as the backup,** syncing the wrapped seed through a vault server blob or
  `largeBlob`. Deferred: it is a new component whose store learns credential usage, and it needs
  its own design section.
- **A local Cairo proof calling the account** (ADR-0018 PROOF1). Moot without bound notes.

## Consequences

- **Privacy.** The prover server, relayer and ticket redeemer do not learn the spender, absent
  timing and network correlation. The service still learns:
  - the statement and the full pool calldata, early;
  - for a free full withdrawal, that the spend empties its inputs;
  - the client's network metadata, unless OHTTP is used.

  Further limits:
  - The operator's ticket issuer can correlate pass claims with spends by timing.
  - The vault and the application front end, both served by the operator, are trusted not to
    correlate the connected account with vault activity. A compromised deploy of either could.
  - Until invokes are relayed (F06), an invoke or P1 settlement publicly links its submitter
    account to the spend.
  - PROOF2 no longer differs by mode, so the padding work is moot.
  - Once ADR-0024 gate 4 establishes the client proof's hiding, PROOF2's witness holds only that
    proof and public data. PROOF2 hiding (ADR-0024 gate) then no longer has to hide a mode or an
    account.
- **Gates.** Real value stays gated on ADR-0024's hiding (gate 4) and review (gate 5) gates.
- **Reach.** Any wallet can deposit and withdraw, including Controller, guardian, multisig and
  hardware accounts. There is no per-spend wallet prompt.
- **Losses:**
  1. A leaked Templar seed is theft of the pool notes and the shadow-account positions. In the
     extension it also controls the public account.
  2. There is no rotatable second factor: a suspected leak means sweeping to a new seed, which
     costs a ticket per spend except a full withdrawal.
  3. There is no wallet prompt. The vault's confirmation replaces it and shows more. But it
     depends on the vault origin, and on the browser's extensions with access to it, not being
     compromised.
  4. There is no per-account free-withdrawal cap. The global and per-address buckets remain, and
     over OHTTP only the global and per-relay bounds apply. So a mandatory proof-of-work stamp for
     free jobs over OHTTP (PS-13), or a per-note or per-asset free limit, is required before free
     withdrawals ship.
- **New obligations:**
  - **Vault:** its specification, its hardening, and its crypto review.
  - **Custody fallbacks:** the PRF matrix, the password fallback's parameters, and the "seed
    missing" and restore flows.
  - **Untested paths:** deposits signed by extension wallets, and a wallet API for proof-carrying
    transactions if the connected-account override is wanted.
  - **Relaying invokes** under F06 before the web application launches.
  - **Reviews:** Math and protocol design review, then implementation review of V6, and a math
    review of the extension's derivation.
- **Simpler operation:**
  - no account-class matrix, bound freezes or key-rotation window. Operational freezes stay: the
    gateway, OS-program rotation, and verifier proposals;
  - a self-hosted prover no longer needs an operator-controlled node.
