# Pool V3 spec (R0 V6) design review record

Design review of [docs/pool-v3-spec.md](../pool-v3-spec.md) revision 1: phase A of [ADR-0027](../adr/0027-one-wallet-model.md), on 2026-09-26. Three independent, read-only reviewers ran: the Math Reviewer required by `AGENTS.md`, a Protocol Reviewer, and an adversarial reviewer. Each finding was then checked by a skeptic that tried to refute it. Every confirmed finding is applied in revision 2 of the spec.

| Reviewer | Verdict | Confirmed | Rejected |
|---|---|---:|---:|
| Math | CONDITIONAL GO | 4 | 7 |
| Protocol | CONDITIONAL GO | 13 | 1 |
| Attacker | CONDITIONAL GO | 7 | 5 |

No blockers were found. The protocol and adversarial reviewers cleared phase B (removing bound mode off chain) to start. The routing adapter is immutable once deployed, so its interface is fixed by revision 2 and re-checked before phase C builds it.

## Math review: CONDITIONAL GO

R0 V6 is sound as a relation. It is V5 with m := 0 and account := 0 substituted. I walked payment5.rs constraint by constraint, and the only bound-only parts are these: the account guess (payment5.rs:582-583), the m booleanity check and mode_rules (:586-588, :548-557), the two WAUTH hash requests (:627-636), the per-word selects (:638-639), and the published account limbs (:746-748). With m = 0, each select reduces to H(AUTH, sk) and the WAUTH outputs are multiplied by zero, so no ordinary constraint depended on the removed ones. The following are all V4/V5-common and carry over unchanged: nonzero token, sk and rho; the position and amount bit booleanity checks; the real input 0; the e1 dummy rules; the NOTE/INNER/OWNER/NF hashes; membership; conservation with carries in {-2..1}; the exit bit; and the identity mask. V6's accepted set is therefore V5-ordinary's accepted set up to the limb map. Invariant B' holds limb by limb against spend5.cairo:37-52 and the cairo-r5 bridge's binding (lib.cairo:182-208). The layout arithmetic is right: 2 + 13*9 + 8 = 127, plus 2 limbs of valid_until = 129, padded to 132 = 33*4. The last output is [valid_until_hi, 0, 0, 0]. Keeping TMR0_BIND_V5 creates no on-chain confusion, because the pool acts only on the binding and routes pin statement, class and tag. The conditions for starting phase C are spec amendments, not redesigns: - (1) Replace the…

**Confirmed (applied in revision 2):**

| Id | Severity | Section | Finding |
|---|---|---|---|
| MR-V6-1 | high | 4.3 (identity), 4.4 (mutation kills) | The proposed kill for the load-bearing identity rule cannot catch the realistic mutant: an ak that is guessed once and fed to both OWNER0 and IDENTITY. The tamper test as written is either vacuous or defeats itself. |
| MR-V6-2 | high | 5.2, 3 (equivalence), 11.3 | Section 5.2 argues cross-version safety only by where messages come from. Pool safety also needs every route's relation to agree on note and nullifier semantics. This invariant is load-bearing across the cutover and for any later route, and the spec never… |
| MR-V6-5 | medium | 4.4 | The test list says 'in addition to V4's list' and 'V4's mutation list carries over'. That leaves out V5's reviewed F09/AB-IM1 malicious tests and several circuit tests, and in V5 many of those run only on bound fixtures. |
| MR-V6-6 | medium | 4.4, 15 (phase C tests) | Tests for the cross-version and stranding claims are missing, and the scope of the cross-version KAT is unspecified. |

**Rejected by the skeptic:**

| Id | Finding | Why rejected |
|---|---|---|
| MR-V6-3 | The equivalence claim is one-sided and imprecise. It says V6 computes V5's values for m = 0 witnesses (completeness) but not that V6… | The finding misreads what carries soundness. V6 is defined normatively by its own constraint list (pool-v3-spec.md:101-119: V4's constraints plus changes, then outputs… |
| MR-V6-4 | The spec gives no V6 offset table or decode obligations, although ADR-0027 says the design phase fixes the bridge's offsets. valid_until… | The layout is fixed, though not tabulated: - Section 4.1 (pool-v3-spec.md:83-89) gives the ordered fields with widths, 129 limbs, three zero padding limbs and 33 QM31… |
| MR-V6-7 | The hiding regression is only named. V6 changes the trace: hash batching, four fewer permutations, the mode gadget removed and 33 outputs.… | The content of the regression is defined by F27, and the spec already requires re-running it on V6's circuit (pool-v3-spec.md:146, :555). That is exactly the answer to… |
| MR-V6-8 | The stranding section overstates its case. The V5 statement account stays deployed and emits exactly the message shape and binding that the… | The factual points hold. The V5 account stays deployed and emits a route-compatible message (cairo-r5/account/src/lib.cairo:82-84). But none of them is a defect: -… |
| MR-V6-9 | Invariant B' is correct but needs precise conditions and one useful corollary. The binding does not identify the relation, which matters… | The finding itself agrees Invariant B' is correct. 'Accepted statements' (pool-v3-spec.md:121-123) already means bridge-decoded, with the canonical felt, amount and… |
| MR-V6-10 | Section 12's PROOF2 argument ('witness holds only that proof and public data') holds only if the statement account's execution is a… | Section 5.3 fully specifies __execute__: the caller-0 check, verify_payment(proof_data), the chain check, and one fixed message (pool-v3-spec.md:185-191). It adds 'There… |
| MR-V6-11 | 'V4's constraints 1-8 hold, with these changes' leaves open that V4's constraint 8 (identity over sk0) is replaced. The spec also does not… | Constraint 2 explicitly replaces the V4 handle: 'This is V5's ordinary handle (ADR-0027 amends ADR-0023's H(IDENTITY, sk0 \|\| scope))' (pool-v3-spec.md:106-113). The two… |

## Protocol review: CONDITIONAL GO

Nothing blocks implementation, and phase B (removing bound mode off chain) can start now. The protocol core is sound. A proof can match at most one route: the message hash covers the OS-enforced from_address, and routes are keyed by statement. A proof cannot match a route it was not made for. The facts and age checks carry over Proof2Adapter's unchanged. The outage start time is right: T 7,200 s minus the 6,144 s margin is 1,056 s, about 18 minutes, as in config.rs:260-262. The V6 statement account loses nothing that ordinary spends needed. The routing adapter will be immutable once deployed, so its interface and keying must be fixed before phase C builds it. Conditions: (1) the adapter gets a view that lists every pending route proposal; (2) the SDK, server and relayer pin and check the full active route set through views, not just the adapter address and one route read by storage slot; (3) OS rotation is made consistent with how routes are keyed, and the P1 adapter is covered; (4) dual-version operation is specified for the relayer and the SDK, not only the server; (5) the spec gains a normative checklist for admitting a route. The medium findings should go into revision 2 of the spec before the Sepolia deploy (phase D).

**Confirmed (applied in revision 2):**

| Id | Severity | Section | Finding |
|---|---|---|---|
| PV3-1 | high | 6.3, 9.5, 10.3 | Nobody can find a pending route addition, which is the dangerous case, using the views the spec lists. So the promised rule (deposits refused and an exit offered while a route change is pending) cannot be built as specified. |
| PV3-2 | high | 10.2, 9.5, 11.1, 10.3 | The SDK and server pin only the adapter address and the V6 route. If an extra route were applied (a missed pending window, or a route added to the adapter between its deployment and the R0 swap), nothing would notice. The pin reads also assume storage slots… |
| PV3-3 | high | 6.1, 6.4, 13, 8 | The spec says OS rotation becomes a route change in which the old route stays until its proofs age out. That contradicts keying routes by statement, and it ignores the P1 adapter, which still pins one OS program. |
| PV3-4 | medium | 6.3 ('a route is as strong as a… | The spec states the principle but gives no criteria for admitting a route. The statement_class pin also binds less than it seems. |
| PV3-5 | medium | 9.5, 11.1, 11.2 step 4, 10 | Dual-version operation is specified only for the server. The relayer and the SDK as built handle one version at a time, and the server needs more changes than the spec lists. |
| PV3-7 | medium | 7.2, 7.4 | Until P7 exists, the fallback for plain spends is in practice 'the vault submitter, at once, after any relayer refusal'. The spec has no consent rule for that and no rule on how the submitter is funded. |
| PV3-8 | medium | 10.3, 6.3 | Refusing deposits while a pinned, planned change is pending protects nothing and costs a lot of liveness. On mainnet each device route or OS rotation would stop deposits for at least 7 days. |
| PV3-9 | medium | 12 | The threat model has no row for the owner's route lever, the fallback submitter, a second relayer, or the OHTTP relay. |
| PV3-10 | medium | 13 | The liveness section misses the server's refusal window for pending changes, and what happens when the relayer is down or the submitter has no funds. |
| PV3-11 | low | 6.3, 6.2 | The route timelock differs from pool_v3.cairo's propose/apply/cancel in details the spec does not state. |
| PV3-12 | low | 9.2, 9.3, 7.3, 10.2 | The admission and job-start lists leave out checks the server actually runs, and some cross-references and pins are wrong or incomplete. |
| PV3-13 | low | 6.2, 17 Q1 | The routing adapter hardcodes the proof variant and output version (facts[1], facts[3]). If an OS release changes the output version, a new adapter class and an R0 swap are needed. |
| PV3-14 | low | 11.3 | The end to end after apply exercises only the good path. The new governance lever is never exercised on a live chain before mainnet. |

**Rejected by the skeptic:**

| Id | Finding | Why rejected |
|---|---|---|
| PV3-6 | How in-flight V5 state is handled at the cutover is under-specified. The relayer keeps submitting V5 spends right up to apply and will deny… | The main premise does not hold. The server refuses r5 jobs from eta minus pending_margin (docs/pool-v3-spec.md:404-409, 466-468), and the margin defaults to… |

## Attacker review: CONDITIONAL GO

R0 V6 and the V6 statement account add no forgery or theft path: the relation is V5's ordinary mode, ak₀ is derived in-circuit, the pool recomputes the binding, and there is no signature path. The routing adapter as specified, however, weakens the timelock's exit protection against a compromised owner. A pending route proposal for a new key cannot be found through the specified views. Route changes can be applied on the adapter before it is active, and the planned-cutover exemption checks only its address. Keying routes by statement also turns every OS rotation into an outage. Separately, the operator's relayer can force a publicly linkable fallback that ties spends to the connected account. These must be fixed in the spec before the adapter is implemented (phase C) and before sign-off. Phase B can proceed.

**Confirmed (applied in revision 2):**

| Id | Severity | Section | Finding |
|---|---|---|---|
| PV3-A1 | high | §6.3, §9.5, §10.3 (route proposal… | The spec gives no way to find a pending route proposal for a statement key nobody knows about. A compromised owner can call propose_route(S_evil, R) with a fresh key and let it run through T. SDKs and servers that query get_route_proposal by known keys never… |
| PV3-A2 | high | §6.1, §6.3, §10.3, §11.1-11.2… | Anyone watching sees route changes only on the adapter that is currently active, yet the adapter accepts propose_route/apply_route from the pool's owner even when it is not the pool's R0 verifier. The planned-cutover exemption checks only that the pending R0… |
| PV3-A3 | high | §6.1, §6.4, §13 (route keying vs OS… | Keying routes by statement contradicts §6.4. A route for a new OS program on the V6 statement account replaces the old route in one step (propose_route adds or replaces). At apply, every in-flight proof under the other program is rejected: before the gateway… |
| PV3-A4 | high | §7.2, §12 (forced linkable fallback) | The operator's relayer can deanonymize a plain spend on chain whenever it wants. A relayer refusal triggers the fallback at once ('submit at once after a refusal'), and until P7 the only fallback is the vault's submitter account. The spec says 'marks it… |
| PV3-A6 | medium | §7.5, §17 Q5 (free-withdrawal griefing) | The mitigations the spec offers do not stop deposit cycling. An attacker deposits a note at or above the priced minimum, takes a free full withdrawal, and repeats. Each cycle costs one deposit's gas but buys a PROOF2 (about 80 s at about 29 GiB) plus the… |
| PV3-A8 | medium | §9.5, §7.3, §11.3 (route checks per… | The server and relayer re-check only get_verifier('R0') per job, never the route. After a route replacement applies (a new age or OS program), they keep proving and relaying spends that cannot land, and the relayer then denies those notes for good. §11.3… |
| PV3-A9 | low | §12 (routes partition the anonymity set) | The on-chain observer row lists only V4's data plus valid_until. Each spend's proof facts also show the base block, the OS program, the statement address (inside the message) and the proof version. Once there is more than one route (a device route, or a… |

**Rejected by the skeptic:**

| Id | Finding | Why rejected |
|---|---|---|
| PV3-A5 | The adapter's statement_class pin binds only what the statement account says about itself. The class hash in the message comes from the… | Refuted. The claim that 'nothing checks the class on chain' is wrong. Server startup reads the statement account's class on chain (server/prover/src/main.rs:88), and the… |
| PV3-A7 | The rationale 'OHTTP is no longer mandatory, since no V6 read names an account' is inaccurate. The operator serves the application, which… | Refuted: the spec already records the linkage. The rationale 'no V6 read names an account' is literally true. OHTTP was mandatory in V5 because bound-mode spend reads… |
| PV3-A10 | 'OS rotation becomes a route change ... with no R0 swap' covers R0 only. Pool V3's P1 verifier stays a Proof2Adapter pinned to one OS… | Refuted: the spec already covers this by reference. §6.4 explicitly says 'with no R0 swap' (docs/pool-v3-spec.md:255-256), and §8 keeps the P1 verifier unchanged and… |
| PV3-A11 | A bound address cannot be told apart from an ordinary one: the address body is chain, pool, receiver and key. The pool's deposit accepts… | Refuted: the spec already handles this. It states that bound receivers are unspendable and that 'any bound address anyone still holds is a burn address'… |
| PV3-A12 | The vault is same-site with the application, and the prover, relayer and redeemer will probably live under the same domain. The rule 'no… | Refuted. The spec states the rule as a normative outcome (docs/pool-v3-spec.md:309-313), and enforcement belongs to the vault specification, which is out of scope here… |

## Answers to the spec's open questions

Summarized in revision 2, §17. Full text from each reviewer:

**Math.** Q1 (small-proof facts): this is mostly a protocol question. The binding view requires that whatever facts layout a small-proof route uses, the facts commit to Poseidon(statement, 0, 5, statement_class, account_tag, chain, pool, binding), and the route's relation meets the invariants in MR-V6-2 (identical nullifiers and notes, the identity slot, binding semantics). If the V2 small proof's layout differs, deploy a new class rather than making fact indices configurable per route. Every new route relation needs Math Reviewer sign-off. Q2 (per-route ages): this has no soundness effect in my lens. Root acceptance and expiry are enforced by the pool, independent of max_proof_age. Leave it to the protocol reviewer. Q3 (governance delegation): this is the protocol reviewer's lens. The only math point is that a route is as strong as a verifier and must pass the route-relation invariants of MR-V6-2. Q4 (Blake and component-size check): keep a cheap check at the binary level that a job's virtual-OS run fits the standard leaf bucket, and refuse outliers rather than pad them. The virtual-OS caps may not line up with bucket boundaries. PROOF2's public header (the version and the bucket root) must stay uniform across spends, as the P5 uniformity gate established (account-bound-note-spec.md:1065-1079). A spend that crossed into another bucket would be publicly distinguishable, whatever the hiding inside PROOF2. Q5 (free jobs over OHTTP): this is outside my lens (protocol and abuse).

**Protocol.** Q1 (small-proof facts): Yes, as far as the repository shows. The version tag in facts[0] names the proof format, not its size. PROOF1 is the V1 small proof. The upstream gateway defaults allow only V2 (bench/m31-device-proof1/PLAN.md:54-55), and project notes from the 2026-09-23 upstream check say V2 verification accepts both the small log20 root and registered large-path leaves. So a V2 small proof from a device should carry 'PROOF2'. The nine-felt Snos layout is the same for PROOF1 and PROOF2 (proof_adapter.cairo:44-59 against adapter.cairo:58-73), so one routing class serves both. Recommendation: keep proof_version per route, also pin the variant and output version per route (PV3-13), and check the V2 small-path tag against the sequencer source before the device ADR. Q2 (per-route proof ages): Yes, but only when a device route exists; use 1,024 until then. The SDK already takes max_proof_age from its pins (sdk/core/src/result.rs:94), so make it a per-route pin. The server should move max_proof_age from the network section to each relation and route. pending_margin should default to the largest age served times 6 s, and the one-age startup check (main.rs:98) should compare per route. Q3 (governance delegation): Reading the owner and T live from the pool is the right model. Copying the owner at construction would create a second governance key that does not follow the pool's two-step ownership transfers. T never changes in pool V3 (pool_v3.cairo:250; no setter). Add a get_pool() view, bind the adapter to exactly one pool in the constructor, read T at both propose and apply, and state that transferring the pool's ownership also transfers route governance. The owner call to the pool is a view that takes no lock (pool_v3.cairo:555-557), so there is no reentrancy concern.…

**Attacker.** Q1 (small-proof facts): the repository cannot confirm what facts[0] is for the V2 small proof. The V1 adapter used 'PROOF1' with the same nine-felt layout and even the same OS program hash (bench/controlled-push-e2e/cairo/src/proof_adapter.cairo:44-59), which suggests only facts[0] changes. If so, pinning proof_version per route is enough; if the layout differs, a new class and an R0 swap are acceptable. From a security standpoint, add a small-proof route only after Starknet's verification of that proof version for virtual-OS facts is confirmed on the target network. Such a route needs its own key (see PV3-A3) and splits the anonymity set (PV3-A9). Q2 (per-route ages): yes. Give the server per-route ages and compute pending_margin per route (age × the slowest assumed block time). Nothing in V6's statement account depends on base-block state, so the age is not a soundness bound for V6, but propose_route should still enforce 0 < max_proof_age ≤ E + Q. Check the route per job (PV3-A8) so a changed age cannot burn tickets. Q3 (governance delegation): reading the owner live from the pool is the right model. Copying it at construction would leave a former owner in control of routes after a transfer, and T is a constant in pool V3, so reading it live or copying it is equivalent. Note that pool V3's ownership transfer is two-step but not timelocked (bench/m31-pool/cairo/src/pool_v3.cairo:540-553); routes inherit that, as every pool lever does, and the SDK should surface OwnershipTransferStarted/Transferred. Delegation alone does not make the lever safe: route changes must be gated on the adapter being the active R0 verifier, and pending proposals must be enumerable (PV3-A1, PV3-A2). Q4 (Blake and component-size check): keep a Blake cap. The account class is now fixed and…


## Re-check of revision 2

A fresh Math Reviewer and a fresh Protocol Reviewer checked revision 2. A skeptic then tried to refute each new finding. Every confirmed finding is applied in revision 3.

| Reviewer | Verdict | Confirmed | Rejected |
|---|---|---:|---:|
| Math | CONDITIONAL GO | 7 | 2 |
| Protocol | CONDITIONAL GO | 9 | 3 |

### Math: CONDITIONAL GO

Phase C may start. The design is sound as a relation: R0 V6 is V5 with m = 0 and account = 0 substituted (checked against payment5.rs:572-751). The limb map and offsets check out: limbs 0-126 are V4's, valid_until sits at 127-128, padding at 129-131, 132 = 33*4, and the last output is [vu_hi,0,0,0]. Invariant B' holds against spend5.cairo:32-53 and cairo-r5/bridge/src/lib.cairo:179-208. Reusing TMR0_BIND_V5 is safe because routes pin the message origin. The gaps are in the test and route rules, not in the relation. Conditions: (1) now, before phase B deletes anything, amend §10.1 so the starknet.js TMR0_BIND_V5 vectors in cairo-r5/kat survive, and make the §4.4 KAT start from V6 limbs (F3). (2) Before phase C pins the V6 circuit hash, and before the Math implementation review, amend §4.4 per F1, F2, F4 and F7, with F8 and F9 as wording fixes. (3) Before any route other than the initial V6 and P1 routes is proposed, amend §6.5 per F5 and F6. None of these changes the adapter's interface or the relation.

**Prior findings.** MR-V6-1: partially addressed. Checking identity and OWNER0 against the AUTH hash's output (auth0.out) kills the single-guessed-copy mutant, provided auth0.out is recorded at that output. But the 'no guess_* variable' clause cannot be met (F2), the plant-test citation is wrong (F8), and the wiring scope stops before the commitment and nullifier fan-out (F1). MR-V6-2: partially addressed. §6.5(a)-(c) and 'section 3 is the instance' are stated. But (a) does not guarantee one nullifier per note (position fixing, dummy nullifier), (c) is not a checkable criterion, there is no P1 analog or cross-domain conservation rule (F5), and the no-review path is keyed on 'relation' rather than on a reviewed, parameter-free class hash and a verified OS program (F6). MR-V6-5: largely addressed. The porting rule and table re-run are stated. The wording leaves bound-fixture tests and the ordinary halves of mixed tests ambiguous (F9). The table lacks V6-specific rows, does not exclude the pinned-hash test from counting kills, and does not commit its script (F7). MR-V6-6: partially addressed. The V5-ordinary vs V6 equality and the binding KAT are specified, and the limb map and bridge offsets are…

| Id | Severity | Finding |
|---|---|---|
| F1 | high | The required wiring test covers only the key wires (sk into AUTH and NK, AUTH into OWNER and IDENTITY, NK into NF). It skips the note and nullifier wires that feed two or more gates. A guessed copy on any of those passes every value test and every listed… |
| F2 | medium | 'Structurally, no guess_* variable enters those slots' cannot hold for the honest circuit, because every hash digest word is itself a guessed M31 lane. Where auth0.out is recorded is not specified. |
| F3 | medium | §10.1 retires cairo-r5/kat as 'SNIP-12 known-answer tests'. But that directory also holds the only starknet.js reference vectors for TMR0_BIND_V5, which the SDK core and the R5 bridge test against. Phase B is already cleared, so the anchor the §4.4 KAT needs… |
| F5 | medium | Invariants (a)-(c) are not enough to rule out a double spend, burned notes or inflation through a future route, and (c) cannot be checked as written. |
| F6 | medium | The path that skips Math review ('a new OS program or a new proof version of an existing relation') assumes the relation is a function of the statement class, and that the pinned os_program is the genuine virtual OS. The admission checklist guarantees neither. |
| F7 | low | The table rule ('re-run, dropping only the mode and account rows') omits V6's own mutants. It does not stop the ported F38 pinned-hash test from 'killing' every topology-changing mutant. It does not require the mutant script to be kept this time. |
| F8 | low | The plant test's cited source does not plant a mixed receiver. On the honest circuit the plant test passes trivially, so it cannot count as a mutation kill. |

**Rejected:** F4 (The spec already handles this structurally. The normative wiring test requires, for both inputs, ownerᵢ.ak ==…); F9 (The spec already handles this. The rule at spec:147-149 moves each test 'on ordinary fixtures'. That wording was added…)


### Protocol: CONDITIONAL GO

The core of the redesign is sound, and I found no forgery or theft path in it. Four things work as intended. (1) The activation gate, the enumerable get_route_proposals view, the full-route-set pins and the SDK exemption, which re-checks the whole adapter, together close PV3-A1 and PV3-A2. (2) Keying routes by statement, with a new statement instance per OS rotation, closes PV3-A3. (3) Reading the owner and T live from the pool is correct. (4) Pool V3's P1 path (pool_v3.cairo:389-391) passes [chain, pool, binding] exactly as the routing adapter expects. The deployed P1 statement account (cairo-p1/account/src/lib.cairo:17-39) meets §6.5's class checklist, and its binding is byte-identical to policy_binding (policy.cairo:84-107). On the questions asked: - The gate deadlocks nothing. It only stops routes being staged on the adapter a pending swap points to; the fix for that is to deploy a new adapter and propose again. - Only the pool owner can propose, so no outside attacker can use MAX_ROUTES or MAX_PENDING. The real risk is the owner locking the adapter by accident, because the cap and lapse rules are underspecified and the class is immutable. Conditions before the routing adapter…

**Prior findings.** PV3-1: addressed. get_route_proposals lists every pending proposal (§6.3:321-322); how lapsed proposals are treated is still open (PR2-6). PV3-2: partially. The route-set views replace the storage-slot reads (§10.2:579-588), but the exact-set rule breaks planned changes (PR2-2), the adapter class check was dropped (PR2-5), and P1 is not covered (PR2-1). PV3-3: addressed. Routes are keyed by statement with a new instance per rotation, and the P1 adapter is covered (§6.1, §6.4). Gap: a server's own route is identified by OS program (PR2-3). PV3-4: partially. §6.5's class checklist is good, but its relation invariants cover R0 only (PR2-4), and nothing makes the adapter itself immutable (PR2-5). PV3-5: partially. Dual-version operation for R0 is specified for the server, relayer and SDK; P1's two generations are missing (PR2-1), and "retry later" and retired generations are undefined (PR2-8). PV3-7: addressed. Consent and the submitter-funding rule are in §7.2. What remains is the ticket cost of declining (PR2-7). PV3-8: partially. The pinned-change exemption is sound given the gate, but the pins break after apply and removals are not covered (PR2-2). PV3-9: partially. Rows for the…

| Id | Severity | Finding |
|---|---|---|
| PR2-1 | high | §8 makes P1's verifier a routing adapter with the same owner route lever, but every watch, pin, pending-change and dual-version rule is written for R0 only. A malicious P1 route addition would therefore go unannounced and could drain the pool after T. At the… |
| PR2-2 | high | The SDK must see get_routes() equal to the pinned set exactly. No single release can pass both before and after a planned route change applies, so every planned OS rotation or device route stops SDKs from opening, spending or exiting. That is PV3-8's liveness… |
| PR2-3 | medium | A server's own route is defined as the route whose os_program matches its OS runner, and results and relay items carry only the relation. Once two routes share an OS program, the refusal rule names two routes, and the SDK and relayer cannot tell which route a… |
| PR2-4 | medium | §6.5's route relation invariants are worded for R0 V6 and do not apply to P1 routes, which the cutover admits 'checked against §6.5'. Nothing requires receiver-domain separation between kinds, although both kinds share one nullifier set. |
| PR2-5 | medium | The adapter is immutable once deployed, but the spec leaves several of its behaviours open. Unless they are fixed now, the build will encode ad hoc choices. |
| PR2-6 | medium | The rules for counting, lapsing and cancelling proposals are underspecified. Depending on how they are read, two pending additions can push the route count past MAX_ROUTES, replacing a route at the cap takes 2T, or lapsed proposals lock the adapter. The gate… |
| PR2-7 | medium | §7.2 says letting a record die costs 'liveness only'. In fact the job's tickets are already spent, and an unsent relay item is not refunded. The operator's relayer can withhold any spend for free, leaving the user to choose between a linkable submission and… |
| PR2-11 | low | The drill never exercises apply, removal, the last-route refusal, the activation gate or the P1 adapter on a live chain before mainnet. |
| PR2-12 | low | The rule that any bucket-check failure is the client's fault charges honest clients whenever the server's pinned bucket is wrong, for example after an OS rotation. With a fixed statement class and circuit, the client controls little besides the length of… |

**Rejected:** PR2-8 (Refuted. 'Retry later' fits the unchanged P4b handoff: it means not answering yet. The relayer already has that state…); PR2-9 (Not a defect of this spec. §7.5 is explicitly a summary: 'Account-bound spec §7.2 carries over (a summary; P7 specifies…); PR2-10 (Refuted. The no-route rule does not block retiring an unsound sole route. The owner can propose the fixed replacement…)


## Final check of revision 3

A read-only checker compared revision 3 with the 16 confirmed re-check findings. It found 13
addressed correctly and 3 partially (F3, F5, PR2-1), and none unaddressed or addressed incorrectly.
It also found 8 contradictions between sections that revision 3 had introduced. The partial items
and the contradictions were fixed in revision 3's final text:
- the `validate_bridge_r6` rejection cases;
- the note on binding tags across kinds;
- the remaining R0-only rules in §7.3, §9.2, §9.5, §11.2 and §13;
- §10.2 aligned with §10.3's removal rule;
- the constructor checks;
- §5.3 aligned with the admission checklist;
- the two meanings of `statement`;
- §4.3 aligned with §4.4's lanes;
- the status line;
- the refunds in the ticket states;
- the wording of the `IDENTITY` payload.
