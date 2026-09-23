# Templar go-to-market strategy

Date: 2026-09-23

Status: internal strategy draft; proposed experiments, not launch commitments

Scope: positioning, acquisition, distribution, incentives, and launch gates

## 1. Strategic thesis

**Win users who want STRK20's private payments and DeFi capabilities but reject
its mandatory disclosure and screening model. Retain them through useful
applications and a dependable product.**

The competitive hook is deliberately direct: **STRK20 with the mandatory
compliance machinery removed.** This means removing protocol-enforced auditor
access and deposit screening, not making a claim about users' legal obligations.
Controlled notes are the third product pillar, not a replacement for this hook
and not a compliance product.

The story has four parts:

1. **Credibility:** the Starknet, Cairo, and S-two proving foundation also used
   by STRK20, with open-source lineage from StarkWare's privacy implementation.
2. **Reason to switch:** no mandatory auditor access or screening machinery.
3. **Everyday utility:** ordinary private payments and open-note-equivalent DeFi
   interactions.
4. **Reason to build:** controlled notes for contract-governed private funds,
   including potential applications such as sealed-bid auctions.

The objective is a durable alternative privacy ecosystem, not a short-lived
increase in deposits purchased with incentives. Community objections to STRK20
are a demand hypothesis to test, not proof of product-market fit.

**Product sequence: dapp first, then wallet + infrastructure.** The dapp is the
initial customer-facing product. A standalone wallet and externally marketed
infrastructure are expansion products, not prerequisites for the first launch.

## 2. Positioning and message discipline

### Message hierarchy

**Comparative hook**

> STRK20's private DeFi proposition, without mandatory auditor access and screening.

**Credibility line**

> Same proving foundation. Different privacy model.

**Product line**

> Private payments. Composable DeFi. Programmable private applications.

**Longer description — target positioning, subject to qualification**

> Templar is an independent private token pool built on Starknet's Cairo and
> S-two infrastructure. It removes mandatory auditor access and screening,
> supports ordinary private payments and DeFi return flows, and extends the
> model with contract-controlled notes for private applications.

This describes the intended product. Public copy must label experimental,
testnet, and production capabilities separately; it must not imply current
feature parity or official StarkWare endorsement.

### What the competitive comparison can establish

STRK20's published model requires viewing-key registration and encryption to a
master key, with an operational process for scoped disclosure. It also describes
deposit screening. Contrast that architecture accurately, including its stated
safeguards; do not present it as an undisclosed exploit or ordinary public access
to everyone's funds. [STRK20 compliance architecture](https://www.starknet.io/blog/compliance-layer-onchain-privacy-strk20/)

Templar derives from the open-source privacy implementation and reuses native
virtual-OS/proof-verification infrastructure. That is a concrete engineering
lineage, not an inheritance of every upstream security property or audit.
[Upstream architecture](https://github.com/starkware-libs/starknet-privacy#architecture)

| Use | Avoid |
| --- | --- |
| Built on established Starknet proving infrastructure | Templar inherits all STRK20 security guarantees |
| No mandatory auditor access or protocol-level screening | Compliance-free means exempt from legal obligations |
| Independent implementation with a different privacy model | Official STRK20 successor or StarkWare-endorsed product |
| State exactly what is hidden and from whom | Untraceable, zero metadata, or guaranteed anonymity |
| Contract-controlled spending on selected notes | Controlled notes are a pool-wide audit or compliance layer |
| Describe reviewed components and their exact scope | The whole system is battle-tested because the prover is shared |

### Product direction versus existing documentation

The founder's direction for this strategy is **no viewing keys at all**; do not
reintroduce optional auditor/viewing exports as a GTM feature. This does not mean
wallets have no spending or encryption keys.

The current [README](../README.md), [push specification](push-payment-spec.md),
and historical [viewing/recovery decision](adr/0020-full-viewing-and-recovery.md)
still describe viewing capabilities. Reconcile the implementation, recovery
model, ADRs, and public documentation before advertising "no viewing keys" as a
verified property of a release. This strategy records product intent; it does
not silently supersede architecture decisions or remove implemented features.

## 3. Three product pillars

| Pillar | Job to be done | Demonstration | Qualification boundary |
| --- | --- | --- | --- |
| Ordinary notes | Hold, receive, transfer, and withdraw private value | Receive while offline, send, restore, and spend recovered funds | Qualify the exact shipping proof path, wallet, tokens, and recovery format |
| Open-note equivalent | Use external DeFi and return proceeds into funded private notes | Authorize a swap with a minimum return and recover the resulting note | Templar's reference uses ReturnNote; this is not a claim of identical upstream semantics or arbitrary DeFi support |
| Controlled notes | Bind private funds to application-defined spending rules | A sealed-bid auction with funded bids, correct settlement, and refunds | The auction needs its own reviewed protocol; controlled-note support alone does not establish it |

The existing [return-note reference](return-note-spec.md) covers transaction-local
external settlement. Public execution amounts and return metadata can remain
visible. Do not call all DeFi activity confidential merely because funds start
and end in the pool.

The [controlled-note reference](adr/0022-controlled-push-payments.md) requires
ownership plus controller approval. The controller does not gain the owner's
spending key, but scoped details and its identity are visible in the current
reference, and refusal can freeze value. An auction must separately specify bid
secrecy, deadlines, winner selection, settlement authority, non-reveal behavior,
and exits/refunds. Do not advertise guaranteed exits or hidden bids to the
controller without implementing and reviewing those properties.

**Ordinary notes establish utility; return flows preserve composability;
controlled notes expand what developers can build.** All three support the
no-mandatory-auditor position rather than displacing it.

### Product sequence: dapp → wallet + infrastructure

| Stage | Product and customer experience | Evidence needed to advance |
| --- | --- | --- |
| First: Templar dapp | Connect an existing Starknet wallet for public account actions; use Templar's private balance, deposit, receive, send, withdrawal, and qualified DeFi flows in one application | Repeat usage after credits expire, reliable recovery and settlement, understood costs, and a qualified client/proving experience |
| Expansion: Templar wallet | Make private assets and applications a persistent wallet experience rather than a destination users must repeatedly visit | Dapp users demonstrate demand for daily wallet use; choose extension/mobile/other delivery based on research and separately qualify key management and recovery |
| Expansion: Templar infrastructure | Offer reusable SDKs, APIs, proving/relay services, and application primitives to third-party builders | External teams request the capabilities, can operate integrations independently, and service reliability, economics, privacy boundaries, and support are qualified |

The first dapp must manage private-note access and recovery explicitly; connecting
an ordinary Starknet wallet alone does not establish either capability. Browser
proving, secure local state, and any required companion tooling need qualification.
Do not promise a browser-only or one-click experience before testing it.

Build the supporting proving, indexing, relay, and contract components needed by
the dapp, but do not simultaneously sell them as a mature infrastructure platform.
An internal SDK or preview for a design partner is not an infrastructure launch.
Likewise, compatibility with an existing wallet is not launching a Templar wallet.

Use the dapp to discover which components deserve to become products. Wallet and
infrastructure expansion may proceed separately or in parallel when their gates
are met; neither is an automatic day-90 deliverable. Controlled notes remain the
third pillar throughout, with a scoped application demo rather than an obligation
to ship every possible private application in the first dapp release.

## 4. Initial audiences and distribution

| Priority | Audience and motivation | Offer | Route to acquisition |
| --- | --- | --- | --- |
| 1: dapp launch | Privacy-conscious Starknet users, including prospective or existing STRK20 users who reject its disclosure model | A usable Templar dapp for transfers and supported DeFi flows, without first adopting a new wallet | Sourced comparison, hands-on demos, existing wallet communities, privacy researchers |
| 2: design partners, then infrastructure expansion | Wallet and DeFi developers who want to offer that choice | Early technical collaboration; later, qualified SDKs, services, and integration support | Direct technical outreach, Cairo developer groups, office hours, reproducible examples |
| 3: application partners | Teams needing contract-governed private funds | A scoped controlled-note application demo, followed by reusable primitives as qualified | Co-design with auction organizers and application developers |

Do not pivot the initial positioning to regulated payroll, enterprise compliance,
or controller-based auditing. Those are not the founder's chosen wedge. Also do
not assume existing STRK20 users are the entire market: interview people who
declined to use privacy products because of their trust models.

Begin with two ordinary/DeFi design partners and one application design partner.
Their initial job is to validate and use the dapp, not depend on an unfinished
wallet or infrastructure suite. Existing-wallet compatibility supports launch;
wallet distribution partnerships are opportunities, not assumed commitments.
Borrow established AMM/DeFi infrastructure where technically compatible rather
than launching competing liquidity venues just to support the pool.

## 5. Adapt the Sushi playbook

Sushi attracted Uniswap liquidity providers with SUSHI incentives and a migration
mechanism. The useful lesson is to combine an existing audience, a reason to
switch, and low switching costs. [Sushi's account of the vampire attack](https://www.sushi.com/blog/the-sushi-de-fi-glossary-2025)

| Original mechanism | Templar adaptation |
| --- | --- |
| Target established liquidity providers | Target privacy users and developers with a demonstrated objection to mandatory disclosure |
| Reward switching | Sponsor initial proving/transaction costs and pay milestone-based integration grants |
| Provide migration tooling | Offer supported onboarding, clear compatibility checks, and a user-authorized movement of funds |
| Retain economically useful liquidity | Retain repeat private activity, integrations, and applications after subsidies end |

### Proposed campaign: Choose Your Privacy

1. Publish a factual STRK20/Templar comparison with sources, release scope, fees,
   trust assumptions, and explicit unknowns.
2. Let prospects try a complete testnet flow without depositing real funds.
3. After launch gates pass, offer a capped onboarding credit and supported
   asset/route list. Existing privacy-product users are welcome, but do not make
   them disclose private transaction history or keys to demonstrate eligibility.
4. Onboard partner communities into the dapp. Use targeted integration work to
   improve that experience; expand grants to independent builders when the
   infrastructure offering is qualified. Publish terms and sponsorship disclosures.
5. Publish pilot outcomes: working flows, reliability, actual costs, and retained
   usage, not manufactured transaction volume or headline TVL alone.

Keep "vampire attack" as an internal analogy. The outward offer is user choice,
not a claim of taking assets without authorization or exploiting a competitor.

### Migration and privacy constraints

- STRK20 notes are not assumed portable into Templar. Determine the supported
  withdrawal/deposit or adapter route before promising migration, and require
  explicit user authorization for every asset movement.
- A public withdrawal followed by a deposit may be linkable. Migration cannot
  erase information already exposed or available under the source pool's model.
- Do not describe an atomic migration as unlinkable without a reviewed design.
- Do not require custody, unlimited approvals, viewing secrets, or a privileged
  migrator that can move arbitrary user funds.
- Pool balances are not AMM liquidity. Deposits alone do not establish useful
  activity, effective anonymity, or a sustainable business.
- Different assets, controllers, public metadata, and application patterns may
  distinguish users even inside a shared pool. Measure privacy under a stated
  threat model; do not equate total TVL with anonymity-set size.

## 6. Launch sequence and decision gates

Timings below are planning windows relative to strategy kickoff, not promises.
Research and testnet distribution can proceed while engineering is blocked.
Any real-funds phase waits for qualification, regardless of the calendar.
Owner roles describe responsibilities, not assumed staffing; one person may
cover more than one role.

| Phase | Owner role | Deliverables | Decision gate |
| --- | --- | --- | --- |
| Days 1–14: validate the wedge | Founder/product | Interview 15 prospective users and 5 builders; test trust-model versus utility messaging; recruit design partners | At least 3 concrete pilot commitments, not just social engagement; record price, latency, and trust objections |
| Days 15–30: earn credibility | Engineering/security + product | Reconciled claims, threat model, release-status matrix, testnet dapp with ordinary and qualified return flows; controlled-note/auction design brief | An outsider can repeat advertised dapp flows; existing-wallet connection, private-note recovery, and proving UX are qualified |
| Days 31–60: supported dapp pilot | Engineering + developer relations | Capped dapp cohort, partner-community onboarding, recovery drills, cost dashboard, disclosed subsidy program | Security and network gates passed before real funds; pilot completion and retention meet agreed thresholds |
| Days 61–90: expand the dapp or revise | Founder + developer relations | Case study, second repeat-using partner cohort, reduced subsidies, scoped auction prototype if qualified; wallet/infra demand assessment | Repeat use without incentives and manageable support costs; decide whether either expansion product is justified, rather than launching both on a calendar |

### Mandatory real-funds gates

- Independent review of the shipping contracts, proof statements, bindings,
  privacy construction, wallets, and relevant integrations; resolve blockers and
  publish scope rather than implying inherited audit coverage.
- Demonstrate actual target-network acceptance and successful lifecycle receipts
  for the exact release path. Simulation and local proof verification are not
  sufficient. Re-prove stale proofs when required.
- Test withdrawals, fresh recovery, malformed/replayed transactions, unavailable
  services, controller refusal, and app-specific exit/refund behavior.
- Document upgrades, configuration authority, token/issuer dependencies, RPC and
  indexing trust, metadata exposure, and incident-response responsibilities.
- Qualify latency, devices, supported tokens/accounts, relayer behavior, and
  capacity under realistic load; clearly distinguish client proving from total
  time to accepted settlement.
- Have counsel assess the intended operating model, service roles, marketing,
  jurisdictions, and any incentive/token plans. Do not turn architectural
  absence of screening into a legal guarantee.

As of the [2026-09-23 Sepolia run](../bench/m31-sepolia/README.md), a genuine
large-path PROOF2 was generated and verified locally, and the transfer simulated,
but the tested gateway rejected its proof version. The
[v0.14.4 announcement](https://community.starknet.io/t/starknet-v0-14-4-prerelease-notes/116341)
and protocol support do not resolve that operational gate. Earlier PROOF1
experiments do not establish production readiness or feature parity for the
compact-client PROOF2 path. Treat network access as a dependency, not evidence
of application-specific discrimination.

## 7. Economics and incentives

**Default: no token launch, no deposit APY, no uncapped transaction rewards.**
These are proposed GTM choices, not permanent protocol decisions. Revisit a
token only with a concrete purpose, reviewed economics, and appropriate legal
assessment; do not depend on an implied future airdrop to recruit users.

Spend in this order:

1. Product/security readiness and operational reliability, budgeted separately
   from acquisition so an incentive campaign cannot consume them.
2. Dapp usability, existing-wallet compatibility, and partner onboarding; later,
   integration work that produces maintainable code and an independent operator.
3. Capped initial-use credits that remove proving/gas friction.
4. Technical content, demos, and application-partner distribution.

Before paying incentives, approve a total ceiling, per-cohort limits, expiry,
eligible costs, abuse controls, and stop conditions. Never pay in proportion to
reported private balances or self-generated volume. Keep initial credits small
and budget-limited; any later anonymous eligibility mechanism needs its own
privacy and anti-abuse review.

Track unit economics explicitly:

```text
Cost per successful operation =
  (total compute + RPC/indexing + relay/network costs + failed/retried work
   + allocated operating/support costs) / successful operations

Subsidy per retained participant =
  cohort acquisition spend / consenting participants retained after credits expire
```

Avoid double-counting costs paid directly by users; record who pays each term.
Test a transparent per-operation service quote once costs are measured. Any
proving/relay revenue is a hypothesis, not a justification for a mandatory
operator or an unannounced protocol toll.

The Sepolia benchmark distinguishes client proving, server wrapping, and network
fees. Its updated results also show that caller account versions materially
affect gas. Do not market a 4.7-second client proof as 4.7-second settlement, or
quote test-STRK measurements as mainnet dollar prices.

## 8. Scorecard and learning loop

North-star outcome: **people and applications repeatedly use private transfers
and supported DeFi/application flows after initial incentives end.**

Initial pilot targets below are decision thresholds, not forecasts or evidence
of statistically established demand. Agree them with design partners before
launch and revise explicitly rather than quietly changing the denominator.

| Metric | Initial target or use | Collection boundary |
| --- | --- | --- |
| Activation | At least 80% of 30–50 invited pilot participants complete the supported receive/spend flow | Voluntary participant reports; disclose cohort size and assistance provided |
| D30 retention | At least 40% of activated, consenting participants complete another useful flow in days 22–35; observe a period without credits | Report opt-in sample and denominator; do not infer unique humans from wallet addresses |
| Technical completion | At least 95% of valid supported pilot requests reach accepted settlement, with failures classified | Aggregate infrastructure data; no private witness or payment-graph logging |
| Recovery | Every scripted release-candidate recovery drill passes | Test accounts and controlled fixtures, not users' seeds |
| Dapp partner adoption | Two partner cohorts demonstrate repeat use before broad acquisition spend | Direct partner feedback and consenting cohort reports |
| Wallet expansion signal | Repeat dapp users request a persistent wallet experience and commit to a separately qualified pilot | Interviews and explicit commitments, not an assumed wallet launch |
| Infrastructure expansion signal | At least two external teams request an integration; qualify one independently operated pilot before broader service marketing | Reproducible code and operation without the founder performing every step |
| Economics | Publish cost and subsidy per completed flow, p50/p95 latency, and capacity | Coarse aggregates and explicit hardware/network scope |
| Application pull | At least one organizer requests a repeat auction trial after the first qualified trial | Direct partner feedback; auction milestones remain separate from payment readiness |

No public balance leaderboards, cross-app identity graphs, or mandatory
third-party analytics. Use minimal, opt-in telemetry and publish its scope and
retention policy. If privacy constraints prevent reliable user-level measurement,
report that limitation and use partner-cohort evidence; do not quietly introduce
linkable identifiers.

Review weekly. Expand only when both repeat demand and reliability are present.
If interest vanishes without rewards, stop increasing subsidies. If demand is
strong but settlement is slow or expensive, fix that bottleneck before buying
more traffic. Stop real-funds onboarding on a security or withdrawal blocker.

## 9. Content, partnerships, and first actions

### Content sequence

1. **Why another privacy pool?** Explain the disclosure-model difference with
   primary sources and a clear release-status box.
2. **Same proving foundation, different privacy model.** Identify reused
   infrastructure, modified components, and what still needs review.
3. **Three kinds of private utility.** Show ordinary notes, return flows, and
   controlled notes without presenting the latter as a compliance mechanism.
4. **A useful application.** Demonstrate a qualified sealed-bid auction and its
   exact threat model; keep it a third-pillar showcase, not the whole identity.
5. **What the pilot taught us.** Publish reproducible successes, limitations,
   costs, recovery results, and the next release criteria.

Cooperate on shared infrastructure while competing on product design. Credit
StarkWare's work and respect upstream licenses. Ask maintainers factual protocol
questions; do not assume hostility, conceal the application's nature, or promise
that self-hosting Pathfinder bypasses sequencer admission. Maintain a neutral
technical dependency log instead of turning rollout issues into accusations.

### Immediate backlog

- [ ] Founder: approve this positioning and select the first two user/DeFi and
  one application design partners.
- [ ] Product/engineering: freeze the initial dapp's supported flows, existing
  wallet connections, private-note key/recovery UX, and proving requirements;
  keep standalone wallet and public infrastructure launches out of that scope.
- [ ] Product/engineering: reconcile the no-viewing-keys direction with current
  docs, recovery design, and implementation; track any architecture change
  separately.
- [ ] Product: draft the sourced comparison and interview script; test whether
  the disclosure objection causes actual switching intent.
- [ ] Engineering/security: publish the component/release evidence matrix and
  review plan, including exact PROOF2 and controlled-note scope.
- [ ] Engineering: verify target-network acceptance of the intended release
  path; do not schedule a public funds launch around an assumed activation date.
- [ ] Developer relations: scope dapp partner onboarding and one auction design
  partnership with deliverables, ownership, and grant caps; collect wallet and
  infrastructure demand for the later expansion decisions.
- [ ] Founder/operations: approve pilot budget, service pricing experiment,
  privacy-respecting measurement plan, and stop conditions.

This document authorizes no spending, token issuance, public publishing,
partnership commitments, or transactions. Those remain separate decisions.

## Bottom line

**Use the absence of mandatory compliance machinery to win attention. Use shared
Starknet infrastructure to establish engineering credibility. Use ordinary notes
and DeFi returns to deliver utility. Use controlled notes to grow a private
application ecosystem. Earn trust in Templar itself through independent review
and reliable operation. Start with a dapp; expand into wallet and infrastructure
products when adoption justifies them.**
