# Privacy pools, mixers and enforcement: research for counsel

- Date: 2026-09-27
- Status: research input for counsel, **not legal advice**. Searches were run on 2026-09-27.
  **[unverified]** marks items from secondary sources or that could not be confirmed.
- Informs: [ADR-0028](../adr/0028-deposit-admission-and-screening.md) (deposit admission and
  sanctions screening)

## Summary

- **Mechanics do not separate a privacy pool from a mixer.** FinCEN's proposed definition and
  Chainalysis's both cover pooling that breaks on-chain links, and Templar fits both. Its
  classification will turn on its controls, who operates what, how much the owner can change,
  and its messaging.
- **None of the projects whose operators were charged had effective screening.** Tornado Cash
  screened only in its website. Samourai, Bitcoin Fog and Helix had none, and each case carried
  strong evidence of intent.
- **Projects with real screening have not been charged:** Railgun, Privacy Pools (0xbow),
  Nocturne, STRK20, and Wasabi's coordinator blacklist. Wasabi still shut its coordinator out of
  caution.
- **The relayer is Templar's largest open legal question.** Tornado's relayers did the same job,
  and the Samourai case treated coordination without custody as money transmission.
- **The law is unsettled.** Storm's retrial is set for April 2027, FinCEN's mixer rule is
  dormant, US developer-protection bills have not passed, and EU AMLR Article 79 applies from
  July 2027.

## 1. How comparable projects handle compliance

| Project | Compliance mechanism | Enforced where | Operator, custody and fees | Legal or regulatory outcome | Exchange and vendor treatment |
|---|---|---|---|---|---|
| **Tornado Cash** | None in the contracts. From April 2022 the website blocked sanctioned addresses through a Chainalysis oracle, which could be bypassed [7] | Website only | Non-custodial. Relayers staked TORN to be listed and took fees; the founders ran the website [7] | Sanctioned by OFAC in 2022. *Van Loon* (5th Cir., Nov 2024) held that immutable contracts are not "property", and it was delisted on 2025-03-21 [4]. See §2 for the prosecutions | Vendors moved it from "sanctioned" to "mixer", which still triggers high-risk alerts [8]. It was 70% of mixer use in hack laundering in H1 2026 [23] |
| **Privacy Pools (0xbow)** | An association set provider (ASP) vets every deposit (about 1 hour to days). Withdrawals prove the deposit is in the ASP set. "Ragequit" returns funds publicly, to the original depositor only [20] | Contract (ASP root) plus an off-chain ASP | One ASP. 0–0.5% vetting fee, relayer fee capped at 5–10%, self-relay possible. A 2-of-4 multisig can change configuration instantly. The ASP can drop an approved deposit later, so exclusion works retroactively [20] | No enforcement actions found | TRM cites it as compliant application-level privacy [28]. Exchange treatment **[not found]** |
| **Railgun** | Private Proofs of Innocence: lists from Elliptic, Chainalysis and others, and anyone can publish one. New shields wait 1 hour and can only return to their origin during that time [21] | Wallet SDK and broadcasters, not the contracts [21] | Non-custodial. 0.25% shield and unshield fees to the DAO treasury. Upgrades by DAO vote with a 7-day delay [21] | Not sanctioned. The FBI said Lazarus moved over $60M through it in 2023 [22] | Elliptic (2023) flagged it as a Tornado alternative [22]. Global Ledger counts it as a mixer (27.5% of hack cases in H1 2026) [23] |
| **STRK20 (StarkWare, launched 2026-06-09)** | Deposit screening by Elliptic, with a screener signature checked on chain. Each viewing key is encrypted to a master key held by Financial Privacy Inc. in a TEE and released by a 3-of-4 multisig on lawful request [24] | Contract plus operator | The hosted prover sees private inputs [24] | None found | Marketed as compliant. Vendor treatment **[not found]** |
| **Aztec** | Leaves compliance to applications ("the appropriate hook"). Offers viewing keys and ZKPassport [25] | Application | Decentralized L2 (Ignition, Nov 2025) [25] | Aztec Connect closed in 2023 "for commercial reasons" [25] | Chainalysis lists it under private smart contracts [27] |
| **Zcash** | Voluntary viewing keys. TEX addresses let exchanges accept transparent-only funds [26] | Protocol and wallet | No operator | EU AMLR bars exchanges from anonymity-enhancing coins from July 2027 [18] | Binance removed its monitoring tag on 2025-07-09 [26]. Chainalysis labels shielded flows "Protocol privacy", not mixing [27] |
| **Samourai (Whirlpool)** | None [10] | Coordinator | Non-custodial coordinator; about $6.3M in fees forfeited [10][36] | See §2 | Chainalysis calls it a mixer [27] |
| **Wasabi (zkSNACKs)** | The coordinator blacklisted UTXOs from 2022 [29] | Coordinator | Company-run coordinator, now community-run ones | Coordinator shut on 2024-06-01 over legal uncertainty. No charges [29] | Called a mixer [27] |
| **Nocturne** | A TRM screener signed deposits after a delay of several hours. The contract had a global hourly cap (e.g. 100 ETH), a per-deposit maximum and a per-address daily cap. Pending deposits could be withdrawn with `retrieveDeposit` [30] | Contract plus screener | Non-custodial | Protocol closed Jan 2024 and company wound down June 2024 [30] | n/a |
| **Hinkal** | KYC access token, Chainalysis KYT on every transaction, viewing keys (self-described) [31] | Contract plus operator | — | None found | Self-described as compliant **[unverified]** |
| **Tongo, Mist.cash (Starknet)** | Tongo hides amounts only; an auditor key is optional per deployment [32]. Mist.cash's mechanism **[not verified]** [32] | — | — | None | — |

The Ethereum Foundation's Kohaku SDK (May 2026) builds Railgun and Privacy Pools into wallets [33].

## 2. Enforcement cases

| Case | Custody | Screening | Evidence of intent | Outcome |
|---|---|---|---|---|
| **Tornado Cash** (Storm, Semenov; Pertsev in the Netherlands) | Non-custodial contracts | Website only (Chainalysis oracle from April 2022). Direct contract use and relayers were unaffected [7] | Over $1B laundered, including hundreds of millions for Lazarus. The founders kept operating the website and relayer registry and profited through TORN [7][34] | Charged in 2023 with conspiracy to launder money, to operate an unlicensed money-transmitting business, and to violate sanctions [34]. Storm was **convicted on 2025-08-06 on the §1960 count**; the jury hung on laundering and sanctions [5]. His Rule 29 motion is pending and the retrial is set for 2027-04-26 [6]. Pertsev got 64 months in the Netherlands; his appeal is pending [9]. Semenov is at large |
| **Samourai Wallet** (Rodriguez, Hill) | Non-custodial coordinator | None. Never registered with FinCEN; no effective AML or KYC [36] | Promoted Whirlpool on darknet forums as a way to "clean dirty BTC". Rodriguez urged hackers from a social media breach to route stolen funds through it [36][37] | Pleaded guilty to §1960 with knowledge of criminal proceeds. **Sentenced to 5 and 4 years** in November 2025, each with a $250k fine [11][36]. The court treated coordination as transmission [12]. FinCEN reportedly told prosecutors this was not money transmission **[defense-aligned sources]** [12] |
| **Bitcoin Fog** (Sterlingov) | Custodial | None | Over $400M, largely from darknet markets [38] | Convicted; **12.5 years** [38] |
| **Helix** (Harmon) | Custodial | None | Over $300M, built for darknet markets [39] | Pleaded guilty; **3 years**, reduced for cooperating in the Bitcoin Fog case [39] |

**What they have in common:**
- no effective screening;
- strong evidence of knowledge or intent (marketing, chats, known Lazarus use);
- operators who earned fees.

**The relayer parallel.** Part of the government's case against Tornado concerned its relayers,
which paid gas so users could withdraw to unfunded addresses [7][35]. Templar's relayer does the
same job.

## 3. What makes something a mixer

1. **The mechanism doesn't matter.** FinCEN's 2023 proposed rule defines mixing as obfuscating
   "source, destination, or amount … regardless of the type of protocol". It lists pooling and
   user-initiated delays, and excludes only institutions that keep records [2]. The rule has sat
   as a "Long-Term Action" since the Spring 2025 agenda [3]. Chainalysis defines a mixer as
   pooling funds to "break the on-chain link" [27].
2. **Service versus software.** Under FinCEN's 2019 guidance, whoever accepts and transmits value
   to hide its source is a money transmitter; a supplier of anonymizing software is not. Control
   is judged on four factors: who owns the value, where it is stored, whether the owner interacts
   directly, and whether the intermediary has "total independent control" (§§4.2, 4.5.1) [1].
3. **Criminal law reaches beyond custody.** In Samourai, coordination without custody counted as
   transmission [12]. Storm's jury rejected his lack-of-control defense [5].
4. **Knowledge, intent and marketing.** Samourai's marketing and chats were central evidence
   [10]. The DOJ now says it will not target mixers "for the acts of their end users" [14]. It
   will not approve new §1960(b)(1)(C) charges against "truly decentralized" peer-to-peer software
   without third-party custody or control, absent criminal intent [15]. That is a policy, not a
   law.
5. **Mutability and influence.** *Van Loon* protects only immutable contracts; contracts someone
   can change, and entities, remain open to sanctions [4]. FATF treats control of protocol
   parameters, or an ongoing business relationship with users, as signs of an operator (VASP)
   [19].
6. **Operators who earn fees:** Samourai's coordinator fees, and Tornado's relayers and TORN
   [7][10].
7. **The observed share of illicit funds** drives vendor labels. Lazarus flows did this to
   Tornado and Railgun [22][23].
8. **Controls that vendors give credit for.** TRM lists selective disclosure, set-membership
   proofs, view keys, limits on converting out, and velocity or value limits [28]. The concrete
   precedent for moving to a lower-risk category is Zcash: it shipped TEX addresses for
   exchanges, and Binance removed its monitoring tag [26].
9. **Legislation has not arrived.** The Clarity Act, which protects non-custodial developers,
   failed cloture on 2026-09-15 **[from search summaries; the article returned 403]** [16]. The
   bill narrowing §1960 was introduced in February 2026 and has not passed [17]. EU AMLR Article
   79 applies from 2027-07-10 **[secondary sources]** [18].

**What this means:**
- **For protocol developers:** the risk is low for immutable, non-custodial code with no evidence
  of intent, but not zero while Storm's case is open.
- **For operators of relayers, provers and front ends:** this is where exposure concentrates
  (Tornado's relayers and website, Samourai's coordinator).

## 4. Where Templar lands (ADR-0028, as of 2026-09-27)

**Strengths**
- **A gate in the contract** with a refund to the sender always available. That is stronger than
  Railgun's wallet-level enforcement and matches Nocturne and STRK20.
- **A hold on every deposit:** 1 hour under $10k, 3 hours from $10k. This matches Railgun's
  minimum.
- **A global admission rate limit,** like Nocturne's hourly cap.
- **Fair-value adapters,** which count as the "conversion constraints" TRM credits.
- **Proving on the device.** The server never holds keys or sees private inputs.
- **Voluntary viewing keys** for selective disclosure. There is no auditor key.
- **Sanctions checks in every operated service,** not just the website as with Tornado.
- **Messaging reconciled.** On 2026-09-27 the GTM strategy, README and guide dropped the
  "compliance removed" positioning.

**Weak spots**
- **The relayer.** One operator account submits every spend and is paid through blind tickets.
  It is the closest analogue to Tornado's relayers and Samourai's coordinator (§5).
- **The vault.** The seed stays client-side, but a compromised deploy could steal it. Whether
  serving that code amounts to control is a question for counsel.
- **The owner's timelocked powers** (verifiers, allowlists, routes). They put the pool outside
  *Van Loon* and the DOJ's "truly decentralized" line, and FATF counts parameter control as a
  sign of an operator. They are also the only way to respond to incidents.
- **The list provider's veto** over deposits. The refund bounds it.
- **No retroactive exclusion,** because notes merge. Privacy Pools and Railgun can act on late
  flags.
- **The $10k threshold** matches the US currency transaction report threshold, which could look
  like an invitation to structure deposits (a question for counsel).
- **Screening described before it exists.** The public docs describe deposit screening as a
  feature. Mainnet must not launch before ADR-0028 is built. A gap between claimed and actual
  controls resembles the "cosmetic screening" allegation against Tornado.

## 5. The relayer

It exists for **unlinkable submission**. If a user submitted a spend themselves, the account
paying the gas would publicly link them to it. A standard paymaster does not help, because the
paying account is still the transaction's account (pool-v3-spec §7.2).

| Option | Assessment |
|---|---|
| Pay the relayer from spend outputs | Rejected. It still needs a relayer. It mirrors Tornado's fee taken from each withdrawal. It makes the operator's revenue mixer-exposed. It needs a new R0 output or a public fee that reveals a hidden asset |
| The user's own fee account | Removes the operator, but publicly links all of that user's spends to each other. One withdrawal to a KYC'd address then identifies the whole cluster. Rotating fee accounts doesn't break the chain without a relayer. It remains the linkable fallback (the vault's submitter account) |
| The pool pays its own gas as an account | The only option that removes the relayer without linkability, but unproven. One sequential nonce is shared by all users; Starknet has no 2D nonces, and SNIP-9 random nonces still need a submitter. It also has to respect account validation limits, pay a fee without revealing a hidden asset, and never pay for failed spends. The prover server, list provider, vault and owner powers would remain in any case |
| **Keep the relayer (decided 2026-09-27)** | With the mitigations below |

**Mitigations:**
1. Get counsel's opinion on the relayer: free versus paid, and which jurisdiction.
2. Separate a developer entity from an operating entity, which runs its own sanctions and AML
   program and registers or is licensed if counsel requires it.
3. Make relaying a commodity. Tickets can already be verified by any relayer. Publish the relayer
   software, support independent relayers, and have no registry or staking.
4. Apply sanctions checks consistently, and record refusal counts without private data.
5. Keep an incident procedure. When notified of a hack or flagged funds: pause admissions,
   refuse proving and relaying to flagged recipients, and respond to law enforcement.

## 6. Screening vendors

- **Elliptic** (used upstream) publishes no prices. Its AWS Marketplace listing shows 12-month
  contracts at $50,000 or $100,000 a year [40].
- **Chainalysis:** Vendr's buyer data report a median of about $18.5k a year, with negotiated
  contracts ranging from about $26k to $297k [41].
- **TRM** lists Starknet wallet screening [42].
- **Free, sanctions-only:** the Chainalysis API (its on-chain oracle is EVM-only), OFAC's SDN list
  and OpenSanctions [43].

**Decision (2026-09-27): no paid vendor for now.**
- Screen against OFAC's list, including the Ethereum senders of StarkGate deposits.
- Geoblock IP addresses in operated services.
- Keep a manual blocklist of exploit and incident addresses. Sanctions lists rarely contain hack
  addresses, so without it the hold would catch nothing.
- Revisit a risk-scoring vendor when volume justifies it.

## 7. Open questions for counsel

1. Is the paid relayer an "anonymizing services provider" under FinCEN 2019, state law or the
   Samourai coordination theory? Does free versus paid relaying change that?
2. Does serving the web vault count as control or custody (the four-factor test, MiCA, state
   law)?
3. Does the list provider's admission role add control exposure? Should it be a separate or
   licensed entity?
4. Do the owner's timelocked powers make the owner a VASP, or an entity that can be sanctioned?
   Would freezing the core help?
5. Is a $10k tier defensible given structuring concerns?
6. If a sanctioned deposit is found after admission and cannot be frozen, what must be reported or
   blocked in the operated services?
7. Would EU exchanges treat Templar withdrawals as "anonymisation" under AMLR Article 79? Is EU
   geoblocking needed?
8. Are policy-note controllers, such as auction organizers, escrow agents or custodians?
9. How should launch timing relate to the pending Storm Rule 29 ruling and the April 2027 retrial?
10. In which jurisdiction should the operating entity be based?

## Sources

1. https://www.fincen.gov/system/files/2019-05/FinCEN%20Guidance%20CVC%20FINAL%20508.pdf
2. https://www.davispolk.com/insights/client-update/fincen-proposes-rule-targeting-international-convertible-virtual-currency
3. https://www.reginfo.gov/public/do/eAgendaViewRule?pubId=202504&RIN=1506-AB64
4. https://www.arnoldporter.com/en/perspectives/advisories/2024/12/fifth-circuit-limits-ofacs-sanctioning-authority ; https://www.defieducationfund.org/deep-dive-on-delisting-of-tornado-cash-potential-implications/
5. https://www.coindesk.com/policy/2025/08/06/roman-storm-guilty-of-unlicensed-money-transmitting-conspiracy-in-partial-verdict ; https://www.mayerbrown.com/en/insights/publications/2025/08/the-tornado-cash-trials-mixed-verdict-implications-for-developer-liability
6. https://www.theblock.co/news/regulation/2026-08-26-tornado-cash-roman-storm-retrial-april-2027-412761
7. https://www.skadden.com/insights/publications/2023/09/court-victory-for-treasury-and-indictment ; https://blockworks.com/news/tornado-cash-spins-up-sanctions-compliant-web-interface
8. https://www.k2integrity.com/en/knowledge/policy-alerts/the-tornado-cash-delisting-and-sanctions-compliance-implications-for-crypto/
9. https://www.theblock.co/post/339401/tornado-cash-developer-alexey-pertsev-gets-nod-for-conditional-release-from-prison-to-work-on-appeal
10. https://www.irs.gov/zh-hant/compliance/criminal-investigation/founders-of-samourai-wallet-cryptocurrency-mixing-service-plead-guilty
11. https://therecord.media/samourai-wallet-crypto-mixer-founders-sentenced
12. https://cointelegraph.com/news/samourai-sentences-cement-doj-money-transmitter-theory ; https://www.btcpolicy.org/articles/fincen-said-that-samourai-wallet-case-violated-treasurys-aml-guidance--doj-prosecuted-devs-anyway
13. https://en.wikipedia.org/wiki/Keonne_Rodriguez
14. https://www.justice.gov/dag/media/1395781
15. https://www.justice.gov/opa/speech/acting-assistant-attorney-general-matthew-r-galeotti-delivers-remarks-american
16. https://www.cnbc.com/2026/09/15/senate-cloture-vote-on-clarity-act-fails-dealing-regulatory-setback-to-crypto-industry.html ; https://www.troutmanfinancialservices.com/2026/09/senate-blocks-crypto-clarity-act-leaving-regulatory-framework-in-limbo/
17. https://www.defieducationfund.org/promotinginnovationinblockchaindevelopmentact/
18. https://techlawpolicy.com/2025/06/eu-vs-crypto-anonymity-what-you-need-to-know/ (confirm against the text of Reg. (EU) 2024/1624)
19. https://www.fatf-gafi.org/en/publications/Fatfrecommendations/Guidance-rba-virtual-assets-2021.html ; https://www.fatf-gafi.org/en/publications/Fatfrecommendations/targeted-update-virtual-assets-vasps-2025.html
20. https://l2beat.com/privacy/projects/privacy-pools ; https://0xbow.io/blog/getting-started-with-privacy-pools ; https://deepwiki.com/0xbow-io/privacy-pools-core/2.1-transaction-flows
21. https://docs.railgun.org/wiki/assurance/private-proofs-of-innocence ; https://l2beat.com/privacy/projects/railgun
22. https://www.fbi.gov/news/press-releases/fbi-confirms-lazarus-group-cyber-actors-responsible-for-harmonys-horizon-bridge-currency-theft ; https://www.elliptic.co/insights/crypto-mixers-and-privacy-protocols-the-sanctions-compliance-implications/
23. https://blog.globalledger.io/research-investigations/crypto-hacks-h1-2026
24. https://www.starknet.io/blog/compliance-layer-onchain-privacy-strk20/ ; https://www.starknet.io/blog/privacy-live-on-starknet/ ; https://github.com/starkware-libs/starknet-privacy/blob/b40bf109c8e5b97d9d6e8ec6db48b16b9d10a106/proof-interceptor/README.md
25. https://aztec.network/policy-principles ; https://www.coindesk.com/markets/2025/11/20/privacy-focused-aztec-network-s-ignition-chain-lights-up-on-ethereum ; https://www.coindesk.com/consensus-magazine/2023/03/24/founders-deny-regulatory-pressure-forced-aztec-connect-zkmoney-shutdown
26. https://www.binance.com/en/support/announcement/detail/c2536e8b6ed44c7ba4f62c249dbde9bb ; https://forum.zcashcommunity.com/t/binance-to-remove-monitoring-tag-for-zec/51631
27. https://www.chainalysis.com/blog/privacy-blockchain-compliance/ ; https://www.chainalysis.com/glossary/crypto-mixer/
28. https://www.trmlabs.com/reports-and-whitepapers/on-chain-privacy-and-financial-compliance
29. https://blog.wasabiwallet.io/zksnacks-is-discontinuing-its-coinjoin-coordination-service-1st-of-june/ ; https://blog.wasabiwallet.io/zksnacks-blacklisting-update/
30. https://nocturne-xyz.gitbook.io/nocturne/protocol-details/contracts/deposit-manager ; https://nocturne-xyz.gitbook.io/nocturne/introduction/compliance ; https://cointelegraph.com/news/vitalik-buterin-nocturne-labs-shuts-down
31. https://blog.hinkal.pro/hinkal-on-chain-privacy-with-compliance-guarantees/
32. https://github.com/fatlabsxyz/tongo ; https://docs.mist.cash/
33. https://thedefiant.io/news/blockchains/ethereum-foundation-kohaku-sdk-privacy-wallet-integration-bb4t52
34. https://www.justice.gov/usao-sdny/pr/tornado-cash-founders-charged-money-laundering-and-sanctions-violations
35. https://www.defieducationfund.org/us-v-storm-background-timeline/
36. https://www.irs.gov/compliance/criminal-investigation/founders-of-samourai-wallet-cryptocurrency-mixing-service-sentenced-to-five-and-four-years-in-prison
37. https://www.moneylaunderingnews.com/2025/12/the-prosecution-of-samourai-wallet-developers-expanding-the-reach-of-crypto-enforcement/
38. https://www.infosecurity-magazine.com/news/man-12-years-running-crypto-mixer/
39. https://therecord.media/ohio-man-helix-crypto-sentenced
40. https://aws.amazon.com/marketplace/pp/prodview-6odrg7umycz5u
41. https://www.vendr.com/marketplace/chainalysis
42. https://www.trmlabs.com/blockchain-coverage/starknet
43. https://go.chainalysis.com/crypto-sanctions-screening.html ; https://chainscreen.io/tools/sanctions-screening-tools-comparison
