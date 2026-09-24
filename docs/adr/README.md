# Architecture Decision Records

ADRs record the architectural decisions behind Templar. The current architecture
is specified in [push payments](../push-payment-spec.md), with local S-two proving
selected by ADR-0018, push receiving selected by ADR-0021, and atomic
[open notes](../open-note-spec.md) (formerly return notes) added by ADR-0023.
[Compact client proofs with server wrapping](0024-compact-client-proofs-and-server-wrapping.md)
are the accepted target architecture; ADR-0018's local pipeline remains the integration
baseline until ADR-0024's hiding, review and format gates close.
[`PLAN.md`](../../PLAN.md) retains the development roadmap and earlier analysis.

## Process

1. Copy [`template.md`](template.md) to `NNNN-short-title.md` (zero-padded, sequential).
2. Write it while the decision is being made; link evidence (benchmarks, audits,
   upstream code references).
3. Status: `Proposed` → `Accepted` / `Rejected` / `Superseded by ADR-XXXX`.
4. ADRs are immutable once Accepted — to change a decision, write a new ADR that
   supersedes the old one, and update the old one's status only.

## Index

| ADR | Title | Status |
|-----|-------|--------|
| [0001](0001-two-phase-proof-facts-architecture.md) | Keep the two-phase proof-facts architecture | Superseded by [0010](0010-single-phase-architecture.md) |
| [0002](0002-remove-mandatory-auditor.md) | No mandatory auditor; voluntary viewing keys only | Accepted |
| [0003](0003-remove-onchain-screening.md) | No on-chain screening; opt-in ZK association sets | Accepted |
| [0004](0004-commitment-tree-state-model.md) | Sparse commitment tree + nullifier ring state model | Accepted |
| [0005](0005-proving-architecture.md) | User-generated inner proofs; blind operator; client-side Stwo as end state | Superseded by [0010](0010-single-phase-architecture.md) |
| [0006](0006-controlled-notes.md) | Adopt controlled notes with out-of-prover controller authorization | Accepted (format superseded by 0009) |
| [0007](0007-public-event-minimization.md) | Public event minimization rules | Accepted; push publication metadata amended by [0021](0021-push-only-payments.md); return-note extension in [0023](0023-return-notes-and-adapter-compatibility.md) |
| [0008](0008-inner-proof-system.md) | Inner proof system selection | Superseded by [0018](0018-stwo-private-proving.md) |
| [0009](0009-note-type-unification.md) | Note-type unification; open notes cut | Accepted; ownership derivations amended by [0021](0021-push-only-payments.md); open-note exclusion superseded by [0023](0023-return-notes-and-adapter-compatibility.md) |
| [0010](0010-single-phase-architecture.md) | Single-phase on-chain verification; operator removed; private invokes cut | Accepted; proof path amended by [0018](0018-stwo-private-proving.md); external-invoke exclusion superseded by [0023](0023-return-notes-and-adapter-compatibility.md) |
| [0011](0011-two-part-leaf-deposit.md) | Two-part commitment leaf; standalone proofless deposit | Accepted |
| [0012](0012-recipient-authored-notes.md) | Recipient-authored notes (invoice flow); channel machinery cut | Superseded by [0021](0021-push-only-payments.md) |
| [0013](0013-tree-depth.md) | Tree depth 32 | Accepted |
| [0014](0014-m2-statement-shape.md) | M2 statement shape: padded binding + counts, scalar publics, single-token 4/4/2 | Accepted; proof mechanics amended by [0018](0018-stwo-private-proving.md), push binding by [0021](0021-push-only-payments.md); return-note extension in [0023](0023-return-notes-and-adapter-compatibility.md) |
| [0015](0015-gnark-multicommit-garaga.md) | gnark multicommit ↔ Garaga incompatibility; custom limb layer is the production path | Superseded by [0018](0018-stwo-private-proving.md) |
| [0016](0016-noir-honk-feasibility.md) | Noir/Honk Garaga compatibility benchmark; production scaling remains open | Superseded by [0018](0018-stwo-private-proving.md) |
| [0017](0017-desktop-native-hash-pathfinding.md) | Desktop feasibility favors native BN254 hashing | Superseded by [0018](0018-stwo-private-proving.md) |
| [0018](0018-stwo-private-proving.md) | Client-side S-two ZK proving with native Starknet proof facts | **Accepted** — native PROOF1 proving selected; note semantics amended by [0021](0021-push-only-payments.md); integration and desktop qualification pending; client/server proving split amended by [0024](0024-compact-client-proofs-and-server-wrapping.md) |
| [0019](0019-offline-push-receiving.md) | Offline push receiving; separate delivery and spending keys | Superseded by [0021](0021-push-only-payments.md); prototype evidence preserved |
| [0020](0020-full-viewing-and-recovery.md) | Full viewing authority and recoverable push notes | Superseded by [0021](0021-push-only-payments.md); [Sepolia evidence](../../bench/push-e2e/README.md) preserved |
| [0021](0021-push-only-payments.md) | Push-only payments with reusable receiving addresses | **Accepted** — product and architecture; production integration and format review pending; return-note extension in [0023](0023-return-notes-and-adapter-compatibility.md) |
| [0022](0022-controlled-push-payments.md) | Controlled push payments with exact transition approval | Accepted experimental architecture; real signatures and native Sepolia lifecycle validated; production integration pending |
| [0023](0023-return-notes-and-adapter-compatibility.md) | Open notes (formerly return notes) with upstream-compatible external settlement | Accepted architecture; experimental reference and production qualification tracked separately; amended 2026-09-24 for the compact path and shadow accounts |
| [0024](0024-compact-client-proofs-and-server-wrapping.md) | Compact private client proofs with server-side PROOF2 wrapping | Accepted architecture — R0 V2 verified end to end and live on Sepolia up to the gateway (PROOF2 not yet enabled); hiding, review and formats gate production |
| [0025](0025-policy-notes.md) | Policy notes: bounded, capability-spent, controller-gated (supersedes 0022 once accepted) | Proposed — design reviewed (GO); implementation pending |
