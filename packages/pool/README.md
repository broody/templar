# TemplarPool v2 contract

Cairo implementation of [`docs/pool-v2-spec.md`](../../docs/pool-v2-spec.md)
(frozen 2026-09-19). Milestone M1 of [PLAN.md](../../PLAN.md).

## Modules

| Module | Contents | Status |
|---|---|---|
| [`src/hashes.cairo`](src/hashes.cairo) | The §3.1 derivation family (`note_secret`, `inner`, `note_id`, `commitment`, `nullifier`) with frozen V3 domain-separation tags | done |
| `src/tree.cairo` | Sparse commitment tree + root history ring (§4) — component + pure path verification | done |
| `src/spend.cairo` | Spend types, verifier seams, frozen statement-binding flattening (§5–§7) | done |
| `src/pool.cairo` | `apply_spend` gating (§7.4) + 1:1 action zip + atomic application; proofless `deposit` (ADR-0011); events (§8); governance | done |

## Contract/circuit agreement

`src/tests/test_hashes.cairo` contains **golden reference vectors** for the frozen
derivations (inputs documented in the file header). The M2 inner circuit must
reproduce these byte-for-byte — this is the single source of truth for the
felt252-Poseidon derivations the circuit re-implements over BN254.

## Build and test

```bash
PATH="/usr/bin:$PATH" snforge test
```

`PATH="/usr/bin:$PATH"` works around a `~/bin/cc` shim shadowing the system
compiler, which breaks scarb's proc-macro plugin builds (snforge_std 0.63).

Tests: 4 hash tests (incl. golden vectors) + 7 tree tests + 35 pool tests (57
total incl. the gas-snapshot benches) — happy path (proofless deposit →
spend/withdraw; controlled deposit → controlled spend), deposit guards (zero
amount/token/inner, caller-only allowance), and the M1 adversarial battery:
replay, forged/missing/extra nullifier writes, stale root (256-evict), wrong
pool/chain/version, tampered binding, rejected proof (creator-spend class),
commitment mismatch, controller required/mismatch/deadline (expired AND
mismatched)/sig failures, double apply, zero-leaf inputs, fee collection, and
rejection of direct tree insertion through the production ABI.

Gas snapshot (`src/tests/bench_pool.cairo`, depth 32 per ADR-0013, 4/4/2 max
bundle per ADR-0014): apply overhead ~0.9 M l2, ~0.6 M/nullifier,
~6.7 M/leaf steady-state, `deposit()` ~21.3 M, max bundle ~44.6 M — full table
in `docs/m1-invariant-review.md` §E. Invariant review:
`docs/m1-invariant-review.md`.

Governance (M1 fix, review §B): `owner` (deploy-time) gates `set_fee`,
`set_verifier`, `set_sig_verifier`; `transfer_ownership`. Interim only —
upstream Roles/AccessControl lands in M3 (mainnet readiness); production
deployment blocked until then.

M1 seams (single-phase per ADR-0010, signature-stable): `IVerifier` (mock → real
on-chain Groth16 verifier in M2) and `ISigVerifier` (mock → on-chain cairo-ec in
M3).
