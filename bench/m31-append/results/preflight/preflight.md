# M31-append preflight inventory

2026-09-21. Read-only operational inventory for a local synthetic
M31-append → PROOF1 → local-contract round trip. Nothing was built, deployed,
or executed beyond version/hash/integrity checks. Frozen archives untouched.

## Toolchain (exact paths)

- Scarb 2.18.0 (cairo 2.18.0, sierra 1.8.0): `/home/broody/.asdf/installs/scarb/2.18.0/bin/scarb` (default shim matches).
- snforge / sncast 0.63.0: `/home/broody/.asdf/installs/starknet-foundry/0.63.0/bin/` — **`~/.local/bin` and the default sncast shim are 0.20.0; explicit paths required.**
- starknet-devnet 0.6.0: `/home/broody/.asdf/installs/starknet-devnet/0.6.0/bin/starknet-devnet` (shim matches).

## Native binaries (hash-verified in place)

- Prover `starknet_transaction_prover` sha256 `31fb582d…`, verifier `local-verifier` sha256 `492e2ea2…`, both under `/tmp/templar-stwo-privacy-dtgn6e8l/sepolia-v1-test/` (sequencer `e6b6fd2e…`, proving_utils `3035dd00…`, per `bench/push-e2e` manifest). **Risk: /tmp is ephemeral; archive or rebuild before reboot.**
- Mutable M31 target build sha256 `f5a9d8c4…`; the preserved
  `target/m31-tree/frozen-v2/templar-m31-tree` hashes to `afd206ce…` and is the
  frozen v2 identity. New work uses a separate build directory.

## Prover RPC interface (sources: `bench/push-e2e/proving.py`, `bench/direct-air/bridge-findings.md`)

Local HTTP JSON-RPC service (`PROVER_IP`/`PROVER_PORT`, `RPC_URL`, `CHAIN_ID`).
`starknet_proveTransaction{block_id, INVOKE v3 to statement account,
calldata=[len(private),*private]}` → base64 proof + facts; `facts[0]=='PROOF1'`;
the single L2→L1 message `[statement_class, *public]` is digest-bound to
`facts[8]`. `local-verifier <proof_dir>` verifies offline. **Hard boundary: no
state-override parameter, and the virtual OS forbids declaration/deployment
inside the proven transaction** — the statement account must already exist in
authenticated state at the proven block. Sepolia public RPC previously
sufficed, including storage-proof requests. The pinned service explicitly calls
`starknet_getStorageProof`; ordinary state reads alone are insufficient.

## Local devnet feasibility

No existing devnet bootstrap harness in `bench/*`; the loopback capture proxy
in `bench/push-e2e/common.py` only logs negative sncast submissions — it is not
a prover state replay. No saved RPC/state fixture can support isolated
declaration/deployment; that assumption would be false. Synthetic statement
account artifacts exist in `bench/direct-air/artifacts/`.

## Processes/ports

No devnet/prover processes running. Prover port 31458 free. In use:
`127.0.0.1:9222` (existing Chrome debug), `100.81.77.19:60675`. Nothing
terminated or controlled.

## Archive integrity

`results/preflight/integrity-initial.json`: **PASS** — 8 manifests including
`bench/m31-tree/SHA256SUMS` (`a51ed0ae…`), 1,741 files checked, no failures
(script: `target/kimi-m31-append/preflight-integrity.py`).

## Proposed local run (NOT executed)

1. Astra freezes the M31-append statement account (direct-air pattern).
2. Start devnet 0.6.0 on a fresh port with state dump.
3. Declare/deploy via explicit sncast 0.63.0 (devnet public predeployed accounts).
4. Run pinned prover with `RPC_URL=http://127.0.0.1:<devnet>`, port 31458, under
   systemd caps (proving.py pattern).
5. `starknet_proveTransaction` at the deployment block; check PROOF1 facts and
   message binding; run local-verifier.
6. Local `starknet_call` append/root checks.

## Open feasibility questions

- Does the service accept devnet 0.6.0 as `RPC_URL` (block `starknet_version`
  0.14.4 was asserted by prior runs)? CHAIN_ID handling on devnet?
- Virtual-OS RPC surface requires authenticated storage proofs and complete block headers; see the subsequent local capability probes.
- Block-id semantics and mining cadence between deploy and prove on devnet.
- Devnet state-dump/restart workflow so the proven block stays available.
- /tmp-hosted binaries need archival.

Prover proof-code and architecture decisions remain with Astra; this inventory
makes no privacy or soundness claim.

## Subsequent capability probe

The installed devnet returns error42 for storage proofs. Katana supplies
storage proofs but its RPC0.9 headers omit the commitment/count fields required
by the pinned prover. Raw requests/responses are in `../local-capability/`.
These capability probes do not claim PROOF1 compatibility. Kimi exhausted its
five-hour quota after the inventory; Astra performed and reviewed these checks.
