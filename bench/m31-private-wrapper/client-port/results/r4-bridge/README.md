# R0 V4 client proofs and bridge

Real blinded arithmetic-only client proofs of R0 V4 (`src/payment4.rs`, `docs/hidden-asset-spec.md`
§4) for every shape, compress tree nodes, and the V4 bridge (`cairo-r4`) executed on them
standalone (`validate_bridge_r4.py`). 2026-09-24, 36-core host, `-C target-cpu=native`.

- **Proofs** (`proofs.json`): trace 2^18 for every shape, 0.23–0.32 s proving, 29–31k proof
  felts, about 0.6 GiB peak; one circuit hash for all shapes. V3 on the same host: trace 2^18,
  0.28 s, 29,858 felts. Each proof verifies natively and passes the five tamper negatives.
- **Bridge** (`validation.json`, 57/57): all eight honest shapes accepted with the exact binding
  (recomputed independently), 1.99–2.07M Cairo steps; 44 altered statements and encodings
  rejected; and five real proofs of statements the circuit admits but the bridge must reject,
  each rejected by its own check: voluntary asset reveal (`exit rule`), zero delivery digest
  (`delivery`), recipient without amount (`withdrawal`), identity without intent
  (`identity intent`), duplicate nullifier (`duplicate nullifier`).
- **Build** (`bridge-build-record.json`): account CASM within the 81,920-felt sequencer limit.

Reproduce: `cargo build --release --features tamper --example prove_payment_r4`, prove each
`--shape` and `--forge` kind into one directory, `build_bridge_arith.py` on a proof's
`trusted-config.json`, then `validate_bridge_r4.py WORK PROOFS OUT`. Runs belong under
`~/.local/share/templar/runs`.
