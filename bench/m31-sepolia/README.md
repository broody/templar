# Sepolia run: option-A pool with R0 client proofs wrapped in PROOF2

Tooling for a live Sepolia lifecycle on the M31 pool (`bench/m31-pool`, frontier storage,
single-permutation nodes). Each spend is proved on the client (`client-port` `wallet` example,
R0 V2), then wrapped on the server. The server runs the statement account's `__execute__` in
the pinned virtual OS against real Sepolia state and proves the PIE through the PROOF2 large
path. The pool's relayer (`account-1`) submits `apply_spend` with the proof attached. The
`Proof2Adapter` then checks the facts and binds their single message to the spend.

| Step | Script | Network |
| --- | --- | --- |
| Local rehearsal: wallet proof, circuit-hash pin, bridge acceptance | `rehearse.py BRIDGE_BUILD` | none |
| Private runtime, wallet secrets | `init.py` | none |
| Class hashes and declaration fee estimates | `deploy.py --check` | reads only |
| Declare and deploy token, pool, adapter, statement account; attach adapter; approve | `deploy.py` | **transactions** |
| Deposits, transfer, partial and full withdrawal, two negatives | `flow.py` | **transactions** |
| Public evidence into `results/` | `report.py` | none |

Lifecycle (`flow.py`): deposits alice 600, 400, 100 and bob 200. Then:
- **transfer:** alice (600 + 400) → bob 700, alice 300;
- **partial withdrawal:** bob (700 + 200) → bob 500, plus 400 to `0xb0b`;
- **full withdrawal:** alice (300 + 100) → 400 to `0xa11ce`.

Negatives reuse a valid proof: the transfer replayed (`NULLIFIER_USED`) and the partial
withdrawal redirected in calldata (`BAD_BINDING`). Wallets rebuild the tree from the pool's
`NotePublished` events.

## Transport notes

- **RPC v0.10 throughout.** sncast needs it for proof fields, and the pinned runner needs its
  block headers (`state_diff_commitment`).
- **Proof transactions** are signed by sncast against a local capture server, checked, then
  posted to the gateway. They are never re-signed automatically.
- **Declarations go through the public endpoint.** The local node fails to simulate them, with
  an internal error on Sierra 1.8 classes. The gateway allows up to Sierra 1.9.0 and exempts
  declarations from its 1.21B L2 gas cap.
- **Declaration cost** is 40,960 L2 gas per class felt (Sierra + CASM):

  | Class | L2 gas | Test STRK at 20.7 gwei-fri |
  | --- | ---: | ---: |
  | Pool | 3.47B | ~72 |
  | Statement account | 3.69B | ~76 |
  | Token | 0.23B | ~4.7 |
  | Adapter | 0.15B | ~3.0 |

- **Statement account build.** It is declared from a copy of the `target/bridge-r0w` workspace
  with gas enabled at the root, because sncast builds with the release profile. Its CASM must
  equal the audited `contract`-profile build; `deploy.py` asserts this.
