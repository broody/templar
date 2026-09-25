# P0b signing page (live)

A local page that asks a Ready or Braavos wallet on Sepolia to sign two SNIP-12 test messages twice each,
checks each signature with a read-only `is_valid_signature` call, and saves the results. It sends no
transactions.

```bash
python3 bench/wallet-sig-spike/sign-live/serve.py 8765
```

Open http://localhost:8765/ in the Chrome that has the wallet extension, connect, press
**Sign 4 test messages**, approve the four prompts. Repeat for the other wallet.

- Results: `target/wallet-sig-spike/sign-live/results/<wallet>-<account>-<n>.json`.
- `serve.py` binds 127.0.0.1, serves `index.html` and starknet.js 10.8.0 (copied from
  `sdk/ts/node_modules/starknet/dist/index.global.js` to `target/wallet-sig-spike/sign-live/`), and forwards
  only `starknet_call`, `starknet_getClassHashAt`, `starknet_chainId` and `starknet_blockNumber` to the local
  pathfinder at http://127.0.0.1:9545/rpc/v0_9.
- The spend message is the fixed test message from `../snip12/typed-data.json`. Its message hash for the test
  account `0x0734b2c2` matches that file.
- The derivation message uses purpose `TEMPLAR_SPIKE_P0B` rather than `TEMPLAR_SECRET_V1`, so these
  signatures can never serve as a real Templar secret.
