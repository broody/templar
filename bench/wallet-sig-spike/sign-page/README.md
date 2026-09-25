# P0b spike: wallet signing page (S4)

Throwaway page for the account-bound notes feasibility spike. You open it in your own Chrome with
Ready (Argent X) or Braavos. It connects through get-starknet and asks the wallet to sign two SNIP-12
revision-1 typed-data messages, twice each. It shows the four signatures, whether each pair is
identical, and the message hashes computed locally with starknet.js. An optional read-only check asks
a node for the account class hash and calls the account's `is_valid_signature` on those hashes.
**Copy JSON** exports everything.

The page sends no transactions. It uses only three wallet requests: `wallet_requestAccounts`,
`wallet_requestChainId` and `wallet_signTypedData`. get-starknet also calls `wallet_getPermissions`
when it connects.

## Run it (manual steps)

1. Start the server from this directory. It binds 127.0.0.1 only:

   ```bash
   cd /home/broody/development/templar/bench/wallet-sig-spike/sign-page
   python3 serve.py                 # http://localhost:8000/ ; --port N to change
   ```

   `serve.py` serves the page and runs a read-only JSON-RPC proxy. `/rpc/sepolia` goes to
   `http://127.0.0.1:9545/rpc/v0_9` and `/rpc/mainnet` goes to `:9546`. The proxy forwards only
   `starknet_chainId`, `starknet_specVersion`, `starknet_blockNumber`, `starknet_getClassHashAt` and
   `starknet_call`. It refuses everything else, including batches and requests from other origins.
   The proxy is needed because pathfinder sends no CORS headers, so the browser cannot call it
   directly.

   `python3 -m http.server 8000 --bind 127.0.0.1` also works. Only step 6 is then unavailable, unless
   you enter an RPC URL in the page that accepts browser requests.

2. Open **http://localhost:8000/** in the Chrome that has the wallet extension. Set the wallet to
   **Starknet Sepolia**. Use a **deployed** account if you want step 6: an undeployed account can
   still sign, but there is no contract to call.
3. Wait for the pill next to the button to read **libraries ready**. The footer should read
   `starknet.js self-check against the S1 test vectors: 11/11 match.` If it shows anything else,
   stop. The page fetches starknet.js 10.8.0 and get-starknet 4.0.7 from jsDelivr and refuses to run
   them if their bytes differ from the pinned SHA-384.
4. Press **Connect wallet**, pick Ready or Braavos in the get-starknet dialog, and approve the
   connection. The page then shows the wallet name and version, the account, and the chain id.
5. Press **Sign 4 test messages** and approve four prompts, in this order: derivation, spend,
   derivation, spend. Each prompt should be a message signature with domain `Templar`, version 1, on
   `SN_SEPOLIA`, and should contain:
   - **TemplarKeyDerivation**: purpose `TEMPLAR_SIGTEST_V0`, chain `SN_SEPOLIA`, and your own account
     address.
   - **TemplarSpend**: pool `0x2da001111…137b9`, binding_commitment `0x4ab86daf…420afb`, token_out 0,
     withdrawal_recipient 0, withdrawal_amount 0, intent 0, valid_until 16000000.

   Reject anything else. If you reject a prompt, the run stops there. Pressing the button again
   continues from that prompt and does not ask again for signatures you already gave.
6. Optional: press **Run read-only check**. It shows the class hash and one result per signature:
   - `VALID`: the wallet signed exactly the hash that the S1 Cairo code computes.
   - `VALID only with ... domain`: the wallet encodes the domain differently. This is a finding to
     report.
   - `not valid`: the account rejected the signature. The result also shows what the account returned.
   - `account class has no is_valid_signature`.
7. Press **Copy JSON** and paste the result back. If you want a file, save it as
   `target/wallet-sig-spike/sign-page/results/<wallet>-<n>.json`. The JSON holds:
   - the wallet name, id and version
   - the account, as normalised and as the wallet returned it
   - the chain id
   - the class hash, with its source (`starknet_getClassHashAt(latest)`)
   - both typed-data objects
   - the local message hashes, including the diagnostic ASCII-domain variants
   - the four signatures, normalised and raw
   - `identical` for each pair
   - the read-only check results
8. Reload the page and repeat with the other wallet. The dialog asks every time.

### What the results answer

- **Determinism**: `messages.derivation.identical` and `messages.spend.identical`. Deriving the
  Templar secret from the wallet's signature over `TemplarKeyDerivation` only works if the wallet
  signs deterministically, meaning an RFC 6979 nonce. The starknet.js signer is deterministic (tested
  below). Whether Ready and Braavos are deterministic is what this page measures.
- **Encoding**: `read_only_checks.signatures[*].matched_variant == "standard"` means the wallet's
  SNIP-12 hash equals starknet.js `getMessageHash`. S1 showed that this is also the Cairo hash.
- **What the bridge must run**: `class_hash` is the account class whose `is_valid_signature` the
  virtual OS would execute. `signatures[*]` gives the exact calldata shape. Ready and Braavos may add
  more than `[r, s]`; the page records whatever the wallet returns.
- Inferred, not tested: an account with a guardian (Argent/Ready 2FA) may need the guardian's
  cosignature for `is_valid_signature`. If so, the owner-only signature from `signTypedData` would
  show as `not valid`.

### Deliberate deviation from S1

The page signs `TemplarKeyDerivation` with purpose **`TEMPLAR_SIGTEST_V0`**, not the S1 test value
`TEMPLAR_SECRET_V1`. The exported JSON contains these signatures. If a later production derivation
used the S1 message, the signature pasted here would be that account's Templar secret. The type,
encoding and domain are unchanged, so the S1 Cairo `derivation_message_hash` reproduces the hash when
given this purpose. `katSelfCheck` still checks the S1 message, with `TEMPLAR_SECRET_V1` and account
`0x0734b2c2`, but only computes its hash and never signs it.

Both messages are hashed with the **connected** account, because `getMessageHash(td, account)` binds
the signer. The derivation message's `account` member is also the connected account, as S1's
`derivation_message_hash` requires. The spend hash therefore differs from the S1 test hash for
`0x0734b2c2` (`0x2bf922f4…97be2c`). The typed-data objects for the fixed test inputs are
byte-identical to `../snip12/typed-data.json`, as tested below.

## Files

| File | Role |
|---|---|
| `index.html` | The page: DOM, get-starknet connect, library loading (fetch with `integrity`, then evaluate) |
| `sign-logic.mjs` | All logic, with no DOM and no imports: typed data, hashes, chain id handling, the sign plan, read-only checks, the report. `sn` (starknet.js) and the wallet are passed in, so node runs the same code |
| `serve.py` | Static server plus the read-only RPC proxy |
| `test/test_logic.mjs` | Headless tests of `sign-logic.mjs` against mock wallets, plus `--live` read-only RPC |
| `test/test_serve.py` | Proxy tests: a recording fake node proves that refused methods never reach it, plus `--live` |
| `test/mock-wallet.mjs` | Test-only mock get-starknet wallet on a fresh random Stark key, in memory, never printed. `index.html` never loads it |

Libraries, loaded only from `cdn.jsdelivr.net/npm/`:

- `starknet@10.8.0/dist/index.global.js`: `sha384-DbZWEnxQq8varDEksnUMqbJiyXIfymtrLPEQBbN5K4eZR5elHpN2tinGSfS2+9pD`
- `@starknet-io/get-starknet@4.0.7/dist/ui.js`: `sha384-dapAnd74G6L9ETZfVGV/9duLXURycOIdirFA4UL5lbvChKom8DLNrwkmMp1AgL9u`. This is a self-contained ES module with no imports, so it loads from a `blob:` URL after the check.

Each hash is the SHA-384 of that file inside the npm tarball in the local npm cache. The cache is
content-addressed by the lockfile sha512, and the test re-checks it. get-starknet is pinned to
4.0.7, not the newer 4.0.8, because 4.0.7's tarball is available locally to verify the hash. The
browser test also confirmed that jsDelivr serves exactly these bytes and that Chrome rejects a wrong
hash.

The starknet.js IIFE declares a global named `starknet`. Wallets inject the same name, so the page
evaluates the IIFE inside a function scope and no global is created; the browser test confirmed this.
`connect()` passes `exclude: ['metamask']`, because get-starknet's MetaMask entry would load code
from `snaps.consensys.io`.

## Testing (done headlessly; no wallet, no transactions, no existing keys)

```bash
cd /home/broody/development/templar
node bench/wallet-sig-spike/sign-page/test/test_logic.mjs --live   # 15 passed, 0 failed
python3 bench/wallet-sig-spike/sign-page/test/test_serve.py --live  # 16 passed, 0 failed
```

`test_logic.mjs` checks:
- The pinned SRI equals the npm tarball files, and the local starknet copy is identical.
- The IIFE build, evaluated exactly as the page does it, passes the KAT.
- `katSelfCheck` gives 11/11 on both the CJS and the IIFE builds. It covers 3 type hashes,
  binding_commitment, domain hash, 2 struct hashes, 2 message hashes, the ASCII-version domain hash,
  and a hand-computed rev-1 hash that must equal `getMessageHash`.
- Typed data is identical to S1's `typed-data.json`.
- Chain id: wallet hex maps to the domain value, a numeric-looking short string stays hex, and the
  hash is the same either way.
- Signature normalisation.
- Mock wallet, deterministic:
  - the wallet calls are exactly requestAccounts, requestChainId and 4 × signTypedData
  - both pairs are identical
  - all 4 signatures verify against the local hashes
  - the hash binds the connected account
  - the read-only check reports `standard` VALID
- Mock wallet, randomized nonce: both pairs are reported `different`.
- Mock wallet that hashes the domain as ASCII: the check reports `version_and_revision_ascii`.
- A rejected prompt resumes without asking again.
- The report fields.
- The page sources contain no transaction or permission request strings and no URLs other than
  jsDelivr.

With `--live`, it makes read-only calls to the Sepolia pathfinder:
- It finds INVOKE senders in recent blocks.
- It calls `starknet_getClassHashAt` on them.
- It calls `is_valid_signature` with a mock-key signature. Class
  `0x5b4b537eaa2399e3aa99c4e2e0208ebd6c71bc1467938cd52c798c601e43564` returned `[0x0]`, and a class
  without the entrypoint was reported as such.

Browser test in the desktop app's built-in Chrome 152, through `serve.py --port 8791`:
- Both libraries loaded from jsDelivr with SRI, and the KAT gave 11/11.
- No global `starknet` was created.
- A mock wallet was injected as `window.starknet_templarmock` by hand:

  ```js
  const m = await import('/test/mock-wallet.mjs');
  const mock = m.createMockWallet(window.templarSignPage.state.sn, { address: '<optional real account>' });
  window.starknet_templarmock = mock.swo;
  ```
- The get-starknet dialog listed it, with install links and no MetaMask. Connect, all 4 signatures
  (identical pairs, all verify), the read-only check through the proxy against a real account
  (class hash shown, `[0x0]` for the mock signature) and Copy JSON all worked. There were no console
  errors and no horizontal scroll at 375 px.

What only you can test: real Ready and Braavos behaviour, meaning their prompts, determinism,
signature format and `is_valid_signature` results.
