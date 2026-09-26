// P6 end to end on Sepolia (docs/account-bound-note-spec.md §15 P6): pool V3 with the SDK, the
// prover server and the relayer, a real Braavos account for the bound wallet.
//
// A record of the P6 run (results in bench/account-bound-p6/results/e2e.json). ADR-0027 phase B
// removed bound wallets from the SDK and the prover server, so this script runs only against the
// SDK at commit 7b5b0a4.
//
//   node bench/sepolia-v3-e2e.mjs RUN_DIR            # one stage per run; resumable
//
// Stages: seeds; the bound setup check (Braavos signs); two deposits from the relayer's account
// (live: CONFIRM_DEPOSITS=yes); sync; a bound in-pool transfer (Braavos signs the spend) and an
// ordinary full withdrawal, each proved in WASM, wrapped by the prover server and handed to the
// relayer, which simulates the exact transaction with validation and sends it; then the wallet's
// own fallback submission near the deadline (FALLBACK=yes). While the gateway rejects large
// proofs, the proof-carrying transactions end at the gateway; every answer is recorded.
//
// RUN_DIR is bench/account-bound-p6's run directory: `sepolia/deployment.json`, `pool-pins.json`,
// `sepolia/relayer.json` and the relayer's fresh key. Signing goes through the local page
// (client-port/cairo-r5/sign/serve.py RUN_DIR/sign/requests.json RUN_DIR/sign/results): the script
// writes the request and waits for the saved signature. The only secrets (seeds, the relayer key)
// stay in RUN_DIR.
import { mkdir, readFile, writeFile, chmod } from 'node:fs/promises';
import { Account, RpcProvider, typedData as TD, num } from 'starknet';
import { FileKV, SEPOLIA, Templar, loadCore, FALLBACK_MARGIN } from '../dist/index.js';

await loadCore();
const [runDir] = process.argv.slice(2);
if (!runDir) throw new Error('usage: sepolia-v3-e2e.mjs RUN_DIR');
const LOCAL = process.env.LOCAL_RPC ?? 'http://127.0.0.1:9545/rpc/v0_10';
const PUBLIC = process.env.PUBLIC_RPC ?? 'https://api.zan.top/public/starknet-sepolia/rpc/v0_10';
const PROVER = process.env.PROVER_URL ?? 'http://127.0.0.1:8490';
const BRAAVOS = '0x665f820f6fda2b1a864ae5814e568f26fbc259c43c428643b64172c2bef58db';

const json = (v) => JSON.stringify(v, (_, x) => (typeof x === 'bigint' ? x.toString() : x), 1);
const load = async (p, d) => JSON.parse(await readFile(`${runDir}/${p}`, 'utf8').catch(() => JSON.stringify(d)));
const save = (p, v) => writeFile(`${runDir}/${p}`, json(v), { mode: 0o600 });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
await mkdir(`${runDir}/e2e`, { recursive: true, mode: 0o700 });
await mkdir(`${runDir}/sign/results`, { recursive: true });

const progress = await load('e2e/progress.json', { stage: 'start', log: [] });
const log = async (stage, detail) => {
  progress.stage = stage;
  progress.log.push({ at: new Date().toISOString(), stage, ...detail });
  await save('e2e/progress.json', progress);
  console.log(stage, json(detail));
};

const pins = await load('pool-pins.json');
const deployment = await load('sepolia/deployment.json');
const relayerInfo = await load('sepolia/relayer.json');
const TOKEN = deployment.token;
// The SDK pins pool V3 as Sepolia's active pool; the deployment must be the pinned one.
const network = SEPOLIA;
const active = SEPOLIA.pools.at(-1);
if (BigInt(active.pool) !== BigInt(pins.pool) || BigInt(active.adapter) !== BigInt(pins.adapter)) throw new Error('the run directory is not the pinned pool V3');

// Providers: `seen` has seen the bound account (setup checks, sync); spend reads and every
// submission go through the local node, which has not (spec §10).
const seen = new RpcProvider({ nodeUrl: PUBLIC });
const local = new RpcProvider({ nodeUrl: LOCAL });
const relayerKey = (await readFile(relayerInfo.key_file, 'utf8')).trim();
const relayer = new Account({ provider: local, address: relayerInfo.address, signer: relayerKey });

// The connected wallet, through the signing page: the request is written, the page signs it with
// Braavos and saves the result, and the signature is read back.
let label = '';
const braavos = {
  address: BRAAVOS,
  async signTypedData(typedData) {
    const hash = TD.getMessageHash(typedData, BRAAVOS);
    const results = `${runDir}/sign/results/braavos-${BRAAVOS.slice(0, 12)}.json`;
    await writeFile(`${runDir}/sign/requests.json`, json({ [num.toHex(BRAAVOS)]: [{ typedData, messageHash: hash, proof: label }] }));
    console.log(`\nSIGN NOW: reload http://localhost:8766/, connect Braavos, press Sign ("${label}", message hash ${hash})\n`);
    await writeFile(`${runDir}/e2e/waiting-for-signature.txt`, `${label}\n${hash}\n`);
    for (;;) {
      const r = await readFile(results, 'utf8').then(JSON.parse).catch(() => null);
      const hit = r && (r.results ?? [r]).find((x) => x.messageHash && BigInt(x.messageHash) === BigInt(hash));
      if (hit) {
        await writeFile(`${runDir}/e2e/waiting-for-signature.txt`, '');
        return hit.signature;
      }
      await sleep(2000);
    }
  },
};

const seeds = await load('e2e/private-seeds.json', null);
if (!seeds) {
  await save('e2e/private-seeds.json', {
    alice: Buffer.from(Templar.generateSeed()).toString('hex'),
    bound: Buffer.from(Templar.generateBoundSeed()).toString('hex'),
  });
  await chmod(`${runDir}/e2e/private-seeds.json`, 0o600);
  console.log('seeds created; run again');
  process.exit(0);
}
const seed = (name) => Uint8Array.from(Buffer.from(seeds[name], 'hex'));

const tpl = await Templar.connect({ provider: seen, network, kv: new FileKV(`${runDir}/e2e/store`) });
const prover = tpl.prover({ url: PROVER });

if (progress.stage === 'start') {
  label = 'bound setup check';
  const r = await tpl.boundSetupCheck(BRAAVOS, braavos);
  await log('bound-checked', { account: BRAAVOS, ...r, prover_info: await prover.info() });
}

const alice = await tpl.wallet(seed('alice'));
const bound = await tpl.boundWallet(seed('bound'), BRAAVOS, braavos, { spendProvider: local });
const aliceAddr = await alice.address(0);
const boundAddr = await bound.address(0);

if (progress.stage === 'bound-checked') {
  if (process.env.CONFIRM_DEPOSITS !== 'yes') throw new Error('the deposits are live transactions: set CONFIRM_DEPOSITS=yes');
  const asset = { standard: 20, contract: TOKEN };
  const a = await alice.deposit(relayer, { asset, amount: 1000n, to: aliceAddr.address });
  await local.waitForTransaction(a.transactionHash);
  const b = await bound.deposit(relayer, { asset, amount: 1000n, to: boundAddr.address });
  await local.waitForTransaction(b.transactionHash);
  await log('deposited', { ordinary: a, bound: b, fingerprints: { alice: aliceAddr.fingerprint, bound: boundAddr.fingerprint } });
}

async function blockAtLeast(n) {
  for (;;) {
    const b = (await local.getBlockLatestAccepted()).block_number;
    if (b >= n) return b;
    await sleep(5000);
  }
}

if (progress.stage === 'deposited') {
  await blockAtLeast((await local.getBlockLatestAccepted()).block_number + 11);
  const a = await alice.sync();
  const b = await bound.sync();
  await log('synced', { alice: { complete: a.complete, problems: a.problems, balances: a.balances }, bound: { complete: b.complete, problems: b.problems, balances: b.balances } });
}

// Prove in WASM, (bound) authorize, wrap at the server, then follow the relayer's answer.
async function relayed(name, spend) {
  const t0 = Date.now();
  const proved = await spend.prove();
  const proveMs = Date.now() - t0;
  let authorization;
  if (name.startsWith('bound')) {
    label = `${name}: pay 400 of token A in the pool`;
    authorization = await spend.authorize();
  }
  const t1 = Date.now();
  const window = await spend.wrap(prover, { url: PROVER, onStatus: (s) => console.log(name, s.status, s.stage ?? '') });
  const wrapMs = Date.now() - t1;
  // The relayer claims the job, simulates the exact transaction with validation and sends it; its
  // answer is the signed transaction hash, or a refusal when nothing was sent.
  let relay;
  for (let i = 0; i < 200; i++) {
    relay = await spend.relayStatus(prover);
    if (relay && relay.status !== 'pending') break;
    await sleep(6000);
  }
  let txStatus;
  if (relay?.status === 'submitted') {
    txStatus = await local.getTransactionStatus(relay.transaction_hash).catch((e) => ({ error: String(e.message ?? e).slice(0, 300) }));
  }
  const rec = await spend.record();
  await save(`e2e/${name}-record-id.json`, { id: spend.id });
  await log(name, { prove_ms: proveMs, wrap_ms: wrapMs, plan: { version: rec.plan.version, valid_until: rec.plan.valid_until, bound_account: rec.plan.bound_account },
                    authorization: authorization && { salt: authorization.salt, hash: authorization.hash }, window, relay, relay_tx_status: txStatus,
                    job: rec.server, token_out: proved.statement.token_out });
}

if (progress.stage === 'synced') {
  await relayed('bound-transfer', await bound.transfer(TOKEN, 400n, aliceAddr.address));
}

if (progress.stage === 'bound-transfer') {
  await relayed('ordinary-withdraw', await alice.withdraw(TOKEN, 1000n, relayerInfo.address));
}

// The wallet's own submission (§7.4): allowed from `send_deadline − FALLBACK_MARGIN` while the
// relayer's transaction never landed. Simulated with validation, then sent to the gateway.
if (progress.stage === 'ordinary-withdraw' && process.env.FALLBACK === 'yes') {
  const { id } = await load('e2e/ordinary-withdraw-record-id.json');
  const spend = await alice.resume(id);
  const rec = await spend.record();
  const deadline = rec.window.valid_until;
  const from = await blockAtLeast(deadline - FALLBACK_MARGIN);
  let outcome;
  try {
    const s = await spend.submit(relayer, { prover, confirmFee: (max, expected, warnings) => (console.log('fallback max fee', max, 'expected', expected, warnings), true) });
    outcome = { sent: s.transactionHash, maxFee: s.prepared.maxFee, expectedFee: s.prepared.expectedFee, warnings: s.warnings };
  } catch (e) {
    const r = await spend.record();
    const msg = String(e.message ?? e);
    // A node error embeds the whole request; keep the gateway's reason, which comes last.
    const reason = msg.match(/An unexpected error occurred: "?([^"\n]*)/)?.[1] ?? msg.slice(-400);
    outcome = { error: reason, code: e.code, record_stage: r.stage, tx: r.tx && { hash: r.tx.hash, nonce: r.tx.nonce, maxFee: r.tx.maxFee } };
  }
  await log('fallback', { deadline, from_block: from, outcome });
}
console.log('stage', progress.stage);
