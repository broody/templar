// End to end on Sepolia with the SDK alone (spec §12.7): a deposit (live), sync and fresh-process
// recovery, a hidden transfer proved in WASM and wrapped by a prover server (directly or through
// OHTTP), submitted with starknet.js; then the same record re-planned as a withdrawal. While the
// gateway rejects large proofs, `submit` still simulates the exact signed transaction with
// validation before sending, and the gateway's answer is recorded.
//
//   STARKNET_RPC=… PROVER_URL=… [OHTTP_KEY_HEX=…] node bench/sepolia-e2e.mjs RUN_DIR
//
// The only live transaction without a proof is the deposit (stage `deposit`). The relayer's key is
// read from the sncast accounts file at run time and never written anywhere.
import { mkdir, readFile, writeFile, chmod } from 'node:fs/promises';
import { Account, RpcProvider } from 'starknet';
import { FileKV, SEPOLIA, Templar } from '../dist/index.js';

const [runDir] = process.argv.slice(2);
if (!runDir) throw new Error('usage: sepolia-e2e.mjs RUN_DIR');
await mkdir(runDir, { recursive: true, mode: 0o700 });
await chmod(runDir, 0o700);
const nodeUrl = process.env.STARKNET_RPC ?? 'http://127.0.0.1:9545/rpc/v0_10';
const proverUrl = process.env.PROVER_URL ?? 'http://127.0.0.1:8480';
const TOKEN = '0x039f5916e2110601b44d7ed0f4c033dd684f99b945df2cce8356c73dc0c805b8';
const RELAYER = '0x54f2b25070d70d49f1c1f7c10ef2639889fdac15894d3fba1a03caf5603eca3';

const load = async (p, d) => JSON.parse(await readFile(`${runDir}/${p}`, 'utf8').catch(() => JSON.stringify(d)));
const save = (p, v) => writeFile(`${runDir}/${p}`, JSON.stringify(v, (_, x) => (typeof x === 'bigint' ? x.toString() : x), 1), { mode: 0o600 });
const progress = await load('progress.json', { stage: 'start', log: [] });
const log = async (stage, detail) => {
  progress.stage = stage;
  progress.log.push({ at: new Date().toISOString(), stage, ...detail });
  await save('progress.json', progress);
  console.log(stage, JSON.stringify(detail, (_, x) => (typeof x === 'bigint' ? x.toString() : x)));
};

const seeds = await load('private-seeds.json', null);
const seed = (name) => Uint8Array.from(Buffer.from(seeds[name], 'hex'));
if (!seeds) {
  await save('private-seeds.json', { alice: Buffer.from(Templar.generateSeed()).toString('hex'), bob: Buffer.from(Templar.generateSeed()).toString('hex') });
  process.exit(0 + console.log('seeds created; run again') ?? 0);
}

const provider = new RpcProvider({ nodeUrl });
const accounts = JSON.parse(await readFile('/home/broody/.starknet_accounts/starknet_open_zeppelin_accounts.json', 'utf8'));
const key = accounts.alpha_sepolia?.['account-1']?.private_key ?? accounts['alpha-sepolia']?.['account-1']?.private_key;
if (!key) throw new Error('relayer key not found');
const relayer = new Account({ provider, address: RELAYER, signer: key });

const tpl = await Templar.connect({ provider, network: SEPOLIA, kv: new FileKV(`${runDir}/store`) });
const alice = await tpl.wallet(seed('alice'));
const bob = await tpl.wallet(seed('bob'));
const aliceAddr = await alice.address(0);
const bobAddr = await bob.address(0);

const waitBlocks = async (n) => {
  const start = (await provider.getBlockLatestAccepted()).block_number;
  while ((await provider.getBlockLatestAccepted()).block_number < start + n) await new Promise((r) => setTimeout(r, 5000));
};

if (progress.stage === 'start') {
  if (process.env.CONFIRM_DEPOSIT !== 'yes') throw new Error('the deposit is a live transaction: set CONFIRM_DEPOSIT=yes');
  const d = await alice.deposit(relayer, { asset: { standard: 20, contract: TOKEN }, amount: 100n, to: aliceAddr.address });
  await provider.waitForTransaction(d.transactionHash);
  await log('deposited', { tx: d.transactionHash, commitment: d.commitment, address_fingerprint: aliceAddr.fingerprint });
}

if (progress.stage === 'deposited') {
  await waitBlocks(11);
  const r = await alice.sync();
  // Recovery: a fresh store, seed only.
  const fresh = await (await Templar.connect({ provider, network: SEPOLIA, kv: new FileKV(`${runDir}/recovery`) })).wallet(seed('alice'));
  const rec = await fresh.sync();
  await log('synced', { complete: r.complete, problems: r.problems, balances: r.balances, recovered: rec.balances, recovery_complete: rec.complete });
}

async function run(spend, name) {
  const t0 = Date.now();
  const proved = await spend.prove();
  const proveMs = Date.now() - t0;
  const ohttp = process.env.OHTTP_KEY_HEX ? { relayUrl: proverUrl, keyConfig: Uint8Array.from(Buffer.from(process.env.OHTTP_KEY_HEX, 'hex')) } : undefined;
  const prover = tpl.prover({ url: proverUrl, ohttp });
  const t1 = Date.now();
  const window = await spend.wrap(prover, { url: proverUrl, onStatus: (s) => console.log(name, s.status, s.stage ?? '') });
  const wrapMs = Date.now() - t1;
  let latest = (await provider.getBlockLatestAccepted()).block_number;
  while (latest < window.submit_after) {
    await new Promise((r) => setTimeout(r, 5000));
    latest = (await provider.getBlockLatestAccepted()).block_number;
  }
  let outcome;
  try {
    const s = await spend.submit(relayer, { confirmFee: (max, expected) => (console.log(name, 'max fee', max, 'expected', expected), true) });
    outcome = { included: 'sent', tx: s.transactionHash, maxFee: s.prepared.maxFee, expectedFee: s.prepared.expectedFee, linkable: s.linkable };
  } catch (e) {
    // A rejection after a passing simulation is the gateway's (PROOF_VERSION_NOT_ALLOWED today).
    outcome = { error: String(e.message ?? e).slice(0, 600), record_stage: spend.record.stage, tx: spend.record.tx };
  }
  await log(name, { prove_ms: proveMs, wrap_ms: wrapMs, window, token_out: proved.statement.token_out, outcome });
}

if (progress.stage === 'synced') {
  const spend = await alice.transfer(TOKEN, 60n, bobAddr.address);
  await save('record-id.json', { id: spend.record.id });
  await run(spend, 'transfer');
}

if (progress.stage === 'transfer') {
  // The transfer's statement left the wallet: its note is bound to that record. Re-plan it as a
  // withdrawal of the same note (spec §9.1).
  const { id } = await load('record-id.json', {});
  const spend = await alice.replan(id, { kind: 'withdraw', asset: TOKEN, amount: '100', recipient: RELAYER });
  await run(spend, 'withdraw');
}
console.log('stage', progress.stage);
