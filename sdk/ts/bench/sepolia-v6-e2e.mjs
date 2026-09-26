// ADR-0027 phase E on Sepolia (docs/pool-v3-spec.md §11.2–§11.4): the SDK's view of the cutover,
// and §11.3's end to end: P6's ordinary deposit (1,000 token A) spent under R0 V6 through the SDK,
// the r6 prover server and the relayer's simulation, up to the gateway (which still refuses PROOF2).
//
//   node bench/sepolia-v6-e2e.mjs P6_RUN_DIR STEP
//
// Steps (each appends to P6_RUN_DIR/e2e/v6-progress.json):
//   check      the pins against the chain (Templar.connect), each kind's current generation and
//              route set, the pending proposals with their pinned flags, and the prover's info
//   deposits   whether deposits are allowed now: a deposit is attempted with an account that refuses
//              to send, so an allowed deposit stops before any transaction ("would send")
//   withdraw   after the swap: sync, the P6 V5 withdrawal record's state, then a full withdrawal of
//              the ordinary note to the relayer, planned under the current generation (R0 V6),
//              proved in WASM, wrapped by the prover server and handed to the relayer
//
// P6_RUN_DIR is bench/account-bound-p6's run directory (the ordinary wallet's seed and store, the
// relayer's address). Nothing here signs with account-1; the only transactions are the relayer's.
import { readFile, writeFile } from 'node:fs/promises';
import { RpcProvider } from 'starknet';
import { FileKV, SEPOLIA, Templar, currentGeneration, loadCore } from '../dist/index.js';

await loadCore();
const [runDir, step] = process.argv.slice(2);
if (!runDir || !step) throw new Error('usage: sepolia-v6-e2e.mjs P6_RUN_DIR check|deposits|withdraw');
const LOCAL = process.env.LOCAL_RPC ?? 'http://127.0.0.1:9545/rpc/v0_10';
const PROVER = process.env.PROVER_URL ?? 'http://127.0.0.1:8490';

const json = (v) => JSON.stringify(v, (_, x) => (typeof x === 'bigint' ? x.toString() : x), 1);
const load = async (p, d) => JSON.parse(await readFile(`${runDir}/${p}`, 'utf8').catch(() => JSON.stringify(d)));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const progress = await load('e2e/v6-progress.json', { log: [] });
const log = async (stage, detail) => {
  progress.log.push({ at: new Date().toISOString(), stage, ...detail });
  await writeFile(`${runDir}/e2e/v6-progress.json`, json(progress), { mode: 0o600 });
  console.log(stage, json(detail));
};

const deployment = await load('sepolia/deployment.json');
const relayerInfo = await load('sepolia/relayer.json');
const seeds = await load('e2e/private-seeds.json', null);
if (!seeds) throw new Error('no P6 seeds in the run directory');
const TOKEN = deployment.token;
const local = new RpcProvider({ nodeUrl: LOCAL });
const tpl = await Templar.connect({ provider: local, network: SEPOLIA, kv: new FileKV(`${runDir}/e2e/store`) });
const alice = await tpl.wallet(Uint8Array.from(Buffer.from(seeds.alice, 'hex')));
const prover = tpl.prover({ url: PROVER });
const pool = SEPOLIA.pools.at(-1);

async function generations() {
  const out = {};
  for (const kind of ['R0', 'P1']) {
    try {
      const { generation, routes } = await currentGeneration(local, pool, kind);
      out[kind] = { relation: generation.relation, adapter: generation.adapter, routing: generation.routing, routes: routes.map((r) => r.statement) };
    } catch (e) {
      out[kind] = { error: `${e.code ?? ''} ${String(e.message ?? e).slice(0, 300)}` };
    }
  }
  return out;
}

const proposals = async () =>
  (await alice.proposals()).map((p) => ({
    key: p.key, value: p.value, eta: p.eta, lapsed: p.lapsed, verifier: p.verifier, pinned: p.pinned,
    route: p.route && { adapter: p.route.adapter, statement: p.route.statement, adding: p.route.value !== null },
  }));

if (step === 'check') {
  let info;
  try {
    info = await prover.info();
  } catch (e) {
    info = { error: String(e.message ?? e).slice(0, 300) };
  }
  const infoSummary = info?.error
    ? info
    : { r6: info.r6 && { adapter: info.r6.adapter, route: info.r6.route, bucket_log_size: info.r6.bucket_log_size },
        relations: info.relations?.map?.((r) => ({ name: r.name, adapter: r.adapter, status_at_startup: r.status_at_startup })) };
  await log('check', { block: (await local.getBlockLatestAccepted()).block_number, generations: await generations(), proposals: await proposals(), prover: infoSummary });
} else if (step === 'deposits') {
  // An account that refuses to send: an allowed deposit stops at its first transaction.
  const refuse = { address: relayerInfo.address, execute: async () => { throw Object.assign(new Error('would send'), { code: 'would_send' }); } };
  let outcome;
  try {
    await alice.deposit(refuse, { asset: { standard: 20, contract: TOKEN }, amount: 1n });
    outcome = { allowed: true, note: 'returned without sending?' };
  } catch (e) {
    outcome = e.code === 'would_send' ? { allowed: true } : { allowed: false, code: e.code, message: String(e.message ?? e).slice(0, 300) };
  }
  await log('deposits', { outcome, proposals: await proposals() });
} else if (step === 'withdraw') {
  const gens = await generations();
  if (gens.R0.relation !== 'r6') throw new Error(`the pool's R0 verifier is not the V6 routing adapter yet: ${json(gens.R0)}`);
  const s = await alice.sync();
  const old = await load('e2e/ordinary-withdraw-record-id.json', null);
  let v5;
  if (old) {
    try {
      const rec = await (await alice.resume(old.id)).record();
      v5 = { stage: rec.stage, version: rec.plan?.version, valid_until: rec.window?.valid_until ?? rec.plan?.valid_until };
    } catch (e) {
      v5 = { error: `${e.code ?? ''} ${String(e.message ?? e).slice(0, 200)}` };
    }
  }
  const spend = await alice.withdraw(TOKEN, 1000n, relayerInfo.address);
  const t0 = Date.now();
  const proved = await spend.prove();
  const proveMs = Date.now() - t0;
  const t1 = Date.now();
  const window = await spend.wrap(prover, { url: PROVER, onStatus: (x) => console.log('withdraw', x.status, x.stage ?? '') });
  const wrapMs = Date.now() - t1;
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
  await writeFile(`${runDir}/e2e/v6-withdraw-record-id.json`, json({ id: spend.id }), { mode: 0o600 });
  await log('withdraw', {
    generations: gens, sync: { complete: s.complete, problems: s.problems, balances: s.balances }, v5_record: v5,
    prove_ms: proveMs, wrap_ms: wrapMs, plan: { version: rec.plan.version, valid_until: rec.plan.valid_until, adapter: rec.adapter },
    circuit_hash: proved.circuit_hash, window, relay, relay_tx_status: txStatus, job: rec.server,
  });
} else {
  throw new Error(`unknown step ${step}`);
}
