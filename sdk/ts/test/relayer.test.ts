// The relayer and the wallet's fallback (docs/account-bound-note-spec.md §7.3, §7.4; P4b): the
// relayer takes each finished R0 V5 result from the prover's handoff, waits for its submit block,
// runs the acceptance checks, claims and submits, answering every job with a transaction hash or a
// refusal; the wallet submits itself only on a refusal, or near the deadline with no relayer
// transaction pending. The review's cases (AB-RL1 to AB-RL11) each have a test.
import 'fake-indexeddb/auto';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { beforeAll, describe, expect, test } from 'vitest';

import * as wasm from '../wasm/templar.js';
import initTest, * as twasm from '../wasm-test/templar_test.js';
import { FALLBACK_MARGIN, MemoryKV, SEPOLIA, Templar, loadCore, pinsOf, type NetworkConstants } from '../dist/index.js';
import { Relayer, fileStore, type RelayerState, type StateStore } from '../dist/relayer.js';
import { MockChain, MockProver, SEL } from './mockchain.js';

const TOKEN = '0x39f5916e2110601b44d7ed0f4c033dd684f99b945df2cce8356c73dc0c805b8';
const V5_CIRCUIT = [1903585510, 1708577544, 3915427995, 3101166941, 461832048, 2805149134, 1077751030, 1205594117];
const V3: NetworkConstants = {
  ...SEPOLIA,
  pools: [
    {
      ...SEPOLIA.pools[0]!,
      pool: '0x7e57b301',
      version: 'v5',
      parameters: { expiryWindow: 1500, quantum: 100, rootWindow: 4096, timelock: 86400 },
      adapter: '0xada5',
      adapterClass: '0xada5c1a5',
      statement: '0x5a7e05',
      statementClass: '0x5a7e05c1a5',
      accountTag: 'TMPZR0_PAYMENT_V5',
      maxProofAge: 1024,
      circuitHash: V5_CIRCUIT,
    },
  ],
};
const POOL = V3.pools[0]!;
const pins = JSON.stringify(pinsOf(V3, POOL));
const facts = (binding: string, base: number, hash: string) => JSON.parse(twasm.test_expected_facts(pins, binding, BigInt(base), hash));

beforeAll(async () => {
  await loadCore();
  await initTest({ module_or_path: readFileSync(new URL('../wasm-test/templar_test_bg.wasm', import.meta.url)) });
});

const memory = (init?: RelayerState): StateStore & { s?: RelayerState } => {
  const m: StateStore & { s?: RelayerState } = { s: init, load: () => m.s && structuredClone(m.s), save: (s) => (m.s = structuredClone(s)) };
  return m;
};

function relayerFor(chain: MockChain, prover: MockProver, opts: { state?: StateStore; assets?: string[] } = {}) {
  return new Relayer({
    pool: POOL,
    provider: chain.provider(),
    account: chain.account('0x5e1a'),
    handoff: { url: 'http://p', token: 't0ken', fetch: prover.handoff as any },
    // The signed hash, one per nonce (the mock node answers every send with 0xbeef).
    hashOf: (p) => '0xa' + BigInt(p.nonce).toString(16).padStart(4, '0'),
    maxFee: 10n ** 18n,
    assets: opts.assets ?? [TOKEN],
    ...(opts.state ? { state: opts.state } : {}),
  });
}

/** A proved and wrapped V5 withdrawal at a relaying server, and a relayer on the same chain. */
async function relayedSpend(amount = 300n, opts: { state?: StateStore; assets?: string[] } = {}) {
  const chain = new MockChain(POOL);
  const t = await Templar.connect({ provider: chain.provider(), network: V3, kv: new MemoryKV() });
  const w = await t.wallet(new Uint8Array(32).fill(0xe5));
  chain.deposit(JSON.parse(wasm.note_for((await w.address(0)).address, TOKEN, amount.toString(), V3.chainId, POOL.pool)), TOKEN, amount);
  chain.mine(12);
  await w.sync();
  const spend = await w.withdraw(TOKEN, amount, '0xb0b');
  const proved = await spend.prove();
  const prover = new MockProver(chain, facts);
  prover.binding = proved.binding;
  prover.relayEnabled = true;
  const client = t.prover({ url: 'http://p', fetch: prover.fetch as any });
  const window = await spend.wrap(client, { url: 'http://p' });
  const relayer = relayerFor(chain, prover, opts);
  return { chain, t, w, spend, proved, prover, client, window, relayer };
}

/** The first job's body with its nullifiers moved by `k`: other notes for the relayer's checks. */
function otherNotes(body: string, k: number): string {
  const b = JSON.parse(body);
  b.statement.nullifiers = b.statement.nullifiers.map((n: number[]) => n.map((x) => (x + k) % 2147483647));
  return JSON.stringify(b);
}

describe('the relayer', () => {
  test('takes a result, waits for its submit block, claims, submits, and answers the job', async () => {
    const { chain, spend, prover, client, relayer } = await relayedSpend();
    expect((await spend.record()).relay).toEqual({ status: 'pending' });
    expect(await relayer.tick()).toEqual([]); // the base block is too recent
    chain.mine(12);
    expect(await relayer.tick()).toEqual([{ id: expect.any(String), outcome: { transaction_hash: '0xa0007' } }]);
    expect(prover.claimed.size).toBe(1);
    const sim = chain.calls.filter((c) => c.method === 'fetch').at(-1)!;
    expect(sim.args[0]).toBe('starknet_simulateTransactions');
    expect((sim.args[1] as any).simulation_flags).toEqual([]);
    expect(await relayer.tick()).toEqual([]);
    expect(await spend.relayStatus(client)).toEqual({ status: 'submitted', transaction_hash: '0xa0007' });
    // The same notes through another job: answered with the transaction it already sent, never a
    // refusal the wallet would act on (AB-RL1).
    prover.jobs.set('dup', { status: 'done', body: prover.bodies[0]! });
    expect(await relayer.tick()).toEqual([{ id: 'dup', outcome: { transaction_hash: '0xa0007' } }]);
    // Its margin must exceed the wallet's fallback margin by at least 20 blocks (AB-RL8), and it
    // always needs the handoff token (AB-RL10).
    const bad = (over: object) => () =>
      new Relayer({ pool: POOL, provider: chain.provider(), account: chain.account(), hashOf: () => '0x1', handoff: { url: 'http://p', token: 'x' }, maxFee: 1n, assets: [], ...over });
    expect(bad({ marginBlocks: FALLBACK_MARGIN + 19 })).toThrow(/relay_margin/);
    expect(bad({ handoff: { url: 'http://p', token: '' } })).toThrow(/relay_token/);
  }, 120_000);

  test('an ambiguous send, a lost report, a restart: the answer is always the signed hash', async () => {
    const state = memory();
    const { chain, prover, relayer } = await relayedSpend(300n, { state });
    chain.mine(12);
    // The send fails after the transaction may have left, and the report does not arrive (AB-RL1).
    chain.sendFailNext = true;
    prover.reportFailNext = true;
    expect(await relayer.tick()).toEqual([{ id: expect.any(String), outcome: { transaction_hash: '0xa0007' } }]);
    expect(prover.relay.size).toBe(0);
    // The next pass delivers the same answer, and decides nothing again.
    const sends = chain.sent.length;
    await relayer.tick();
    expect([...prover.relay.values()]).toEqual([{ status: 'submitted', transaction_hash: '0xa0007' }]);
    expect(chain.sent.length).toBe(sends);
    // A restarted relayer (same state) answers a new job for these notes with that hash (AB-RL6).
    prover.jobs.set('again', { status: 'done', body: prover.bodies[0]! });
    expect(await relayerFor(chain, prover, { state }).tick()).toEqual([{ id: 'again', outcome: { transaction_hash: '0xa0007' } }]);
    // The state file round-trips.
    const file = fileStore(join(mkdtempSync(join(tmpdir(), 'relayer-')), 'state.json'));
    expect(file.load()).toBeUndefined();
    file.save(state.s!);
    expect(Object.values(file.load()!.submitted).map((v) => v.tx)).toEqual(['0xa0007', '0xa0007']);
  }, 120_000);

  test('nonces in sequence; its own transactions tracked: a stuck one pauses, a revert denies', async () => {
    const state = memory();
    const { chain, prover, relayer } = await relayedSpend(300n, { state });
    chain.mine(12);
    // Two jobs in one pass: nonces 7 and 8, never the chain's twice (AB-RL4). The extra jobs share
    // the first one's result (its base block), with other notes.
    const r1 = [...prover.jobs.values()][0]!.result as Record<string, unknown>;
    prover.jobs.set('b', { status: 'done', body: otherNotes(prover.bodies[0]!, 1), result: r1 });
    const out = await relayer.tick();
    expect(out.map((o) => o.outcome)).toEqual([{ transaction_hash: '0xa0007' }, { transaction_hash: '0xa0008' }]);
    expect(chain.signedNonces.slice(-2)).toEqual(['0x7', '0x8']);
    // One of them pending past stuckBlocks: new jobs wait unanswered.
    chain.txStatus.set('0xa0007', { finality_status: 'RECEIVED' });
    chain.txStatus.set('0xa0008', { finality_status: 'ACCEPTED_ON_L2', execution_status: 'SUCCEEDED' });
    chain.mine(25);
    prover.jobs.set('c', { status: 'done', body: otherNotes(prover.bodies[0]!, 2), result: r1 });
    expect(await relayer.tick()).toEqual([]);
    // It reverts: its notes are denied for good (AB-RL7), and the pause ends.
    chain.txStatus.set('0xa0007', { finality_status: 'ACCEPTED_ON_L2', execution_status: 'REVERTED' });
    expect((await relayer.tick()).map((o) => o.id)).toEqual(['c']);
    expect(Object.keys(state.s!.denied).length).toBe(2);
    expect(Object.keys(state.s!.inflight)).toEqual(['0xa0009']);
  }, 120_000);

  test('refuses what the pool would refuse or it will not relay, with a reason; waits on a lagging node', async () => {
    const { chain, prover, relayer, proved } = await relayedSpend();
    chain.mine(12);
    const body = JSON.parse(prover.bodies[0]!);
    const base = chain.latest - 12;
    const f = facts(proved.binding, base, chain.blocks[base - chain.base]!.hash);
    const job = (id: string, over: Record<string, unknown> = {}) =>
      prover.jobs.set(id, { status: 'done', body: prover.bodies[0]!, result: { proof: 'AAAA', proof_facts: f, base_block: base, binding: proved.binding, send_deadline: 10 ** 9, pool_call: body.pool_call, ...over } });
    prover.jobs.clear();
    // A lagging node: nothing is sent or answered (AB-RL8).
    chain.blockTime = 1_000;
    job('late', { send_deadline: chain.latest + 10 });
    expect(await relayer.tick()).toEqual([]);
    chain.blockTime = undefined;
    job('invoke', { pool_call: { entry_point: 'apply_spend_with_invoke', calldata: body.pool_call.calldata } });
    const out = await relayer.tick();
    expect(Object.fromEntries(out.map((o) => [o.id, o.outcome]))).toEqual({
      invoke: { refused: expect.stringMatching(/F06/) },
      late: { refused: expect.stringMatching(/too close/) },
    });
    chain.superseded.set(body.statement.root.join(','), chain.latest - 4096 + 5);
    job('root');
    expect((await relayer.tick())[0]!.outcome).toEqual({ refused: expect.stringMatching(/root/) });
    chain.superseded.clear();
    // An exit asset outside its allowlist (AB-RL7).
    job('asset');
    expect((await relayerFor(chain, prover, { assets: [] }).tick())[0]!.outcome).toEqual({ refused: expect.stringMatching(/asset/) });
    // A claim the server refuses (it answered the job for lateness): nothing is sent (AB-RL9).
    prover.refuseClaims = true;
    job('unclaimed');
    const sends = () => chain.calls.filter((c) => c.method === 'invokeSignedTx').length;
    const before = sends();
    expect(await relayer.tick()).toEqual([]);
    expect(sends()).toBe(before);
    prover.refuseClaims = false;
    // A nullifier already spent.
    chain.inject({ from_address: POOL.pool, keys: [SEL.NullifierSpent], data: ['0x9', ...body.statement.nullifiers[0].map((x: number) => '0x' + x.toString(16))] });
    job('spent');
    expect((await relayer.tick())[0]!.outcome).toEqual({ refused: expect.stringMatching(/already spent/) });
    expect(prover.relay.get('spent')).toEqual({ status: 'refused', reason: expect.stringMatching(/already spent/) });
  }, 120_000);
});

describe('the wallet fallback', () => {
  test('waits for the relayer, falls back on its refusal or near the deadline, never beside a pending transaction', async () => {
    const { chain, spend, client, window, relayer } = await relayedSpend();
    const submit = (prover = true) => spend.submit(chain.account('0xfa11'), { confirmFee: () => true, ...(prover ? { prover: client } : {}) });
    chain.mine(12);
    // While the relayer may submit, its answer is required (AB-RL3).
    await expect(submit(false)).rejects.toThrow(/prover_required/);
    await expect(submit()).rejects.toThrow(/relay_pending/);
    await relayer.tick();
    chain.txStatus.set('0xa0007', { finality_status: 'RECEIVED' });
    await expect(submit()).rejects.toThrow(/relay_pending/);
    chain.txStatus.set('0xa0007', { finality_status: 'ACCEPTED_ON_L2', execution_status: 'SUCCEEDED' });
    await expect(submit()).rejects.toThrow(/relay_landed/);
    // A status that did not come back is no answer (AB-RL3).
    chain.statusFailNext = true;
    await expect(submit()).rejects.toThrow(/relay_unknown/);
    // Failed: the wallet may submit at once (its account is linkable, §7.4).
    chain.txStatus.set('0xa0007', { finality_status: 'ACCEPTED_ON_L2', execution_status: 'REVERTED' });
    expect((await submit()).linkable).toBe(true);
    // Unknown to the node (RPC error 29): only from the deadline minus the margin.
    chain.txStatus.clear();
    await expect(submit()).rejects.toThrow(/fall back from block/);
    chain.mine(window.valid_until - FALLBACK_MARGIN - chain.latest);
    expect((await submit()).transactionHash).toBe('0xbeef');
  }, 120_000);

  test('a refusal lets the wallet submit at once; a job re-wrapped elsewhere keeps the first relay (AB-RL2)', async () => {
    const { chain, spend, prover, client, relayer } = await relayedSpend();
    const body = JSON.parse(prover.bodies[0]!);
    chain.mine(12);
    chain.inject({ from_address: POOL.pool, keys: [SEL.NullifierSpent], data: ['0x9', ...body.statement.nullifiers[1].map((x: number) => '0x' + x.toString(16))] });
    await relayer.tick();
    expect(await spend.relayStatus(client)).toEqual({ status: 'refused', reason: expect.any(String) });
    expect((await spend.submit(chain.account('0xfa11'), { confirmFee: () => true })).transactionHash).toBe('0xbeef');

    // Re-wrapped at a server that does not relay while the first server's relay is unanswered: that
    // relayer may still submit, so the wallet waits for that job's deadline minus the margin.
    const other = await relayedSpend(200n);
    const first = (await other.spend.record()).window!;
    const plain = new MockProver(other.chain, facts);
    plain.binding = other.proved.binding;
    await other.spend.wrap(other.t.prover({ url: 'http://q', fetch: plain.fetch as any }), { url: 'http://q' });
    const rec = await other.spend.record();
    expect(rec.relay).toEqual({ status: 'none' });
    expect(rec.attempts.at(-1)!.relay).toEqual({ status: 'pending' });
    other.chain.mine(12);
    const submit = () => other.spend.submit(other.chain.account('0xfa11'), { confirmFee: () => true });
    await expect(submit()).rejects.toThrow(/fall back from block/);
    other.chain.mine(first.valid_until - FALLBACK_MARGIN - other.chain.latest);
    expect((await submit()).transactionHash).toBe('0xbeef');
  }, 180_000);

  test('a job abandoned before its result still counts: its relayer may submit it (AB-RL2b)', async () => {
    const chain = new MockChain(POOL);
    const t = await Templar.connect({ provider: chain.provider(), network: V3, kv: new MemoryKV() });
    const w = await t.wallet(new Uint8Array(32).fill(0xe6));
    chain.deposit(JSON.parse(wasm.note_for((await w.address(0)).address, TOKEN, '100', V3.chainId, POOL.pool)), TOKEN, 100n);
    chain.mine(12);
    await w.sync();
    const spend = await w.withdraw(TOKEN, 100n, '0xb0b');
    const proved = await spend.prove();
    const p = new MockProver(chain, facts);
    p.binding = proved.binding;
    p.relayEnabled = true;
    // The app stops waiting at the relaying server P before the result comes back...
    const abandon = () => {
      throw new Error('too slow');
    };
    await expect(spend.wrap(t.prover({ url: 'http://p', fetch: p.fetch as any }), { url: 'http://p', onStatus: abandon })).rejects.toThrow(/too slow/);
    expect((await spend.record()).relay).toEqual({ status: 'pending' });
    // ...and wraps at Q, which does not relay. P's job has no window: the statement's valid_until
    // bounds it.
    const q = new MockProver(chain, facts);
    q.binding = proved.binding;
    await spend.wrap(t.prover({ url: 'http://q', fetch: q.fetch as any }), { url: 'http://q' });
    const rec = await spend.record();
    expect(rec.attempts.at(-1)).toMatchObject({ relay: { status: 'pending' } });
    expect(rec.attempts.at(-1)!.window).toBeUndefined();
    chain.mine(12);
    const submit = () => spend.submit(chain.account('0xfa11'), { confirmFee: () => true });
    await expect(submit()).rejects.toThrow(new RegExp(`fall back from block ${rec.plan.valid_until! - FALLBACK_MARGIN}`));
  }, 120_000);

  test('a prover that does not answer is not a relayer answer (AB-RL3)', async () => {
    const { chain, spend, t, prover } = await relayedSpend();
    chain.mine(12);
    const via = (status: number) =>
      t.prover({ url: 'http://p', fetch: (async (u: string | URL, i?: object) => (String(u).includes('/v1/jobs/') ? new Response('{}', { status }) : prover.fetch(u as string, i as any))) as any });
    await expect(spend.relayStatus(via(503))).rejects.toThrow(/relay_unknown/);
    expect(await spend.relayStatus(via(404))).toEqual({ status: 'pending' });
  }, 120_000);
});
