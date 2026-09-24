// The TypeScript layer against a mock pool, prover server and account (spec §12): receiving,
// spends proved in a worker, wrapping and re-wrapping, submission, the network-trace privacy rules,
// reorgs and bad data, records, deposits, recipients, keys and stores.
import 'fake-indexeddb/auto';
import { mkdtemp, writeFile, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { readFileSync } from 'node:fs';
import { beforeAll, describe, expect, test } from 'vitest';

import * as wasm from '../wasm/templar.js';
import initTest, * as twasm from '../wasm-test/templar_test.js';
import { FileKV, IndexedDBKV, MemoryKV, SEPOLIA, Templar, TemplarError, boundsFrom, loadCore, pinsOf, activePool, type NetworkConstants } from '../dist/index.js';
import { MockChain, MockProver, SEL } from './mockchain.js';

const TOKEN = '0x39f5916e2110601b44d7ed0f4c033dd684f99b945df2cce8356c73dc0c805b8';
const alice = new Uint8Array(32).fill(0xa1);
const bob = new Uint8Array(32).fill(0xb0);

async function setup(network: NetworkConstants = SEPOLIA) {
  const chain = new MockChain();
  const kv = new MemoryKV();
  const t = await Templar.connect({ provider: chain.provider(), network, kv });
  return { chain, kv, t };
}

function depositTo(chain: MockChain, address: string, amount: bigint, asset = TOKEN) {
  const note = JSON.parse(wasm.note_for(address, asset, amount.toString(), SEPOLIA.chainId, activePool(SEPOLIA).pool));
  chain.deposit(note, asset, amount);
}

function mockProver(chain: MockChain) {
  const pins = JSON.stringify(pinsOf(SEPOLIA, activePool(SEPOLIA)));
  return new MockProver(chain, (binding, base, hash) => JSON.parse(twasm.test_expected_facts(pins, binding, BigInt(base), hash)));
}

const leave = (w: any, id: string) => w.step(id, undefined, (r: any) => w.leaving(r));

beforeAll(async () => {
  await loadCore();
  await initTest({ module_or_path: readFileSync(new URL('../wasm-test/templar_test_bg.wasm', import.meta.url)) });
});

describe('receiving, spending and submission', () => {
  test('hidden transfer: prove, wrap, re-wrap, re-plan, submit, settle; only bulk reads', async () => {
    const { chain, kv, t } = await setup();
    const a = await t.wallet(alice);
    const b = await t.wallet(bob);
    const aAddr = (await a.address(0)).address;
    const bAddr = (await b.address(0)).address;
    chain.noise(3);
    depositTo(chain, aAddr, 1000n);
    chain.mine(12);

    let r = await a.sync();
    expect(r.problems).toEqual([]);
    expect(r.balances).toMatchObject([{ asset: TOKEN, unspent: 1000n, spendable: 1000n, notes: 1 }]);

    chain.calls = [];
    const spend = await a.transfer(TOKEN, 600n, bAddr);
    const plan = await spend.plan();
    expect(plan.inputs.length).toBe(1);
    const proved = await spend.prove();
    expect(proved.statement.token_out).toBe('0x0');

    // A server that serves another adapter is refused before the statement leaves (SDK-IP8).
    const evil = mockProver(chain);
    const evilFetch = evil.fetch;
    evil.fetch = async (u, i) => {
      const res = await evilFetch(u, i);
      if (!String(u).endsWith('/v1/info')) return res;
      const v = await res.json();
      v.relations[0].adapter = '0x123';
      return new Response(JSON.stringify(v));
    };
    await expect(spend.wrap(t.prover({ url: 'http://p', fetch: evil.fetch as any }), { url: 'http://p' })).rejects.toThrow(/prover_mismatch/);
    expect((await spend.record()).left).toBe(false);

    // Wrap; the statement leaves; the window is computed locally.
    const prover = mockProver(chain);
    prover.binding = proved.binding;
    const client = t.prover({ url: 'http://p', fetch: prover.fetch as any });
    let w = await spend.wrap(client, { url: 'http://p' });
    expect((await spend.record()).left).toBe(true);
    expect(w.valid_until - w.submit_after).toBe(4096 - 11);
    // Past the window, wrap again: the identical body is resubmitted (SDK-IP7).
    chain.mine(4100);
    w = await spend.wrap(client, { url: 'http://p' });
    expect(prover.bodies.length).toBe(2);
    expect(prover.bodies[1]).toBe(prover.bodies[0]);
    // A failed job is resubmitted with the same body.
    chain.mine(4100);
    prover.failNext = true;
    await spend.wrap(client, { url: 'http://p' });
    expect(new Set(prover.bodies).size).toBe(1);

    // Submit: raw estimate at the query version, the exact object simulated then sent (SDK-P4, IP9).
    chain.mine(12);
    chain.calls = [];
    const account = chain.account();
    chain.strk = 1n;
    await expect(spend.submit(account, { confirmFee: () => true })).rejects.toThrow(/insufficient_fee_balance/);
    chain.strk = 10n ** 20n;
    await expect(spend.submit(account, { confirmFee: () => false })).rejects.toThrow(/fee_declined/);
    const sent = await spend.submit(account, { confirmFee: () => true });
    expect(sent.linkable).toBe(true);
    const factory = chain.sent.filter((s: any) => s.calls?.factory).at(-1) as any;
    expect(factory.calls.factory.versions).toEqual(['0x100000000000000000000000000000003']);
    expect(factory.calls.factory.tip).toBe(0);
    const sim = chain.calls.filter((c) => c.method === 'fetch').at(-1)!;
    expect(sim.args[0]).toBe('starknet_simulateTransactions');
    expect((sim.args[1] as any).block_id).toBe('pre_confirmed');
    expect((sim.args[1] as any).simulation_flags).toEqual([]);
    const invoked = chain.calls.find((c) => c.method === 'invokeSignedTx')!.args[0];
    expect(invoked).toBe((sim.args[1] as any).transactions[0]);
    expect(sent.prepared.bounds.l2_gas).toEqual({ max_amount: (0x8000000n * 3n + 1n) / 2n, max_price_per_unit: 4n });
    const rec = await spend.record();
    expect(rec.tx?.hash).toBe('0xbeef');
    expect(rec.stage).toBe('sent_to_chain');

    // The note is bound to the record: another spend cannot take it, a re-plan can (spec §9.1).
    chain.mine(12);
    await expect(a.transfer(TOKEN, 1n, bAddr)).rejects.toThrow(/insufficient_notes/);
    expect((await a.sync()).balances).toMatchObject([{ unspent: 1000n, spendable: 0n }]);
    const again = await a.replan(spend.id, { kind: 'withdraw', asset: TOKEN, amount: '1000', recipient: '0xb0b' });
    const rec2 = await again.record();
    expect(rec2.attempts.length).toBe(1);
    expect(rec2.nullifiers).toEqual(rec.nullifiers);
    expect((await again.plan()).companion).toEqual(plan.companion);

    // The first attempt lands (the gateway or anyone): the record settles by its nullifiers (SDK-IP6).
    chain.applySpend(proved, plan);
    chain.mine(12);
    expect((await b.sync()).balances).toMatchObject([{ unspent: 600n }]);
    r = await a.sync();
    expect(r.balances).toMatchObject([{ unspent: 400n }]);
    expect((await again.record()).stage).toBe('settled');
    await expect(again.prove()).rejects.toThrow(/record_closed/);

    // Network trace (spec §12.5): events by pool address and every selector only; calls only to
    // pinned constants, the verifier, the leaf count and root, and (for submission) the account's
    // own balance and transaction path.
    const selectors = Object.values(SEL).map((s) => BigInt(s)).sort();
    for (const c of chain.calls) {
      if (c.method === 'getEvents') {
        const f = c.args[0] as { address: string; keys: string[][] };
        expect(BigInt(f.address)).toBe(BigInt(chain.pool.pool));
        expect(f.keys[0]!.map((k) => BigInt(k)).sort()).toEqual(selectors);
      } else if (c.method === 'callContract') {
        expect(['get_verifier', 'get_leaf_count', 'get_root', 'balance_of']).toContain(c.args[1]);
      } else {
        expect(['getBlockLatestAccepted', 'getBlockWithTxHashes', 'specVersion', 'estimate', 'fetch', 'invokeSignedTx']).toContain(c.method);
      }
    }
    for (const c of chain.calls.filter((c) => c.method === 'getBlockWithTxHashes')) expect(((c.args[0] as number) + 1) % 1000).toBe(0);
    for (const v of kv.raw().values()) {
      const s = Buffer.from(v).toString('latin1');
      expect(s.includes('39f5916e')).toBe(false);
      expect(s.includes('"600"')).toBe(false);
    }
  }, 300_000);

  test('a client circuit other than the pinned one is refused before anything leaves', async () => {
    const network = structuredClone(SEPOLIA);
    network.pools[0]!.circuitHash = [1, 2, 3, 4, 5, 6, 7, 8];
    const { chain, t } = await setup(network);
    const a = await t.wallet(alice);
    depositTo(chain, (await a.address(0)).address, 5n);
    chain.mine(12);
    const spend = await a.transfer(TOKEN, 5n, (await a.address(0)).address);
    await expect(spend.prove()).rejects.toThrow(/circuit_mismatch/);
    expect((await spend.record()).left).toBe(false);
  }, 180_000);
});

describe('sync faults', () => {
  test('a reorg rolls back and resyncs', async () => {
    const { chain, t } = await setup();
    const a = await t.wallet(alice);
    const aAddr = (await a.address(0)).address;
    chain.mine(1200);
    depositTo(chain, aAddr, 5n);
    chain.mine(12);
    expect((await a.sync()).balances).toMatchObject([{ unspent: 5n }]);
    chain.reorg(20);
    const r = await a.sync();
    expect(r.complete).toBe(true);
    expect(r.balances).toEqual([]);
  }, 60_000);

  test('a note found before a checkpoint survives later syncs and reorgs after it', async () => {
    const { chain, t } = await setup();
    const a = await t.wallet(alice);
    depositTo(chain, (await a.address(0)).address, 7n);
    chain.mine(1500);
    expect((await a.sync()).balances).toMatchObject([{ unspent: 7n }]);
    chain.mine(5);
    expect((await a.sync()).balances).toMatchObject([{ unspent: 7n }]);
    chain.reorg(100);
    const r = await a.sync();
    expect(r.complete).toBe(true);
    expect(r.balances).toMatchObject([{ unspent: 7n }]);
  }, 60_000);

  test('a leaf dropped once, or tampered once, behind a checkpoint is recovered (SDK-IP2)', async () => {
    for (const mode of ['drop', 'tamper'] as const) {
      const { chain, t } = await setup();
      const a = await t.wallet(alice);
      depositTo(chain, (await a.address(0)).address, 5n);
      chain.mine(1500);
      chain.onceEvents = (evs) =>
        mode === 'drop'
          ? evs.filter((e) => e.keys[0] !== SEL.NotePublished)
          : evs.map((e) => (e.keys[0] === SEL.NotePublished ? { ...e, data: [...e.data.slice(0, 13), '0x1', ...e.data.slice(14)] } : e));
      const first = await a.sync();
      expect(first.complete).toBe(false);
      const second = await a.sync();
      expect(second.complete).toBe(true);
      expect(second.balances).toMatchObject([{ unspent: 5n }]);
    }
  }, 60_000);

  test('conflicting and foreign events', async () => {
    const { chain, t } = await setup();
    const a = await t.wallet(alice);
    const aAddr = (await a.address(0)).address;
    depositTo(chain, aAddr, 5n);
    chain.mine(3);
    const note = JSON.parse(wasm.note_for(aAddr, TOKEN, '7', SEPOLIA.chainId, chain.pool.pool));
    chain.inject({ from_address: chain.pool.pool, keys: [SEL.NotePublished], data: ['0x0', '0x9', ...note.commitment.map((x: number) => '0x' + x.toString(16)), note.delivery, '0xa', ...note.ciphertext] });
    let r = await a.sync();
    expect(r.complete).toBe(false);
    expect(r.problems.join()).toMatch(/conflicting events for leaf 0/);
    await expect(a.transfer(TOKEN, 1n, aAddr)).rejects.toThrow(/incomplete_sync/);
    const { chain: c2, t: t2 } = await setup();
    const a2 = await t2.wallet(alice);
    const forged = JSON.parse(wasm.note_for((await a2.address(0)).address, TOKEN, '9', SEPOLIA.chainId, c2.pool.pool));
    c2.inject({ from_address: '0x1234', keys: [SEL.NotePublished], data: ['0x0', '0x9', ...forged.commitment.map((x: number) => '0x' + x.toString(16)), forged.delivery, '0xa', ...forged.ciphertext] });
    r = await a2.sync();
    expect(r.balances).toEqual([]);
    expect(r.complete).toBe(true);
  }, 60_000);
});

describe('records', () => {
  test('a left record locks its notes until 512 leaves (256 two-output spends) bury its root', async () => {
    const { chain, t } = await setup();
    const a = await t.wallet(alice);
    const aAddr = (await a.address(0)).address;
    depositTo(chain, aAddr, 10n);
    chain.mine(12);
    await a.sync();
    const spend = await a.transfer(TOKEN, 3n, aAddr);
    await leave(a, spend.id);
    await expect(a.transfer(TOKEN, 1n, aAddr)).rejects.toThrow(/insufficient_notes/);
    chain.noise2(255);
    chain.mine(12);
    await a.sync();
    expect((await spend.record()).stage).not.toBe('dead');
    chain.noise2(1);
    chain.mine(3);
    await a.sync();
    expect((await spend.record()).stage).not.toBe('dead');
    chain.mine(10);
    await a.sync();
    expect((await spend.record()).stage).toBe('dead');
    expect((await (await a.transfer(TOKEN, 1n, aAddr)).plan()).inputs.length).toBe(1);
  }, 120_000);

  test('a superseded plan cannot proceed; a second companion for a note is refused (SDK-IP5)', async () => {
    const { chain, t } = await setup();
    const a = await t.wallet(alice);
    const aAddr = (await a.address(0)).address;
    depositTo(chain, aAddr, 10n);
    chain.mine(12);
    const s1 = await a.transfer(TOKEN, 3n, aAddr);
    const s2 = await a.transfer(TOKEN, 4n, aAddr);
    expect((await s1.record()).stage).toBe('dead');
    await expect(s1.prove()).rejects.toThrow(/record_closed/);
    await leave(a, s2.id);
    const other = JSON.parse(JSON.stringify(await s1.record()));
    other.plan.companion.rho[0] = (other.plan.companion.rho[0] + 1) % 2147483647;
    await expect(a.leaving(other)).rejects.toThrow(/companion_mismatch/);
    // A re-plan of the left record reuses its companion.
    const s3 = await a.replan(s2.id, { kind: 'transfer', asset: TOKEN, amount: '5', to: aAddr });
    expect((await s3.plan()).companion).toEqual((await s2.record()).attempts[0]!.plan.companion);
    // Zero is refused on a re-plan too.
    await expect(a.replan(s2.id, { kind: 'transfer', asset: TOKEN, amount: '0', to: aAddr })).rejects.toThrow(/zero/);
  }, 60_000);
});

describe('deposits, withdrawals and keys', () => {
  test('deposits: calldata, confirmation, another pool refused; ERC1155 recipients', async () => {
    const { chain, t } = await setup();
    const a = await t.wallet(alice);
    const account = chain.account();
    const d = await a.deposit(account, { asset: { standard: 20, contract: TOKEN }, amount: 25n });
    expect(d.confirmed).toBe(true);
    const calls = (chain.sent[0] as any).calls;
    expect(calls.map((c: any) => c.entrypoint)).toEqual(['approve', 'deposit']);
    expect(calls[1].calldata.length).toBe(23);
    const other = JSON.parse(wasm.account(bob, SEPOLIA.chainId, '0x1234', 0, 0)).address;
    await expect(a.deposit(account, { asset: { standard: 20, contract: TOKEN }, amount: 1n, to: other })).rejects.toThrow(/wrong_pool/);
    const multi = '0x445558d8ce71b9f6c55687821e7ed7c5081edf69fd0a3c44775e36c3d40b32a';
    const d2 = await a.deposit(account, { asset: { standard: 1155, contract: multi, id: 7n }, amount: 300n });
    expect(d2.confirmed).toBe(true);
    chain.mine(12);
    const bal = (await a.sync()).balances.find((x) => typeof x.kind === 'object');
    expect(bal).toMatchObject({ unspent: 300n });
    chain.supports.set('0xdead', false);
    await expect(a.withdraw(bal!.asset, 300n, '0xdead')).rejects.toThrow(/recipient/);
    expect((await (await a.withdraw(bal!.asset, 300n, '0xa11ce')).plan()).withdrawal_amount).toBe('300');
  }, 60_000);

  test('gap limit: issuance, and recovery beyond the first gap', async () => {
    const { chain, t } = await setup();
    const a = await t.wallet(alice);
    for (let i = 0; i <= 3; i++) await a.address(i);
    await expect(a.address(4)).rejects.toThrow(/gap_limit/);
    const at = (i: number) => JSON.parse(wasm.account(alice, SEPOLIA.chainId, chain.pool.pool, i, i)).address;
    depositTo(chain, at(2), 2n);
    depositTo(chain, at(5), 5n);
    chain.mine(12);
    const fresh = await (await Templar.connect({ provider: chain.provider(), network: SEPOLIA, kv: new MemoryKV() })).wallet(alice);
    const r = await fresh.sync();
    expect(r.balances).toMatchObject([{ unspent: 7n, notes: 2 }]);
    await fresh.address(8);
  }, 60_000);

  test('addresses, mnemonic and viewing keys', async () => {
    const { t } = await setup();
    const words = Templar.mnemonic(alice);
    expect(words.split(' ').length).toBe(24);
    expect(Templar.seedFromMnemonic(words)).toEqual(alice);
    const a = await t.wallet(alice);
    const addr = await a.address(0);
    expect(addr.address.startsWith('templarsep1')).toBe(true);
    expect(addr.fingerprint).toMatch(/^[0-9a-f]{4}(-[0-9a-f]{4}){4}$/);
    const ivk = a.exportViewingKey(0, false);
    expect(JSON.parse(wasm.viewing_key_import(ivk, addr.address)).full).toBe(false);
    expect(() => wasm.address_decode(ivk)).toThrow(/wrong prefix/);
  });

  test('fee bounds are a fixed function of the raw estimate', () => {
    const e = { l1_gas_consumed: '0x0', l1_gas_price: '0x10', l1_data_gas_consumed: '0x80', l1_data_gas_price: '0x3', l2_gas_consumed: '0x8583b00', l2_gas_price: '0x2', overall_fee: '0x1' };
    const { bounds, maxFee } = boundsFrom(e);
    expect(bounds.l2_gas).toEqual({ max_amount: (0x8583b00n * 3n + 1n) / 2n, max_price_per_unit: 4n });
    expect(maxFee).toBe(bounds.l2_gas.max_amount * 4n + 192n * 6n);
  });

  test('every WASM export refuses malformed input with an error, never a trap (SDK-IM3)', () => {
    const bad = ['', '{', 'null', '[]', '"x"', '0x', '0x' + 'f'.repeat(70), '{"chain":"0x1"}'];
    const bytes = [new Uint8Array(0), new Uint8Array(31), new Uint8Array(33)];
    const fns: [string, () => unknown][] = [];
    for (const s of bad) {
      fns.push(['seed_from_mnemonic', () => wasm.seed_from_mnemonic(s)]);
      fns.push(['address_decode', () => wasm.address_decode(s)]);
      fns.push(['viewing_key_import', () => wasm.viewing_key_import(s, s)]);
      fns.push(['asset_id', () => wasm.asset_id(721, s, s, s)]);
      fns.push(['note_for', () => wasm.note_for(s, s, s, s, s)]);
      fns.push(['scan', () => wasm.scan(alice, s)]);
      fns.push(['prove_spend', () => wasm.prove_spend(alice, s)]);
      fns.push(['companion_nullifier', () => wasm.companion_nullifier(s, s, s, s)]);
      fns.push(['check_result', () => wasm.check_result(s, s, s, 0n)]);
      fns.push(['delivery_digest', () => wasm.delivery_digest(s)]);
      fns.push(['pool_commitment', () => wasm.pool_commitment(s, s, s, s, s)]);
      if (s !== '[]') fns.push(['tree.append', () => new wasm.Tree().append(s)]);
      fns.push(['plan_spend', () => wasm.plan_spend(alice, s, new wasm.Tree())]);
      fns.push(['store_open', () => wasm.store_open(alice, s, s, s, s, new Uint8Array(3))]);
    }
    for (const b of bytes) {
      fns.push(['mnemonic_from_seed', () => wasm.mnemonic_from_seed(b)]);
      fns.push(['account', () => wasm.account(b, SEPOLIA.chainId, '0x1', 0, 0)]);
      fns.push(['OhttpRequest', () => new wasm.OhttpRequest(b, 'GET', '/', b)]);
    }
    for (const [name, f] of fns) {
      let threw: unknown = undefined;
      try {
        f();
      } catch (e) {
        threw = e;
      }
      expect(threw, name).toBeDefined();
      expect(typeof threw === 'string' ? JSON.parse(threw).code : String(threw), name).toBeTruthy();
    }
    expect(JSON.parse(wasm.account(alice, SEPOLIA.chainId, '0x1', 0, 0)).address).toMatch(/^templarsep1/);
    expect(new TemplarError('x', 'y').code).toBe('x');
  });
});

describe('stores', () => {
  test('FileKV round trip and stale-lock recovery; IndexedDB round trip', async () => {
    const dir = await mkdtemp(`${tmpdir()}/templar-kv-`);
    const kv = new FileKV(dir);
    await kv.put('a', new Uint8Array([1, 2]));
    expect(await kv.get('a')).toEqual(new Uint8Array([1, 2]));
    await writeFile(`${dir}/.lock-x`, '999999999');
    expect(await kv.lock('x', async () => 5)).toBe(5);
    expect((await readdir(dir)).filter((f) => f.startsWith('.lock'))).toEqual([]);
    await kv.delete('a');
    expect(await kv.get('a')).toBeUndefined();
    const idb = new IndexedDBKV('templar-test');
    await idb.put('k', new Uint8Array([3]));
    expect(await idb.get('k')).toEqual(new Uint8Array([3]));
    await idb.delete('k');
    expect(await idb.get('k')).toBeUndefined();
  });
});
