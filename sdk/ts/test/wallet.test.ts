// The TypeScript layer against a mock pool (spec §12): sync and receiving, a hidden transfer
// proved in a worker, the network-trace privacy rules, reorgs, conflicting events, the record
// rules and store encryption.
import { beforeAll, describe, expect, test } from 'vitest';

import * as wasm from '../wasm/templar.js';
import { MemoryKV, SEPOLIA, Templar, TemplarError, boundsFrom, loadCore } from '../dist/index.js';
import { MockChain, SEL } from './mockchain.js';

const TOKEN = '0x39f5916e2110601b44d7ed0f4c033dd684f99b945df2cce8356c73dc0c805b8';
const alice = new Uint8Array(32).fill(0xa1);
const bob = new Uint8Array(32).fill(0xb0);

async function setup() {
  const chain = new MockChain();
  const kv = new MemoryKV();
  const t = await Templar.connect({ provider: chain.provider(), network: SEPOLIA, kv });
  return { chain, kv, t };
}

function depositTo(chain: MockChain, address: string, amount: bigint) {
  const note = JSON.parse(wasm.note_for(address, TOKEN, amount.toString()));
  chain.deposit(note, TOKEN, amount);
}

beforeAll(async () => {
  await loadCore();
});

describe('receiving and spending', () => {
  test('sync, hidden transfer, both parties receive; only bulk reads', async () => {
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
    expect(r.complete).toBe(true);
    expect(r.balances).toMatchObject([{ asset: TOKEN, unspent: 1000n, spendable: 1000n, notes: 1 }]);

    chain.calls = [];
    const spend = await a.transfer(TOKEN, 600n, bAddr);
    expect(spend.plan.inputs.length).toBe(1);
    const proved = await spend.prove();
    expect(proved.statement.token_out).toBe('0x0');
    chain.applySpend(proved, spend.plan);
    chain.mine(12);

    expect((await b.sync()).balances).toMatchObject([{ unspent: 600n }]);
    r = await a.sync();
    expect(r.balances).toMatchObject([{ unspent: 400n }]);
    expect((await a.record(spend.record.id))!.stage).toBe('settled');

    // Network trace (spec §12.5): events only by pool address and every selector; calls only to
    // pinned constants, the verifier, and the leaf count and root.
    const selectors = Object.values(SEL).map((s) => BigInt(s)).sort();
    for (const c of chain.calls) {
      if (c.method === 'getEvents') {
        const f = c.args[0] as { address: string; keys: string[][] };
        expect(BigInt(f.address)).toBe(BigInt(chain.pool.pool));
        expect(f.keys.length).toBe(1);
        expect(f.keys[0]!.map((k) => BigInt(k)).sort()).toEqual(selectors);
      } else if (c.method === 'callContract') {
        expect(['get_verifier', 'get_leaf_count', 'get_root']).toContain(c.args[1]);
      } else {
        expect(['getBlockLatestAccepted', 'getBlockWithTxHashes']).toContain(c.method);
      }
    }
    // Checkpoint reads are block numbers on the fixed grid, never a note's block.
    for (const c of chain.calls.filter((c) => c.method === 'getBlockWithTxHashes')) expect(((c.args[0] as number) + 1) % 1000).toBe(0);

    // The store holds no plaintext: neither the token nor an amount appears in any record.
    for (const v of kv.raw().values()) {
      const s = Buffer.from(v).toString('latin1');
      expect(s.includes('39f5916e')).toBe(false);
      expect(s.includes('"600"')).toBe(false);
    }
  }, 180_000);
});

describe('sync faults', () => {
  test('a reorg rolls back and resyncs', async () => {
    const { chain, t } = await setup();
    const a = await t.wallet(alice);
    const aAddr = (await a.address(0)).address;
    chain.mine(1200); // cross a checkpoint
    depositTo(chain, aAddr, 5n);
    chain.mine(12);
    expect((await a.sync()).balances).toMatchObject([{ unspent: 5n }]);
    chain.reorg(20); // the deposit block is replaced
    const r = await a.sync();
    expect(r.complete).toBe(true);
    expect(r.balances).toEqual([]);
  }, 60_000);

  test('a note found before a checkpoint survives later syncs and reorgs after it', async () => {
    const { chain, t } = await setup();
    const a = await t.wallet(alice);
    const aAddr = (await a.address(0)).address;
    depositTo(chain, aAddr, 7n);
    chain.mine(1500); // the first sync creates a checkpoint after the deposit
    expect((await a.sync()).balances).toMatchObject([{ unspent: 7n }]);
    chain.mine(5);
    expect((await a.sync()).balances).toMatchObject([{ unspent: 7n }]);
    chain.reorg(100);
    const r = await a.sync();
    expect(r.complete).toBe(true);
    expect(r.balances).toMatchObject([{ unspent: 7n }]);
  }, 60_000);

  test('conflicting and missing events make the sync incomplete', async () => {
    const { chain, t } = await setup();
    const a = await t.wallet(alice);
    const aAddr = (await a.address(0)).address;
    depositTo(chain, aAddr, 5n);
    chain.mine(3);
    // A second event for leaf 0 with another commitment.
    const note = JSON.parse(wasm.note_for(aAddr, TOKEN, '7'));
    chain.inject({ from_address: chain.pool.pool, keys: [SEL.NotePublished], data: ['0x0', '0x9', ...note.commitment.map((x: number) => '0x' + x.toString(16)), note.delivery, '0xa', ...note.ciphertext] });
    let r = await a.sync();
    expect(r.complete).toBe(false);
    expect(r.problems.join()).toMatch(/conflicting events for leaf 0/);
    // An event from another contract with the same selector is ignored, not credited.
    const { chain: c2, t: t2 } = await setup();
    const a2 = await t2.wallet(alice);
    const addr2 = (await a2.address(0)).address;
    const forged = JSON.parse(wasm.note_for(addr2, TOKEN, '9'));
    c2.inject({ from_address: '0x1234', keys: [SEL.NotePublished], data: ['0x0', '0x9', ...forged.commitment.map((x: number) => '0x' + x.toString(16)), forged.delivery, '0xa', ...forged.ciphertext] });
    r = await a2.sync();
    expect(r.balances).toEqual([]);
    expect(r.complete).toBe(true);
    // Spending on an incomplete sync is refused.
    await expect(a.transfer(TOKEN, 1n, aAddr)).rejects.toThrow(/incomplete_sync/);
  }, 60_000);
});

describe('records and keys', () => {
  test('a record that left the wallet locks its notes until its root is evicted', async () => {
    const { chain, t } = await setup();
    const a = await t.wallet(alice);
    const aAddr = (await a.address(0)).address;
    depositTo(chain, aAddr, 10n);
    chain.mine(12);
    await a.sync();
    const spend = await a.transfer(TOKEN, 3n, aAddr);
    // Its statement leaves the wallet (as when sent to a prover server).
    await a.leaving(spend.record);
    // The note is locked: another spend cannot select it...
    await expect(a.transfer(TOKEN, 1n, aAddr)).rejects.toThrow(/insufficient_notes/);
    // ...but the record can be re-planned with the same input.
    const again = await a.replan(spend.record.id, { kind: 'transfer', asset: TOKEN, amount: '4', to: aAddr });
    expect(again.plan.inputs.map((n) => n.index)).toEqual(spend.plan.inputs.map((n) => n.index));
    // The same companion (sticky, SDK-M17).
    expect(again.plan.companion).toEqual(spend.plan.companion);
    // 256 two-leaf insertions would not evict; 512 leaves do, once buried.
    chain.noise(511);
    chain.mine(12);
    await a.sync();
    expect((await a.record(spend.record.id))!.stage).not.toBe('dead');
    chain.noise(1);
    chain.mine(3);
    await a.sync();
    expect((await a.record(spend.record.id))!.stage).not.toBe('dead');
    chain.mine(10);
    await a.sync();
    expect((await a.record(spend.record.id))!.stage).toBe('dead');
    expect((await a.transfer(TOKEN, 1n, aAddr)).plan.inputs.length).toBe(1);
  }, 120_000);

  test('addresses, mnemonic, gap limit and viewing keys', async () => {
    const { t } = await setup();
    const words = Templar.mnemonic(alice);
    expect(words.split(' ').length).toBe(24);
    expect(Templar.seedFromMnemonic(words)).toEqual(alice);
    const a = await t.wallet(alice);
    const addr = await a.address(0);
    expect(addr.address.startsWith('templarsep1')).toBe(true);
    expect(addr.fingerprint).toMatch(/^[0-9a-f]{4}(-[0-9a-f]{4}){4}$/);
    await expect(a.address(4)).rejects.toThrow(/gap_limit/);
    await a.address(3);
    const ivk = a.exportViewingKey(0, false);
    expect(JSON.parse(wasm.viewing_key_import(ivk, addr.address)).full).toBe(false);
    expect(() => wasm.viewing_key_import(ivk, (a as any).exportViewingKey(1, false))).toThrow();
    expect(() => wasm.address_decode(ivk)).toThrow(/wrong prefix/);
  });

  test('fee bounds are a fixed function of the raw estimate', () => {
    const e = { l1_gas_consumed: '0x0', l1_gas_price: '0x10', l1_data_gas_consumed: '0x80', l1_data_gas_price: '0x3', l2_gas_consumed: '0x8583b00', l2_gas_price: '0x2', overall_fee: '0x1' };
    const { bounds, maxFee } = boundsFrom(e);
    expect(bounds.l2_gas).toEqual({ max_amount: (0x8583b00n * 3n + 1n) / 2n, max_price_per_unit: 4n });
    expect(bounds.l1_data_gas.max_amount).toBe(192n);
    expect(maxFee).toBe(bounds.l2_gas.max_amount * 4n + 192n * 6n);
  });

  test('errors carry their core code', () => {
    try {
      wasm.address_decode('templarsep1qqq');
    } catch (e) {
      expect(typeof e).toBe('string');
    }
    expect(new TemplarError('x', 'y').code).toBe('x');
  });
});
