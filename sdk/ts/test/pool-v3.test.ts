// Pool V3 in the TypeScript layer (docs/account-bound-note-spec.md §8–§10): the pinned parameters
// and verifier kind, pending proposals and the deposit rule, and an R0 V5 full withdrawal end to
// end: a stale plan, the V5 proof (every spend ordinary, ADR-0027), the free-withdrawal payment, a
// server publishing other parameters, the job body, a server returning another pool call,
// submission and the expiry rule.
import 'fake-indexeddb/auto';
import { readFileSync } from 'node:fs';
import { beforeAll, describe, expect, test } from 'vitest';

import * as wasm from '../wasm/templar.js';
import initTest, * as twasm from '../wasm-test/templar_test.js';
import { KIND_R0, MemoryKV, SEPOLIA, Templar, canon, loadCore, pinsOf, type NetworkConstants } from '../dist/index.js';
import { MockChain, MockProver } from './mockchain.js';

const TOKEN = '0x39f5916e2110601b44d7ed0f4c033dd684f99b945df2cce8356c73dc0c805b8';
/** The R0 V5 client circuit (the cairo-r5 bridge's build record). */
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

async function setup(network: NetworkConstants = V3) {
  const chain = new MockChain(network.pools[0]!);
  const kv = new MemoryKV();
  const t = await Templar.connect({ provider: chain.provider(), network, kv });
  return { chain, kv, t };
}

function depositTo(chain: MockChain, address: string, amount: bigint) {
  chain.deposit(JSON.parse(wasm.note_for(address, TOKEN, amount.toString(), V3.chainId, POOL.pool)), TOKEN, amount);
}

function mockProver(chain: MockChain) {
  const pins = JSON.stringify(pinsOf(V3, POOL));
  return new MockProver(chain, (binding, base, hash) => JSON.parse(twasm.test_expected_facts(pins, binding, BigInt(base), hash)));
}

beforeAll(async () => {
  await loadCore();
  await initTest({ module_or_path: readFileSync(new URL('../wasm-test/templar_test_bg.wasm', import.meta.url)) });
});

describe('pool V3', () => {
  test('pinned parameters, the verifier by kind, proposals and the deposit rule', async () => {
    const { chain, t } = await setup();
    expect(chain.calls.some((c) => c.method === 'callContract' && c.args[1] === 'get_parameters')).toBe(true);
    const gv = chain.calls.find((c) => c.method === 'callContract' && c.args[1] === 'get_verifier')!;
    expect(gv.args[2]).toEqual([KIND_R0]);
    // Parameters other than the pinned ones are refused, the timelock included (AB-SP15).
    for (const params of [['0x5dc', '0x32', '0x1000', '0x15180'], ['0x5dc', '0x64', '0x1000', '0x1']]) {
      const other = new MockChain(POOL);
      other.parameters = params;
      await expect(Templar.connect({ provider: other.provider(), network: V3, kv: new MemoryKV() })).rejects.toThrow(/pin_mismatch/);
    }
    // On SN_MAIN, a timelock under 7 days is refused even when pinned.
    const MAIN = { ...V3, chainId: '0x534e5f4d41494e' };
    const onMain = new MockChain(POOL);
    const mainProvider = { ...onMain.provider(), getChainId: async () => MAIN.chainId };
    await expect(Templar.connect({ provider: mainProvider as any, network: MAIN, kv: new MemoryKV() })).rejects.toThrow(/mainnet floors/);

    const w = await t.wallet(new Uint8Array(32).fill(0xc3));
    expect(await w.proposals()).toEqual([]);
    const deposit = () => w.deposit(chain.account(), { asset: { standard: 20, contract: TOKEN }, amount: 50n });
    // A pending verifier change stops deposits (AB-PV2), before anything is sent.
    chain.proposals.set(KIND_R0, ['0xbad', 1_900_000_000]);
    expect(await w.proposals()).toMatchObject([{ key: KIND_R0, value: '0xbad', eta: 1_900_000_000, lapsesAt: 1_900_086_400, lapsed: false, verifier: true }]);
    await expect(deposit()).rejects.toThrow(/verifier_change_pending/);
    expect(chain.sent.length).toBe(0);
    // Past eta + T it lapses: shown, but it blocks nothing (AB-SP15).
    chain.timestamp = 1_900_086_401;
    expect(await w.proposals()).toMatchObject([{ key: KIND_R0, lapsed: true }]);
    expect((await deposit()).confirmed).toBe(true);
    chain.timestamp = 1_800_000_000;
    // A shadow-class change is shown, but does not stop deposits.
    chain.proposals.delete(KIND_R0);
    chain.proposals.set('0xc1a55', ['0x1', 1_900_000_000]);
    expect(await w.proposals(['0xc1a55'])).toMatchObject([{ key: '0xc1a55', verifier: false }]);
    const d = await deposit();
    expect(d.confirmed).toBe(true);
    // Only a 32-byte seed opens a wallet: there are no bound wallets (ADR-0027).
    await expect(t.wallet(new Uint8Array(60))).rejects.toThrow(/bad_seed/);
  }, 60_000);
});

describe('R0 V5 spends', () => {
  test('a full withdrawal: stale plan, prove, free payment, wrap, submit, expiry', async () => {
    const { chain, t } = await setup();
    const w = await t.wallet(new Uint8Array(32).fill(0xa5));
    const addr = (await w.address(0)).address;
    depositTo(chain, addr, 1000n);
    chain.mine(12);
    expect((await w.sync()).balances).toMatchObject([{ asset: TOKEN, unspent: 1000n, spendable: 1000n }]);

    // A plan the chain has moved past can no longer land: the core refuses to prove it (AB-SM4).
    let spend = await w.withdraw(TOKEN, 1000n, '0xb0b');
    chain.mine(1601);
    await expect(spend.prove()).rejects.toThrow(/stale_plan/);
    spend = await w.withdraw(TOKEN, 1000n, '0xb0b');
    const plan = await spend.plan();
    expect(plan.version).toBe('v5');
    expect(plan.valid_until).toBe(Math.ceil((chain.latest + 1500) / 100) * 100);
    expect('bound_account' in plan).toBe(false);

    const proved = await spend.prove();
    expect(proved.circuit_hash).toEqual(V5_CIRCUIT);
    // Every spend is ordinary: the statement names no account (ADR-0027).
    expect(canon(proved.statement.account!)).toBe('0x0');

    // A full withdrawal is free: both outputs open to zero-value notes.
    const payment = (await spend.freeWithdrawalPayment()) as { free_full_withdrawal: { openings: number[][] } };
    expect(payment.free_full_withdrawal.openings.map((o) => o.length)).toEqual([9, 9]);

    // A prover server publishing other pool parameters is refused (AB-SP19).
    const liar = mockProver(chain);
    liar.poolParameters = { expiry_window: 1500, quantum: 100, root_window: 4096, timelock: 1 };
    await expect(t.prover({ url: 'http://q', fetch: liar.fetch as any }).info()).rejects.toThrow(/prover_mismatch/);

    // A server that returns another pool call is refused; the honest result is then taken.
    const prover = mockProver(chain);
    prover.binding = proved.binding;
    const client = t.prover({ url: 'http://p', fetch: prover.fetch as any });
    prover.poolCall = (c: any) => ({ ...c, calldata: c.calldata.map((x: string, i: number) => (i === 5 ? '0x1' : x)) });
    await expect(spend.wrap(client, { url: 'http://p', payment })).rejects.toThrow(/bad_result/);
    prover.poolCall = undefined;
    const win = await spend.wrap(client, { url: 'http://p', payment });
    expect(prover.bodies.length).toBe(1);
    const body = JSON.parse(prover.bodies[0]!);
    expect(body).toMatchObject({ relation: 'r5', payment, pool_call: { entry_point: 'apply_spend', calldata: proved.calldata } });
    // A job carries no salt and no signature (the server refuses one that does).
    expect('salt' in body || 'signature' in body).toBe(false);
    expect(canon(body.statement.account)).toBe('0x0');
    const base = chain.latest - 1;
    expect(win.valid_until).toBe(Math.min(plan.valid_until!, base + POOL.maxProofAge));

    chain.mine(12);
    const sent = await spend.submit(chain.account('0xacc'), { confirmFee: () => true });
    expect(sent.transactionHash).toBe('0xbeef');
    expect(sent.linkable).toBe(true);

    // Near the statement's own expiry, another job cannot help: wrap asks for a re-plan (AB-SP18).
    chain.mine(plan.valid_until! - chain.latest - 10);
    await expect(spend.wrap(client, { url: 'http://p', payment })).rejects.toThrow(/replan/);
    // The transaction never lands: past `valid_until` by DEPTH blocks the record is dead.
    chain.mine(plan.valid_until! - chain.latest + 9);
    await w.sync();
    expect((await spend.record()).stage).not.toBe('dead');
    chain.mine(1);
    await w.sync();
    expect(await spend.record()).toMatchObject({ stage: 'dead', closed: 'expired' });
  }, 300_000);

  test('a refused body is rebuilt with new payment; a re-plan sends its own statement', async () => {
    const { chain, t } = await setup();
    const w = await t.wallet(new Uint8Array(32).fill(0xb6));
    depositTo(chain, (await w.address(0)).address, 500n);
    chain.mine(12);
    await w.sync();
    const spend = await w.withdraw(TOKEN, 500n, '0xb0b');
    const proved = await spend.prove();
    const prover = mockProver(chain);
    prover.binding = proved.binding;
    // The server refuses the payment (402): the stored body is dropped, and the next wrap builds a
    // new one with new payment; the statement and proof stay (AB-SP18).
    const fetch402 = async (u: string | URL, i?: { method?: string; body?: string }) =>
      String(u).endsWith('/v1/jobs') && i?.method === 'POST' ? new Response(JSON.stringify({ error: 'ticket spent' }), { status: 402 }) : prover.fetch(u, i);
    await expect(spend.wrap(t.prover({ url: 'http://p', fetch: fetch402 as any }), { url: 'http://p', payment: { tickets: ['old'] } })).rejects.toThrow(/prover_payment/);
    expect((await spend.record()).server).toBeUndefined();
    await spend.wrap(t.prover({ url: 'http://p', fetch: prover.fetch as any }), { url: 'http://p', payment: { tickets: ['new'] } });
    const sent = JSON.parse(prover.bodies.at(-1)!);
    expect(sent.payment).toEqual({ tickets: ['new'] });
    expect(sent.statement).toEqual(proved.statement);
    // A re-plan proves a new statement, which its own body carries.
    const again = await w.replan(spend.id, { kind: 'withdraw', asset: TOKEN, amount: '500', recipient: '0xb0c' });
    const reproved = await again.prove();
    expect(reproved.binding).not.toBe(proved.binding);
    prover.binding = reproved.binding;
    await again.wrap(t.prover({ url: 'http://p', fetch: prover.fetch as any }), { url: 'http://p', payment: { tickets: ['next'] } });
    expect(JSON.parse(prover.bodies.at(-1)!).statement.withdrawal_recipient).toBe('0xb0c');
  }, 300_000);

  test('a partial withdrawal has no free payment', async () => {
    const { chain, t } = await setup();
    const w = await t.wallet(new Uint8Array(32).fill(0xd4));
    depositTo(chain, (await w.address(0)).address, 10n);
    chain.mine(12);
    await w.sync();
    const spend = await w.withdraw(TOKEN, 4n, '0xb0b');
    expect(await spend.freeWithdrawalPayment()).toBeUndefined();
  }, 60_000);
});

test('Sepolia pins pool V3 as the active pool, with pool V2 kept as history', () => {
  const [v2, v3] = SEPOLIA.pools;
  expect(SEPOLIA.pools.length).toBe(2);
  expect(v2!.version ?? 'v4').toBe('v4');
  expect(v3!.version).toBe('v5');
  expect(v3!.accountTag).toBe('TMPZR0_PAYMENT_V5');
  expect(v3!.maxProofAge).toBe(1024);
  const { expiryWindow: E, quantum: Q, rootWindow: W, timelock: T } = v3!.parameters!;
  expect(W).toBeGreaterThanOrEqual(E + Q);
  expect(T).toBeGreaterThan(0);
  expect(v3!.deploymentBlock).toBeGreaterThan(v2!.deploymentBlock);
});
