// R0 V6 and routing adapters in the TypeScript layer (docs/pool-v3-spec.md §10): generations and
// route pins read through the adapter's views, the cutover's deposit rules (a pinned verifier
// proposal is a notice; any unpinned verifier or route change refuses), a V6 spend end to end with
// the r6 body and the route key, route-pin failures, a V5 record across the cutover, and a prover
// server whose r6 route differs.
import 'fake-indexeddb/auto';
import { readFileSync } from 'node:fs';
import { beforeAll, describe, expect, test } from 'vitest';

import * as wasm from '../wasm/templar.js';
import initTest, * as twasm from '../wasm-test/templar_test.js';
import {
  KIND_R0, MemoryKV, SEPOLIA, Templar, canon, decodeRouteProposals, decodeRoutes, loadCore, routeFelts, routeOfFelts, routePins,
  type Generation, type NetworkConstants, type Route,
} from '../dist/index.js';
import { MockChain, MockProver } from './mockchain.js';

const TOKEN = '0x39f5916e2110601b44d7ed0f4c033dd684f99b945df2cce8356c73dc0c805b8';
const V5_CIRCUIT = [1903585510, 1708577544, 3915427995, 3101166941, 461832048, 2805149134, 1077751030, 1205594117];
/** The R0 V6 client circuit (`client-port/results/stwo-client-r6/trusted-config.json`). */
const V6_CIRCUIT = [2010035999, 4123906337, 3936982050, 2269257694, 3115244238, 1536739351, 29337086, 2871661834];
const OS = SEPOLIA.pools[0]!.osProgram;
const ROUTE: Route = { statement: '0x5a7e06', statementClass: '0x5a7e06c1a5', accountTag: 'TMPZR0_PAYMENT_V6', osProgram: OS, maxProofAge: 1024 };
const PLANNED: Route = { ...ROUTE, statement: '0x5a7e07' };
const STRANGER: Route = { ...ROUTE, statement: '0x5a7e08' };
const V6: Generation = {
  relation: 'r6', version: 'v6', adapter: '0xada6', adapterClass: '0xada6c1a5', routing: true, circuitHash: V6_CIRCUIT,
  configHash: SEPOLIA.pools[0]!.configHash, routes: [ROUTE, PLANNED], routeStates: [[ROUTE.statement], [ROUTE.statement, PLANNED.statement]],
  plannedProposals: [{ statement: PLANNED.statement, route: PLANNED }], primary: ROUTE.statement,
};
const V3: NetworkConstants = {
  ...SEPOLIA,
  pools: [
    {
      ...SEPOLIA.pools[0]!,
      pool: '0x7e57b301', version: 'v5', parameters: { expiryWindow: 1500, quantum: 100, rootWindow: 4096, timelock: 86400 },
      adapter: '0xada5', adapterClass: '0xada5c1a5', statement: '0x5a7e05', statementClass: '0x5a7e05c1a5', accountTag: 'TMPZR0_PAYMENT_V5',
      maxProofAge: 1024, circuitHash: V5_CIRCUIT, generations: { r0: [V6] },
    },
  ],
};
const POOL = V3.pools[0]!;

/** Pool V3 with the V5 adapter active and the V6 routing adapter deployed beside it. */
function chainWithV6(): MockChain {
  const chain = new MockChain(POOL);
  chain.adapters.set(canon(V6.adapter), { class: V6.adapterClass, pool: POOL.pool, kind: 'R0', routes: [ROUTE], proposals: [] });
  for (const r of [ROUTE, PLANNED, STRANGER]) chain.classes.set(canon(r.statement), r.statementClass);
  return chain;
}

const switchToV6 = (chain: MockChain) => chain.verifiers.set(KIND_R0, V6.adapter);

async function connect(chain: MockChain) {
  return Templar.connect({ provider: chain.provider(), network: V3, kv: new MemoryKV() });
}

function depositTo(chain: MockChain, address: string, amount: bigint) {
  chain.deposit(JSON.parse(wasm.note_for(address, TOKEN, amount.toString(), V3.chainId, POOL.pool)), TOKEN, amount);
}

/** A dual-version server: r5 on the V5 adapter, r6 on the routing adapter with its route. */
function dualProver(chain: MockChain, route: Route = ROUTE) {
  const pins = JSON.stringify(routePins(V3, POOL, V6, ROUTE.statement));
  const legacy = JSON.stringify(routePins(V3, POOL, { ...V6, routing: false, circuitHash: V5_CIRCUIT, routes: [{ statement: POOL.statement, statementClass: POOL.statementClass, accountTag: POOL.accountTag, osProgram: OS, maxProofAge: POOL.maxProofAge }], primary: POOL.statement }));
  const prover = new MockProver(chain, (binding, base, hash) => JSON.parse(twasm.test_expected_facts(prover.route ? pins : legacy, binding, BigInt(base), hash)));
  prover.relations = [
    { name: 'r5', statement_account: POOL.statement, statement_class: POOL.statementClass, account_tag: POOL.accountTag, adapter: POOL.adapter, circuit_hash_u32_le: V5_CIRCUIT },
    {
      name: 'r6', statement_account: route.statement, statement_class: route.statementClass, account_tag: route.accountTag, adapter: V6.adapter,
      circuit_hash_u32_le: V6_CIRCUIT, adapter_class: V6.adapterClass, max_proof_age: route.maxProofAge,
      route: {
        statement: route.statement, statement_class: route.statementClass, account_tag: route.accountTag, os_program: route.osProgram,
        proof_version: 'PROOF2', proof_variant: 'VIRTUAL_SNOS', output_version: 'VIRTUAL_SNOS0', max_proof_age: route.maxProofAge,
      },
    },
  ];
  return prover;
}

beforeAll(async () => {
  await loadCore();
  await initTest({ module_or_path: readFileSync(new URL('../wasm-test/templar_test_bg.wasm', import.meta.url)) });
});

describe('R0 V6 and routing adapters', () => {
  test('the cutover: a pinned verifier proposal is a notice; unpinned verifier and route changes refuse deposits', async () => {
    const chain = chainWithV6();
    const t = await connect(chain);
    const w = await t.wallet(new Uint8Array(32).fill(0xc6));
    const deposit = () => w.deposit(chain.account(), { asset: { standard: 20, contract: TOKEN }, amount: 10n });
    expect((await deposit()).confirmed).toBe(true);
    // The planned cutover: R0 → the pinned V6 adapter, whose route set is a pinned state with
    // nothing pending. A notice, deposits stay open (PV3-8).
    chain.proposals.set(KIND_R0, [V6.adapter, 1_900_000_000]);
    const [notice] = await w.proposals();
    expect(notice).toMatchObject({ key: KIND_R0, value: canon(V6.adapter), verifier: true, pinned: true });
    expect((await deposit()).confirmed).toBe(true);
    // A pending route change on the proposed adapter makes it unpinned, and is itself an alarm.
    chain.adapters.get(canon(V6.adapter))!.proposals = [{ statement: STRANGER.statement, route: STRANGER, eta: 1_900_000_000 }];
    const pending = await w.proposals();
    expect(pending.find((p) => p.verifier)!.pinned).toBe(false);
    expect(pending.find((p) => p.route)).toMatchObject({ pinned: false, route: { adapter: canon(V6.adapter), statement: canon(STRANGER.statement) } });
    await expect(deposit()).rejects.toThrow(/verifier_change_pending/);
    // The planned route addition is pinned; the verifier proposal is still unpinned while it is pending.
    chain.adapters.get(canon(V6.adapter))!.proposals = [{ statement: PLANNED.statement, route: PLANNED, eta: 1_900_000_000 }];
    expect((await w.proposals()).find((p) => p.route)!.pinned).toBe(true);
    await expect(deposit()).rejects.toThrow(/verifier_change_pending/);
    chain.adapters.get(canon(V6.adapter))!.proposals = [];
    // A verifier proposal to an adapter this release does not pin refuses deposits.
    chain.proposals.set(KIND_R0, ['0xbad', 1_900_000_000]);
    await expect(deposit()).rejects.toThrow(/verifier_change_pending/);
    chain.proposals.delete(KIND_R0);
    // After the switch: the planned route addition on the active adapter is a notice; a removal of
    // the only route the SDK can use is not.
    switchToV6(chain);
    chain.adapters.get(canon(V6.adapter))!.proposals = [{ statement: PLANNED.statement, route: PLANNED, eta: 1_900_000_000 }];
    expect((await deposit()).confirmed).toBe(true);
    chain.adapters.get(canon(V6.adapter))!.proposals = [{ statement: ROUTE.statement, route: null, eta: 1_900_000_000 }];
    await expect(deposit()).rejects.toThrow(/verifier_change_pending/);
  }, 120_000);

  test('route pins: an unpinned route set, a changed route or adapter class is verifier_changed', async () => {
    const chain = chainWithV6();
    switchToV6(chain);
    await connect(chain);
    const ad = chain.adapters.get(canon(V6.adapter))!;
    // The planned state is pinned too.
    ad.routes = [ROUTE, PLANNED];
    await connect(chain);
    ad.routes = [ROUTE, STRANGER];
    await expect(connect(chain)).rejects.toThrow(/verifier_changed/);
    ad.routes = [{ ...ROUTE, maxProofAge: 999 }];
    await expect(connect(chain)).rejects.toThrow(/verifier_changed/);
    ad.routes = [ROUTE];
    chain.classes.set(canon(ROUTE.statement), '0x1');
    await expect(connect(chain)).rejects.toThrow(/verifier_changed/);
    chain.classes.set(canon(ROUTE.statement), ROUTE.statementClass);
    ad.class = '0x1';
    await expect(connect(chain)).rejects.toThrow(/verifier_changed/);
    ad.class = V6.adapterClass;
    ad.kind = 'P1';
    await expect(connect(chain)).rejects.toThrow(/verifier_changed/);
    ad.kind = 'R0';
    // A verifier this release does not pin at all.
    chain.verifiers.set(KIND_R0, '0xbad');
    await expect(connect(chain)).rejects.toThrow(/verifier_changed/);
  }, 60_000);

  test('a V6 spend after the switch: route pins, the r6 body, the route key, submission', async () => {
    const chain = chainWithV6();
    switchToV6(chain);
    const t = await connect(chain);
    const w = await t.wallet(new Uint8Array(32).fill(0xd6));
    depositTo(chain, (await w.address(0)).address, 1000n);
    chain.mine(12);
    await w.sync();
    const spend = await w.withdraw(TOKEN, 1000n, '0xb0b');
    const rec = await spend.record();
    expect(rec.plan.version).toBe('v6');
    expect(rec.adapter).toBe(canon(V6.adapter));
    const proved = await spend.prove();
    expect(proved.circuit_hash).toEqual(V6_CIRCUIT);
    expect('account' in proved.statement).toBe(false);
    const prover = dualProver(chain);
    prover.route = { statement: ROUTE.statement, maxProofAge: ROUTE.maxProofAge };
    prover.binding = proved.binding;
    const payment = (await spend.freeWithdrawalPayment())!;
    const win = await spend.wrap(t.prover({ url: 'http://p', fetch: prover.fetch as any }), { url: 'http://p', payment });
    const body = JSON.parse(prover.bodies.at(-1)!);
    expect(body.relation).toBe('r6');
    expect('account' in body.statement).toBe(false);
    expect((await spend.record()).result!.statement).toBe(ROUTE.statement);
    expect(win.valid_until).toBe(Math.min(rec.plan.valid_until!, chain.latest - 1 + ROUTE.maxProofAge));
    chain.mine(12);
    const sent = await spend.submit(chain.account('0xacc'), { confirmFee: () => true });
    expect(sent.transactionHash).toBe('0xbeef');
    // A result naming a route this release does not pin is refused.
    const spend2 = await (async () => {
      depositTo(chain, (await w.address(0)).address, 500n);
      chain.mine(12);
      await w.sync();
      return w.withdraw(TOKEN, 500n, '0xb0b');
    })();
    const proved2 = await spend2.prove();
    const liar = dualProver(chain);
    liar.route = { statement: STRANGER.statement, maxProofAge: ROUTE.maxProofAge };
    liar.binding = proved2.binding;
    await expect(spend2.wrap(t.prover({ url: 'http://q', fetch: liar.fetch as any }), { url: 'http://q' })).rejects.toThrow(/bad_result/);
  }, 300_000);

  test('a V5 record across the cutover is not submitted under V6 and is re-planned as V6', async () => {
    const chain = chainWithV6();
    const t = await connect(chain);
    const w = await t.wallet(new Uint8Array(32).fill(0xe6));
    depositTo(chain, (await w.address(0)).address, 700n);
    chain.mine(12);
    await w.sync();
    const spend = await w.withdraw(TOKEN, 700n, '0xb0b');
    expect((await spend.record()).plan.version).toBe('v5');
    const proved = await spend.prove();
    expect(proved.circuit_hash).toEqual(V5_CIRCUIT);
    const prover = dualProver(chain);
    prover.binding = proved.binding;
    await spend.wrap(t.prover({ url: 'http://p', fetch: prover.fetch as any }), { url: 'http://p' });
    expect(JSON.parse(prover.bodies.at(-1)!).relation).toBe('r5');
    // The pool switches to V6 before the V5 spend lands.
    switchToV6(chain);
    chain.mine(12);
    await expect(spend.submit(chain.account('0xacc'), { confirmFee: () => true })).rejects.toThrow(/verifier_changed/);
    const again = await w.replan(spend.id, { kind: 'withdraw', asset: TOKEN, amount: '700', recipient: '0xb0b' });
    const rec = await again.record();
    expect(rec.plan.version).toBe('v6');
    expect(rec.adapter).toBe(canon(V6.adapter));
    expect(rec.attempts.at(-1)!.adapter).toBe(canon(POOL.adapter));
  }, 300_000);

  test('a prover server whose r6 route or relation differs from the pins is refused', async () => {
    const chain = chainWithV6();
    switchToV6(chain);
    const t = await connect(chain);
    await t.prover({ url: 'http://p', fetch: dualProver(chain).fetch as any }).info();
    const aged = dualProver(chain, { ...ROUTE, maxProofAge: 999 });
    await expect(t.prover({ url: 'http://q', fetch: aged.fetch as any }).info()).rejects.toThrow(/prover_mismatch/);
    const other = dualProver(chain, PLANNED);
    // A server serving the planned route is a pinned relation, but not the primary route spends use.
    const client = t.prover({ url: 'http://r', fetch: other.fetch as any });
    await client.info();
    await expect(client.checkRelation(V6)).rejects.toThrow(/prover_mismatch/);
  }, 60_000);
});

/** The shared encoding vectors (`sdk/vectors/routing.json`, pinned by the adapter's `routing_vectors_match_serde`). */
describe('routing vectors', () => {
  const v = JSON.parse(readFileSync(new URL('../../vectors/routing.json', import.meta.url), 'utf8'));
  const routeOfJson = (r: any): Route => ({
    statement: r.statement, statementClass: r.statement_class, accountTag: r.account_tag, osProgram: r.os_program,
    proofVersion: r.proof_version, proofVariant: r.proof_variant, outputVersion: r.output_version, maxProofAge: r.max_proof_age,
  });
  const big = (xs: string[]): bigint[] => xs.map((x) => BigInt(x));
  test('route felts and both views decode as the adapter writes them', () => {
    const [a, b] = [routeOfJson(v.routes.r0_v6), routeOfJson(v.routes.p1_v1)];
    expect(routeFelts(a)).toEqual(big(v.routes.r0_v6.felts));
    expect(routeFelts(b)).toEqual(big(v.routes.p1_v1.felts));
    expect(decodeRoutes(v.get_routes.felts)).toEqual([routeFelts(a), routeFelts(b)]);
    expect(routeFelts(routeOfFelts(big(v.routes.p1_v1.felts)))).toEqual(big(v.routes.p1_v1.felts));
    expect(routeOfFelts(big(v.routes.r0_v6.felts)).accountTag).toBe('TMPZR0_PAYMENT_V6');
    const props = decodeRouteProposals(v.get_route_proposals.felts);
    expect(props).toEqual(v.get_route_proposals.proposals.map((p: any) => ({
      statement: canon(p.statement), route: p.route ? routeFelts(routeOfJson(v.routes[p.route])) : null, eta: p.eta,
    })));
    // Hostile answers are typed refusals (ADV-RC-4): a non-numeric felt, a negative count, too many.
    expect(() => decodeRouteProposals(['0xzz'])).toThrow(/verifier_changed/);
    expect(() => decodeRouteProposals(['-1'])).toThrow(/verifier_changed/);
    expect(() => decodeRoutes(['0x5', ...Array(40).fill('0x1')])).toThrow(/verifier_changed/);
    // A tag that is not printable shows as its hex.
    expect(routeOfFelts([1n, 2n, 0x80ffn, 3n, 4n, 5n, 6n, 7n]).accountTag).toBe('0x80ff');
    // Malformed arrays are refused, never read as a shorter list.
    expect(() => decodeRoutes(v.get_routes.felts.slice(0, 10))).toThrow();
    expect(() => decodeRouteProposals([...v.get_route_proposals.felts.slice(0, 3), '0x2'])).toThrow();
  });
});
