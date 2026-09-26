// Chain reads (spec §6, §8): pin verification against the chain, and the pool's events fetched in
// bulk by address and selector only, never by note.
import { hash, type RpcProvider } from 'starknet';

import { fail } from './errors.js';
import { canon, p1Generations, r0Generations, routeOf, sameFelt, versionOf, type Generation, type NetworkConstants, type PoolConstants, type Route } from './network.js';
import type { Digest, Hex } from './core.js';

export const SELECTORS = {
  NotePublished: hash.getSelectorFromName('NotePublished'),
  NullifierSpent: hash.getSelectorFromName('NullifierSpent'),
  AssetRegistered: hash.getSelectorFromName('AssetRegistered'),
  PolicySettled: hash.getSelectorFromName('PolicySettled'),
  Deposited: hash.getSelectorFromName('Deposited'),
} as const;

const shortString = (s: string): bigint => BigInt('0x' + [...new TextEncoder().encode(s)].map((b) => b.toString(16).padStart(2, '0')).join(''));
const fromShortString = (x: bigint): string => {
  const h = x.toString(16);
  const bytes = Uint8Array.from((h.length % 2 ? '0' + h : h).match(/../g) ?? [], (b) => Number.parseInt(b, 16));
  return x !== 0n && bytes.every((b) => b >= 0x20 && b < 0x7f) ? new TextDecoder().decode(bytes) : '0x' + h;
};

/**
 * A route's eight felts, in the adapter's Serde order, as a `Route`, for display. A short string
 * that is not printable ASCII is shown as its hex, so two different felts never display alike.
 */
export function routeOfFelts(f: bigint[]): Route {
  if (f.length !== 8) fail('verifier_changed', 'a route is eight felts');
  if (f[7]! > BigInt(Number.MAX_SAFE_INTEGER)) fail('verifier_changed', 'a route age out of range');
  return {
    statement: canon('0x' + f[0]!.toString(16)), statementClass: canon('0x' + f[1]!.toString(16)), accountTag: fromShortString(f[2]!),
    osProgram: canon('0x' + f[3]!.toString(16)), proofVersion: fromShortString(f[4]!), proofVariant: fromShortString(f[5]!),
    outputVersion: fromShortString(f[6]!), maxProofAge: Number(f[7]!),
  };
}

/** RPC 0.10.1 or later (proof fields). */
export async function checkSpecVersion(provider: RpcProvider): Promise<void> {
  const v = await provider.channel.getSpecVersion();
  const [maj, min, patch] = v.split('.').map((x) => Number.parseInt(x, 10));
  const ok = maj! > 0 || min! > 10 || (min === 10 && (patch ?? 0) >= 1);
  if (!ok) fail('rpc_version', `the RPC node speaks ${v}; 0.10.1 or later is required`);
}

/** Checks the chain against the pinned constants before first use (spec §8). */
export async function verifyPins(provider: RpcProvider, n: NetworkConstants, p: PoolConstants): Promise<void> {
  const chain = await provider.getChainId();
  if (!sameFelt(chain, n.chainId)) fail('wrong_chain', `the RPC node is on ${chain}`);
  // The current R0 generation, and P1's when pinned (docs/pool-v3-spec.md §10.2, PR2-1).
  await checkVerifier(provider, p);
  if (versionOf(p) === 'v5' && p1Generations(p).length > 0) await currentGeneration(provider, p, 'P1');
  if (versionOf(p) === 'v5') {
    // Pool V3's expiry and root rules are constructor constants (docs/account-bound-note-spec.md §8).
    const want = p.parameters ?? fail('pin_mismatch', 'a pool V3 needs its pinned parameters');
    const got = (await provider.callContract({ contractAddress: p.pool, entrypoint: 'get_parameters', calldata: [] })).map((x) => Number(BigInt(x)));
    if (got[0] !== want.expiryWindow || got[1] !== want.quantum || got[2] !== want.rootWindow || got[3] !== want.timelock) fail('pin_mismatch', 'pool parameters');
    // Mainnet floors (§8.4): owner changes wait at least 7 days, and a replaced root outlives any
    // spend that could use it.
    if (sameFelt(n.chainId, MAINNET) && (want.timelock < 7 * 86_400 || want.rootWindow < want.expiryWindow + want.quantum)) {
      fail('pin_mismatch', 'pool parameters below the mainnet floors');
    }
  }
}

/** A pre-cutover adapter's configuration, read from its storage (the flat fields' generation). */
async function checkLegacyStorage(provider: RpcProvider, p: PoolConstants): Promise<void> {
  if (!sameFelt(await provider.getClassHashAt(p.adapter), p.adapterClass)) fail('pin_mismatch', 'adapter class');
  if (!sameFelt(await provider.getClassHashAt(p.statement), p.statementClass)) fail('pin_mismatch', 'statement account class');
  const expect: [string, bigint][] = [
    ['pool', BigInt(p.pool)],
    ['statement', BigInt(p.statement)],
    ['statement_class', BigInt(p.statementClass)],
    ['os_program', BigInt(p.osProgram)],
    ['max_proof_age', BigInt(p.maxProofAge)],
    ['account_tag', shortString(p.accountTag)],
  ];
  for (const [name, want] of expect) {
    const got = await provider.getStorageAt(p.adapter, hash.starknetKeccak(name));
    const value = typeof got === 'string' ? got : (got as unknown as { value: string }).value;
    if (BigInt(value) !== want) fail('pin_mismatch', `adapter ${name}`);
  }
}

const MAINNET = canon(shortString('SN_MAIN'));

/** Pool V3's verifier kinds (docs/account-bound-note-spec.md §8.4). */
export const KIND_R0 = canon(shortString('R0'));
export const KIND_P1 = canon(shortString('P1'));

/**
 * The pool's R0 verifier must be a pinned generation's adapter, with its pins (re-read before every
 * simulation and deposit). Returns that generation.
 */
export async function checkVerifier(provider: RpcProvider, p: PoolConstants): Promise<Generation> {
  return (await currentGeneration(provider, p, 'R0')).generation;
}

/** A route's eight felts in the adapter's Serde order (the `route_serde_order` known answer). */
export function routeFelts(r: Route): bigint[] {
  return [
    BigInt(r.statement), BigInt(r.statementClass), shortString(r.accountTag), BigInt(r.osProgram),
    shortString(r.proofVersion ?? 'PROOF2'), shortString(r.proofVariant ?? 'VIRTUAL_SNOS'), shortString(r.outputVersion ?? 'VIRTUAL_SNOS0'),
    BigInt(r.maxProofAge),
  ];
}

/** `get_routes()`: `[n, route…]`, eight felts per route. */
/** A felt from an RPC answer, as a typed error when it is not one (ADV-RC-4). */
function viewFelt(x: string | undefined, what: string): bigint {
  if (x === undefined) fail('verifier_changed', `${what}: truncated`);
  let v: bigint;
  try {
    v = BigInt(x);
  } catch {
    fail('verifier_changed', `${what}: not a felt`);
  }
  if (v < 0n || v >= 2n ** 252n) fail('verifier_changed', `${what}: not a felt`);
  return v;
}

/** A count or timestamp from an RPC answer: a small nonnegative integer. */
function viewSmall(x: string | undefined, what: string, max = 2 ** 53 - 1): number {
  const v = viewFelt(x, what);
  if (v > BigInt(max)) fail('verifier_changed', `${what}: out of range`);
  return Number(v);
}

export function decodeRoutes(v: string[]): bigint[][] {
  const n = viewSmall(v[0], 'get_routes count', 4);
  if (v.length !== 1 + 8 * n) fail('verifier_changed', 'get_routes: malformed');
  return Array.from({ length: n }, (_, i) => v.slice(1 + 8 * i, 9 + 8 * i).map((x) => viewFelt(x, 'get_routes')));
}

/** `get_route_proposals()`: `[n, (statement, Option<Route>, eta)…]`; `Some` is `0` then eight felts, `None` is `1`. */
export function decodeRouteProposals(v: string[]): { statement: Hex; route: bigint[] | null; eta: number }[] {
  const out: { statement: Hex; route: bigint[] | null; eta: number }[] = [];
  let at = 1;
  const n = viewSmall(v[0], 'get_route_proposals count', 2);
  const next = (): string => v[at++] ?? fail('verifier_changed', 'get_route_proposals: truncated');
  for (let i = 0; i < n; i++) {
    const statement = canon(viewFelt(next(), 'get_route_proposals statement'));
    const tag = viewFelt(next(), 'get_route_proposals tag');
    let route: bigint[] | null = null;
    if (tag === 0n) route = Array.from({ length: 8 }, () => viewFelt(next(), 'get_route_proposals route'));
    else if (tag !== 1n) fail('verifier_changed', 'get_route_proposals: bad Option tag');
    out.push({ statement, route, eta: viewSmall(next(), 'get_route_proposals eta') });
  }
  if (at !== v.length) fail('verifier_changed', 'get_route_proposals: trailing felts');
  return out;
}

const sameRoute = (a: bigint[], b: bigint[]): boolean => a.length === b.length && a.every((x, i) => x === b[i]);

/**
 * A routing adapter's live route set equals a pinned state of its generation (docs/pool-v3-spec.md
 * §10.2): its class, pool and kind, the count and all eight fields of each route, and each route's
 * class on chain. Returns the active routes.
 */
async function checkRoutes(provider: RpcProvider, p: PoolConstants, g: Generation, kind: 'R0' | 'P1'): Promise<Route[]> {
  const read = (entrypoint: string, calldata: string[] = []) => provider.callContract({ contractAddress: g.adapter, entrypoint, calldata });
  if (!sameFelt(await provider.getClassHashAt(g.adapter), g.adapterClass)) fail('verifier_changed', 'the routing adapter class');
  if (!sameFelt((await read('get_pool'))[0] ?? '0x0', p.pool)) fail('verifier_changed', 'the routing adapter serves another pool');
  if (!sameFelt((await read('get_kind'))[0] ?? '0x0', kind === 'R0' ? KIND_R0 : KIND_P1)) fail('verifier_changed', 'the routing adapter is for another kind');
  const live = decodeRoutes(await read('get_routes'));
  const keys = live.map((r) => canon(r[0]!)).sort();
  const state = g.routeStates.find((st) => st.length === keys.length && [...st].map(canon).sort().every((k, i) => k === keys[i]));
  if (!state) fail('verifier_changed', 'the adapter\'s route set is not a pinned state');
  const routes: Route[] = [];
  for (const r of live) {
    const pin = routeOf(g, canon(r[0]!)) ?? fail('verifier_changed', 'a route this release does not pin');
    if (!sameRoute(routeFelts(pin), r)) fail('verifier_changed', `route ${canon(r[0]!)} differs from its pin`);
    if (!sameFelt(await provider.getClassHashAt(pin.statement), pin.statementClass)) fail('verifier_changed', `route ${pin.statement}: statement class`);
    routes.push(pin);
  }
  return routes;
}

/**
 * The pool's current verifier for a kind is a pinned generation's adapter, with its pins: a routing
 * adapter's views, or a pre-cutover R0 adapter's storage (docs/pool-v3-spec.md §10.2). Any mismatch is
 * `verifier_changed`. Returns the generation and its active routes.
 */
export async function currentGeneration(provider: RpcProvider, p: PoolConstants, kind: 'R0' | 'P1'): Promise<{ generation: Generation; routes: Route[] }> {
  // Pool V3 reads `get_verifier(kind)` (AB-PV7); pool V2 has one R0 verifier.
  const v3 = versionOf(p) === 'v5';
  const calldata = v3 ? [kind === 'R0' ? KIND_R0 : KIND_P1] : [];
  const [v] = await provider.callContract({ contractAddress: p.pool, entrypoint: 'get_verifier', calldata });
  const gens = kind === 'R0' ? r0Generations(p) : p1Generations(p);
  const generation = gens.find((g) => v !== undefined && sameFelt(v, g.adapter)) ?? fail('verifier_changed', `the pool's ${kind} verifier is not a pinned adapter`);
  if (generation.routing) return { generation, routes: await checkRoutes(provider, p, generation, kind) };
  if (kind === 'R0') await checkLegacyStorage(provider, p);
  else if (!sameFelt(await provider.getClassHashAt(generation.adapter), generation.adapterClass)) fail('verifier_changed', 'the P1 adapter class');
  return { generation, routes: generation.routes };
}

/** A pending owner change on pool V3: a verifier kind or a shadow class hash, its value and eta. */
export interface Proposal {
  key: Hex;
  value: Hex;
  /** Unix seconds from which the owner may apply it. */
  eta: number;
  /** Unix seconds after which it can no longer apply (`eta + T`). */
  lapsesAt: number;
  /** Past `lapsesAt` at the latest block: shown, but it blocks nothing (AB-SP15). */
  lapsed: boolean;
  /** A verifier change (`R0` or `P1`) rather than a shadow class. */
  verifier: boolean;
  /** A route change on a routing adapter (docs/pool-v3-spec.md §6.3): its adapter, and the route added (`null` for a removal). */
  route?: { adapter: Hex; statement: Hex; value: Route | null };
  /**
   * A change this release pins as planned (§10.3, PV3-8): a verifier proposal to a pinned routing
   * adapter whose route set is a pinned state with nothing pending, or a pinned planned route
   * change. Shown as a notice; any other verifier or route change refuses deposits.
   */
  pinned: boolean;
}

/**
 * The pending proposals for both verifiers and the given shadow classes (spec §8.4, AB-PV2): the SDK
 * shows each, refuses deposits while a verifier change is pending, and stops the routes a pending
 * shadow-class change would break.
 */
export async function pendingProposals(provider: RpcProvider, p: PoolConstants, shadowClasses: Hex[] = []): Promise<Proposal[]> {
  if (versionOf(p) !== 'v5') return [];
  const out = await poolProposals(provider, p, shadowClasses);
  // Route proposals (§10.3), for both kinds: on the current adapter, and on any adapter that is the
  // value of a pending verifier proposal.
  for (const [kind, key] of [['R0', KIND_R0], ['P1', KIND_P1]] as const) {
    const gens = kind === 'R0' ? r0Generations(p) : p1Generations(p);
    if (gens.length === 0) continue;
    const [current] = await provider.callContract({ contractAddress: p.pool, entrypoint: 'get_verifier', calldata: [key] });
    const adapters = [current, ...out.filter((x) => x.key === key && !x.lapsed).map((x) => x.value)].filter((a): a is string => a !== undefined);
    for (const adapter of [...new Set(adapters.map(canon))]) {
      const g = gens.find((x) => sameFelt(x.adapter, adapter));
      if (!g?.routing) continue;
      out.push(...(await routeProposals(provider, p, g, key)));
    }
    // A verifier proposal is pinned only to a pinned routing adapter holding a pinned route set with
    // nothing pending, re-checked on every poll until apply.
    for (const x of out.filter((y) => y.key === key && y.verifier)) {
      const g = gens.find((y) => sameFelt(y.adapter, x.value));
      x.pinned = g?.routing === true && (await pinnedVerifier(provider, p, g, kind));
    }
  }
  return out;
}

async function pinnedVerifier(provider: RpcProvider, p: PoolConstants, g: Generation, kind: 'R0' | 'P1'): Promise<boolean> {
  try {
    await checkRoutes(provider, p, g, kind);
    const [n] = await provider.callContract({ contractAddress: g.adapter, entrypoint: 'get_route_proposals', calldata: [] });
    return n !== undefined && BigInt(n) === 0n;
  } catch {
    return false;
  }
}

async function routeProposals(provider: RpcProvider, p: PoolConstants, g: Generation, key: Hex): Promise<Proposal[]> {
  const timelock = p.parameters?.timelock ?? fail('pin_mismatch', 'a pool V3 needs its pinned parameters');
  const now = await latestTimestamp(provider);
  const raw = decodeRouteProposals(await provider.callContract({ contractAddress: g.adapter, entrypoint: 'get_route_proposals', calldata: [] }));
  const live = decodeRoutes(await provider.callContract({ contractAddress: g.adapter, entrypoint: 'get_routes', calldata: [] }));
  return raw.map((r) => {
    // The proposed value itself, never a pin looked up by key (ADV-V6-3).
    const value = r.route ? routeOfFelts(r.route) : null;
    // Any planned change under this key that equals the pending one: a release may pin both a
    // route's addition and its later removal (§10.2; release review F1, ADV-4).
    const matches = (g.plannedProposals ?? [])
      .filter((x) => sameFelt(x.statement, r.statement))
      .some((x) => (r.route === null ? x.route === null : x.route !== null && sameRoute(routeFelts(x.route), r.route)));
    // A removal never leaves the adapter without a route the SDK can use (PR2-2).
    // Usable means the primary route, the only one this release proves for, stays active (PR2-2).
    const leavesUsable = r.route !== null || (!sameFelt(r.statement, g.primary) && live.some((x) => sameFelt(canon(x[0]!), g.primary)));
    return {
      key, value: canon(r.statement), eta: r.eta, lapsesAt: r.eta + timelock, lapsed: now > r.eta + timelock, verifier: false,
      route: { adapter: canon(g.adapter), statement: r.statement, value }, pinned: matches && leavesUsable,
    };
  });
}

async function latestTimestamp(provider: RpcProvider): Promise<number> {
  const latest = await provider.getBlockLatestAccepted();
  const block = await provider.getBlockWithTxHashes(latest.block_number);
  return Number((block as { timestamp?: number }).timestamp ?? fail('bad_rpc', 'block timestamp'));
}

/** The pool's own pending proposals: both verifier kinds and the given shadow classes. */
async function poolProposals(provider: RpcProvider, p: PoolConstants, shadowClasses: Hex[]): Promise<Proposal[]> {
  const timelock = p.parameters?.timelock ?? fail('pin_mismatch', 'a pool V3 needs its pinned parameters');
  // The pool keeps a lapsed proposal until it is replaced or cancelled: lapse is judged at the
  // latest block's timestamp, the clock the pool uses.
  const latest = await provider.getBlockLatestAccepted();
  const block = await provider.getBlockWithTxHashes(latest.block_number);
  const now = Number((block as { timestamp?: number }).timestamp ?? fail('bad_rpc', 'block timestamp'));
  const out: Proposal[] = [];
  for (const key of [KIND_R0, KIND_P1, ...shadowClasses.map(canon)]) {
    const [value, eta] = await provider.callContract({ contractAddress: p.pool, entrypoint: 'get_proposal', calldata: [key] });
    if (eta === undefined || BigInt(eta) === 0n) continue;
    const e = Number(BigInt(eta));
    out.push({ key, value: canon(value ?? 0), eta: e, lapsesAt: e + timelock, lapsed: now > e + timelock, verifier: key === KIND_R0 || key === KIND_P1, pinned: false });
  }
  return out;
}

export type PoolEvent =
  | { kind: 'note'; block: number; index: number; commitment: Digest; digest: Hex; words: Hex[] }
  | { kind: 'nullifier'; block: number; nullifier: Digest }
  | { kind: 'asset'; block: number; asset: Hex; standard: number; contract: Hex; idLow: string; idHigh: string }
  | { kind: 'settled'; block: number; firstIndex: number; x: string }
  | { kind: 'deposited'; block: number; asset: Hex };

const digestOf = (xs: string[]): Digest => xs.map((x) => Number(BigInt(x)));

/** Parses one event, or `undefined` for a malformed one (which makes the sync incomplete). */
export function parseEvent(keys: string[], data: string[], block: number): PoolEvent | undefined {
  const d = data;
  const n = (i: number) => Number(BigInt(d[i]!));
  try {
    switch (BigInt(keys[0]!)) {
      case BigInt(SELECTORS.NotePublished): {
        if (n(1) !== 9 || n(12) !== 10 || d.length !== 23) return undefined;
        // Commitment words are M31 elements; anything else is malformed, never a throw (SDK-IP10).
        if (d.slice(2, 11).some((x) => BigInt(x) >= 2147483647n)) return undefined;
        return { kind: 'note', block, index: n(0), commitment: digestOf(d.slice(2, 11)), digest: canon(d[11]!), words: d.slice(13, 23).map(canon) };
      }
      case BigInt(SELECTORS.NullifierSpent):
        if (n(0) !== 9 || d.length !== 10 || d.slice(1, 10).some((x) => BigInt(x) >= 2147483647n)) return undefined;
        return { kind: 'nullifier', block, nullifier: digestOf(d.slice(1, 10)) };
      case BigInt(SELECTORS.AssetRegistered):
        if (d.length !== 5) return undefined;
        return { kind: 'asset', block, asset: canon(d[0]!), standard: n(1), contract: canon(d[2]!), idLow: BigInt(d[3]!).toString(), idHigh: BigInt(d[4]!).toString() };
      case BigInt(SELECTORS.PolicySettled):
        if (d.length !== 8) return undefined;
        return { kind: 'settled', block, firstIndex: n(6), x: BigInt(d[5]!).toString() };
      case BigInt(SELECTORS.Deposited):
        if (d.length !== 2) return undefined;
        return { kind: 'deposited', block, asset: canon(d[0]!) };
    }
  } catch {
    return undefined;
  }
  return undefined;
}

/**
 * Every pool event in `[from, to]`, by address and selector only (spec §6). Events from another
 * address or with another selector are dropped; a malformed pool event is reported.
 */
export async function fetchPoolEvents(
  provider: RpcProvider,
  pool: string,
  from: number,
  to: number | 'pre_confirmed',
): Promise<{ events: PoolEvent[]; malformed: number }> {
  const selectors = Object.values(SELECTORS);
  const events: PoolEvent[] = [];
  let malformed = 0;
  let token: string | undefined;
  do {
    const chunk = await provider.getEvents({
      address: pool,
      from_block: { block_number: from },
      to_block: to === 'pre_confirmed' ? 'pre_confirmed' : { block_number: to },
      keys: [selectors],
      chunk_size: 1000,
      ...(token ? { continuation_token: token } : {}),
    });
    for (const e of chunk.events) {
      if (!sameFelt(e.from_address, pool) || !e.keys.length || !selectors.some((s) => sameFelt(s, e.keys[0]!))) continue;
      const parsed = parseEvent(e.keys, e.data, e.block_number ?? -1);
      if (parsed) events.push(parsed);
      else malformed += 1;
    }
    token = chunk.continuation_token;
  } while (token);
  return { events, malformed };
}

export async function leafCountAndRoot(provider: RpcProvider, pool: string, block: number): Promise<{ count: number; root: Digest }> {
  const id = block;
  const [count] = await provider.callContract({ contractAddress: pool, entrypoint: 'get_leaf_count', calldata: [] }, id);
  const root = await provider.callContract({ contractAddress: pool, entrypoint: 'get_root', calldata: [] }, id);
  if (Number(BigInt(root[0]!)) !== 9) fail('bad_rpc', 'get_root');
  return { count: Number(BigInt(count!)), root: digestOf(root.slice(1, 10)) };
}
