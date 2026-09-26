// Pinned network constants (spec §10.2): every pool, past and present, with what the SDK checks
// the chain and prover servers against. Nothing here is taken from a server.
import type { Pins } from './core.js';
import { fail } from './errors.js';

/** A route of a routing adapter (docs/pool-v3-spec.md §6.1): its eight pinned fields. */
export interface Route {
  statement: string;
  statementClass: string;
  accountTag: string;
  osProgram: string;
  /** `facts[0]`, `facts[1]`, `facts[3]`; default PROOF2's `PROOF2`, `VIRTUAL_SNOS`, `VIRTUAL_SNOS0`. */
  proofVersion?: string;
  proofVariant?: string;
  outputVersion?: string;
  maxProofAge: number;
}

/**
 * One generation of a verifier kind (docs/pool-v3-spec.md §10.2): an adapter, its class, and every
 * pinned state of its route set. A pool's flat fields describe its first R0 generation (a
 * pre-cutover adapter, read through its storage); `generations` lists routing adapters after it.
 */
export interface Generation {
  relation: 'r4' | 'r5' | 'r6' | 'p1';
  /** The R0 relation version spends are planned with under this generation. */
  version: 'v4' | 'v5' | 'v6';
  adapter: string;
  adapterClass: string;
  /** A routing adapter (views) rather than a pre-cutover one (storage). */
  routing: boolean;
  /** The client circuit hash (R0), eight u32 little-endian words. */
  circuitHash?: number[];
  configHash: string;
  /** Every route this release knows for the adapter. */
  routes: Route[];
  /** The pinned states of `get_routes()`, as sets of statement addresses. */
  routeStates: string[][];
  /** Route changes this release pins as planned (§10.3): shown as notices, not alarms. */
  plannedProposals?: { statement: string; route: Route | null }[];
  /** The route new spends are proved for: the one the service's prover server serves. */
  primary: string;
}

export interface PoolConstants {
  /** The pool address. */
  pool: string;
  deploymentBlock: number;
  /**
   * The pool's ABI and its first relation: `v4` (pool V2, R0 V4) or `v5` (pool V3, R0 V5 with a
   * public expiry, docs/account-bound-note-spec.md). Absent means `v4`. Later R0 relations on pool
   * V3 (R0 V6) come with their generation.
   */
  version?: 'v4' | 'v5';
  /**
   * Pool V3's constructor constants, checked against `get_parameters`: `E`, `Q`, `W` in blocks and
   * the timelock `T` in seconds (on SN_MAIN at least 7 days, docs/account-bound-note-spec.md §8.4).
   */
  parameters?: { expiryWindow: number; quantum: number; rootWindow: number; timelock: number };
  /** The R0 adapter the pool's verifier must equal, and its class. */
  adapter: string;
  adapterClass: string;
  statement: string;
  statementClass: string;
  accountTag: string;
  osProgram: string;
  /** The virtual OS configuration hash (`proof_facts[6]`). */
  configHash: string;
  maxProofAge: number;
  /** The client circuit hash, eight u32 little-endian words. */
  circuitHash: number[];
  /** Pool V3: routing adapters after the flat fields' generation (docs/pool-v3-spec.md §10.2). */
  generations?: { r0?: Generation[]; p1?: Generation[] };
  /** Pool V3: the pre-cutover P1 adapter and its class, so the P1 kind is watched too (PR2-1). */
  p1Adapter?: { adapter: string; adapterClass: string };
}

export interface TokenInfo {
  address: string;
  symbol: string;
  decimals: number;
}

export interface ProverServer {
  url: string;
  /** The server's OHTTP key configuration list, hex (pinned; spec §8). */
  ohttpKeyConfig?: string;
}

export interface NetworkConstants {
  name: string;
  /** The chain id as hex (`SN_SEPOLIA`, `SN_MAIN`). */
  chainId: string;
  /** Every pool, oldest first; the last is the active one. */
  pools: PoolConstants[];
  tokens: TokenInfo[];
  provers: ProverServer[];
}

/**
 * Sepolia: M31 pool V2 (`bench/m31-sepolia/README.md`, 2026-09-24), then M31 pool V3, the active
 * pool (`bench/account-bound-p6/README.md`, 2026-09-26).
 */
export const SEPOLIA: NetworkConstants = {
  name: 'sepolia',
  chainId: '0x534e5f5345504f4c4941',
  pools: [
    {
      pool: '0x02da0011f775d73885cf86c5145feb4cb9149d007f8546959cce32b51b5f37b9',
      deploymentBlock: 15554632,
      adapter: '0x031ca0ad5bb55c5502b0443decdd1711942e2a1cc39763f44edd7d326e5185fd',
      adapterClass: '0x064148aed7efcab705956779e172385e7f2fa36eb161e62b4dcd629a5a3e6ddb',
      statement: '0x0349eba5bab782fec0997d0fc1c516848ac2c9e070d5fda0c1046727f6209ee4',
      statementClass: '0x003e609d3c89f5c4254b53eab4b11d7543cd7d7e7da7f6027673b12769d61478',
      accountTag: 'TMPZR0_PAYMENT_V4',
      osProgram: '0x53f6c9fcfd31d27279ff7d7e422b44623550a732b59fe193354a7316a96daa1',
      configHash: '0x57ed4d5e20d617d8cc087a5882eae4f71d005172326be6439b2e1fd8b4dc57',
      maxProofAge: 4096,
      circuitHash: [4130052835, 1598900057, 4277742495, 934065338, 3030711690, 3187179780, 957846778, 3640319832],
    },
    {
      pool: '0x03463a80930b97683671b68c6a34feb3ae2ed494bd8cd477cd602dd4ef6a8aa6',
      deploymentBlock: 15655614,
      version: 'v5',
      parameters: { expiryWindow: 1500, quantum: 100, rootWindow: 4096, timelock: 7200 },
      adapter: '0x0078469651c628d0aa30a3bb3d6f762ecfe89308b62c9db4eec8f6a0232c2e7d',
      adapterClass: '0x064148aed7efcab705956779e172385e7f2fa36eb161e62b4dcd629a5a3e6ddb',
      statement: '0x07748e3ba3fca5228625cf754c0d0e7dd7e7bf3e9c426c5c7bc8dc08d88b6a81',
      statementClass: '0x06a2bd80203760b1eb0aee384ae835300c66a24f327b038315d628fbd92b830a',
      accountTag: 'TMPZR0_PAYMENT_V5',
      osProgram: '0x53f6c9fcfd31d27279ff7d7e422b44623550a732b59fe193354a7316a96daa1',
      configHash: '0x57ed4d5e20d617d8cc087a5882eae4f71d005172326be6439b2e1fd8b4dc57',
      maxProofAge: 1024,
      circuitHash: [1903585510, 1708577544, 3915427995, 3101166941, 461832048, 2805149134, 1077751030, 1205594117],
    },
  ],
  tokens: [
    { address: '0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d', symbol: 'STRK', decimals: 18 },
  ],
  provers: [],
};

export function activePool(n: NetworkConstants): PoolConstants {
  const p = n.pools[n.pools.length - 1];
  if (!p) throw new Error('network has no pool');
  return p;
}

export function versionOf(p: PoolConstants): 'v4' | 'v5' {
  return p.version ?? 'v4';
}

/** The flat fields' generation: the pool's first R0 adapter (pre-cutover, storage-pinned). */
export function legacyGeneration(p: PoolConstants): Generation {
  const v = versionOf(p);
  return {
    relation: v === 'v5' ? 'r5' : 'r4',
    version: v,
    adapter: p.adapter,
    adapterClass: p.adapterClass,
    routing: false,
    circuitHash: p.circuitHash,
    configHash: p.configHash,
    routes: [{ statement: p.statement, statementClass: p.statementClass, accountTag: p.accountTag, osProgram: p.osProgram, maxProofAge: p.maxProofAge }],
    routeStates: [[p.statement]],
    primary: p.statement,
  };
}

/** Every R0 generation this release pins, oldest first. */
export function r0Generations(p: PoolConstants): Generation[] {
  return [legacyGeneration(p), ...(p.generations?.r0 ?? [])];
}

/** Every P1 generation this release pins (pool V3), oldest first; empty when P1 is not pinned. */
export function p1Generations(p: PoolConstants): Generation[] {
  const legacy: Generation[] = p.p1Adapter
    ? [{ relation: 'p1', version: 'v5', adapter: p.p1Adapter.adapter, adapterClass: p.p1Adapter.adapterClass, routing: false, configHash: p.configHash, routes: [], routeStates: [], primary: '0x0' }]
    : [];
  return [...legacy, ...(p.generations?.p1 ?? [])];
}

/** A generation's route by its statement address (the route key). */
export function routeOf(g: Generation, statement: string): Route | undefined {
  return g.routes.find((r) => sameFelt(r.statement, statement));
}

/** The pins of one route (docs/pool-v3-spec.md §9.5, §10.2), for checking a result against it. */
export function routePins(n: NetworkConstants, p: PoolConstants, g: Generation, statement: string = g.primary): Pins {
  const r = routeOf(g, statement) ?? fail('bad_result', 'a route this release does not pin');
  return {
    chain: n.chainId,
    pool: p.pool,
    statement: r.statement,
    statement_class: r.statementClass,
    account_tag: r.accountTag,
    os_program: r.osProgram,
    config_hash: g.configHash,
    max_proof_age: r.maxProofAge,
    proof_version: r.proofVersion ?? 'PROOF2',
    proof_variant: r.proofVariant ?? 'VIRTUAL_SNOS',
    output_version: r.outputVersion ?? 'VIRTUAL_SNOS0',
  };
}

export function pinsOf(n: NetworkConstants, p: PoolConstants): Pins {
  return routePins(n, p, legacyGeneration(p));
}

/** Canonical felt text: lowercase, no leading zeros. Malformed text is a `bad_felt` error. */
export function canon(h: string | bigint | number): string {
  let v: bigint;
  try {
    v = BigInt(h);
  } catch {
    fail('bad_felt', `not a felt: ${String(h).slice(0, 80)}`);
  }
  if (v < 0n) fail('bad_felt', 'a negative felt');
  return '0x' + v.toString(16);
}

/** Felt equality; malformed text is a `bad_felt` error, never a raw `SyntaxError`. */
export const sameFelt = (a: string | bigint, b: string | bigint): boolean => canon(a) === canon(b);
