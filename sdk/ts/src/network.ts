// Pinned network constants (spec §10.2): every pool, past and present, with what the SDK checks
// the chain and prover servers against. Nothing here is taken from a server.
import type { Pins } from './core.js';
import { fail } from './errors.js';

export interface PoolConstants {
  /** The pool address. */
  pool: string;
  deploymentBlock: number;
  /**
   * The spend relation: `v4` (pool V2, R0 V4) or `v5` (pool V3, R0 V5; account-bound notes and a
   * public expiry, docs/account-bound-note-spec.md). Absent means `v4`.
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
}

/**
 * An account class a bound wallet may use (docs/account-bound-note-spec.md §6.3, §13): its class
 * hash and the view calls that must answer exactly `expect` (`'*'` matches any felt). Guardian,
 * multisig and non-Stark-signer accounts are refused at launch.
 */
export interface BoundAccountClass {
  vendor: string;
  version: string;
  classHash: string;
  checks: { entrypoint: string; expect: string[] }[];
}

/** The launch matrix, read from the live classes (Sepolia, 2026-09-26). */
export const BOUND_ACCOUNT_CLASSES: BoundAccountClass[] = [
  {
    vendor: 'Argent (Ready)',
    version: '0.5.0',
    classHash: '0x073414441639dcd11d1846f287650a00c60c416b9d3ba45d31c651672125b2c2',
    // No guardian: `get_guardian` is zero and `get_guardian_guid` is `None`.
    checks: [
      { entrypoint: 'get_guardian', expect: ['0x0'] },
      { entrypoint: 'get_guardian_guid', expect: ['0x1'] },
    ],
  },
  {
    vendor: 'Braavos',
    version: '1.2.0',
    classHash: '0x03957f9f5a1cbfe918cedc2015c85200ca51a5f7506ecb6de98a5207b759bf8a',
    // No multisig, and exactly one Stark signer (no secp256r1, no WebAuthn).
    checks: [
      { entrypoint: 'get_multisig_threshold', expect: ['0x0'] },
      { entrypoint: 'get_signers', expect: ['0x1', '*', '0x0', '0x0'] },
    ],
  },
];

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

/** Sepolia, M31 pool V2 (`bench/m31-sepolia/README.md`, 2026-09-24). */
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

export function pinsOf(n: NetworkConstants, p: PoolConstants): Pins {
  return {
    chain: n.chainId,
    pool: p.pool,
    statement: p.statement,
    statement_class: p.statementClass,
    account_tag: p.accountTag,
    os_program: p.osProgram,
    config_hash: p.configHash,
    max_proof_age: p.maxProofAge,
  };
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
