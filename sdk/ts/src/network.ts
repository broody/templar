// Pinned network constants (spec §10.2): every pool, past and present, with what the SDK checks
// the chain and prover servers against. Nothing here is taken from a server.
import type { Pins } from './core.js';

export interface PoolConstants {
  /** The pool address. */
  pool: string;
  deploymentBlock: number;
  /** The R4 adapter the pool's verifier must equal, and its class. */
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

/** Canonical felt text: lowercase, no leading zeros. */
export function canon(h: string | bigint | number): string {
  return '0x' + BigInt(h).toString(16);
}

export const sameFelt = (a: string | bigint, b: string | bigint): boolean => BigInt(a) === BigInt(b);
