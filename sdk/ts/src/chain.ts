// Chain reads (spec §6, §8): pin verification against the chain, and the pool's events fetched in
// bulk by address and selector only, never by note.
import { hash, type RpcProvider } from 'starknet';

import { fail } from './errors.js';
import { canon, sameFelt, type NetworkConstants, type PoolConstants } from './network.js';
import type { Digest, Hex } from './core.js';

export const SELECTORS = {
  NotePublished: hash.getSelectorFromName('NotePublished'),
  NullifierSpent: hash.getSelectorFromName('NullifierSpent'),
  AssetRegistered: hash.getSelectorFromName('AssetRegistered'),
  PolicySettled: hash.getSelectorFromName('PolicySettled'),
  Deposited: hash.getSelectorFromName('Deposited'),
} as const;

const shortString = (s: string): bigint => BigInt('0x' + [...new TextEncoder().encode(s)].map((b) => b.toString(16).padStart(2, '0')).join(''));

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
  await checkVerifier(provider, p);
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

/** The pool's verifier must still be the pinned adapter (re-read before every simulation and deposit). */
export async function checkVerifier(provider: RpcProvider, p: PoolConstants): Promise<void> {
  const [v] = await provider.callContract({ contractAddress: p.pool, entrypoint: 'get_verifier', calldata: [] });
  if (!v || !sameFelt(v, p.adapter)) fail('verifier_changed', 'the pool no longer uses the pinned adapter');
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
